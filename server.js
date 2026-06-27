import express from 'express';
import multer from 'multer';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanUrl } from './src/scanners/urlScanner.js';
import { scanUi } from './src/scanners/uiScanner.js';
import { scanApi } from './src/scanners/apiScanner.js';
import { scanVuln } from './src/scanners/vulnScanner.js';
import { scanRender } from './src/scanners/renderScanner.js';
import { scanCode, entriesFromZip } from './src/scanners/codeScanner.js';
import { scanCodeAudit } from './src/scanners/codeAuditScanner.js';
import { fetchRepoEntries } from './src/scanners/githubScanner.js';
import { scanApiFuzz } from './src/scanners/apiFuzzScanner.js';
import { scanAccess } from './src/scanners/accessScanner.js';
import { scanApiSpec } from './src/scanners/apiSpecScanner.js';
import { scanAudits } from './src/scanners/auditScanner.js';
import { scoreFindings, summarize } from './src/scanners/scoring.js';
import { normalizeUrl, runWithAuth } from './src/scanners/util.js';
import cookieParser from 'cookie-parser';
import { securityHeaders } from './src/middleware/security.js';
import { rateLimit, clientKey } from './src/middleware/rateLimit.js';
import { validate, websiteSchema, apiSchema, credentialsSchema, githubSchema, billingSchema } from './src/middleware/validate.js';
import { hashPassword, verifyPassword, issueToken, verifyToken, setAuthCookie, clearAuthCookie, requireAuth } from './src/auth/auth.js';
import { getUser, hasUser, putUser, setUserPlan } from './src/auth/store.js';
import { checkLock, recordFailure, recordSuccess } from './src/auth/bruteforce.js';
import { isConfigured as billingConfigured, createCheckoutSession, constructEvent, planChangeFromEvent } from './src/billing/billing.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const num = (v, d) => (v !== undefined && v !== '' && !Number.isNaN(Number(v)) ? Number(v) : d);

app.disable('x-powered-by');
// Trust X-Forwarded-* only when explicitly configured — otherwise a client could
// spoof its IP via X-Forwarded-For and evade rate limits.
if (process.env.TRUST_PROXY) {
  app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? true : process.env.TRUST_PROXY);
}

app.use(securityHeaders);                                   // OWASP secure headers on every response
app.use(express.static(path.join(__dirname, 'public')));
// Parse JSON for everything EXCEPT the Stripe webhook, which needs the raw body
// to verify its signature.
const jsonParser = express.json({ limit: '1mb' });
app.use((req, res, next) => (req.path === '/api/billing/webhook' ? next() : jsonParser(req, res, next)));
app.use(cookieParser());                                    // parse the auth cookie

// --- Rate limiting (OWASP API4) — defaults overridable via env --------------
const WINDOW_MS = num(process.env.RATE_LIMIT_WINDOW_MS, 60_000);
const apiLimiter = rateLimit({ windowMs: WINDOW_MS, max: num(process.env.RATE_LIMIT_API_MAX, 120), name: 'the API' });
const scanLimiter = rateLimit({ windowMs: WINDOW_MS, max: num(process.env.RATE_LIMIT_SCAN_MAX, 20), name: 'scanning' });
const fileLimiter = rateLimit({ windowMs: WINDOW_MS, max: num(process.env.RATE_LIMIT_FILE_MAX, 10), name: 'file scanning' });
// Strict limiter for auth endpoints (a second layer behind brute-force lockout).
const authLimiter = rateLimit({ windowMs: WINDOW_MS, max: num(process.env.RATE_LIMIT_AUTH_MAX, 12), name: 'authentication' });
app.use('/api', apiLimiter);                                // global limiter on all API routes

// Optional: require login for the scan endpoints (off by default — non-breaking).
const gate = process.env.REQUIRE_AUTH === '1' ? requireAuth : (req, res, next) => next();

// --- Authentication: JWT cookie auth (bcrypt) + brute-force prevention ------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post('/api/auth/register', authLimiter, validate(credentialsSchema), async (req, res) => {
  const { email, password } = req.body;
  if (!EMAIL_RE.test(email)) return res.status(400).json({ ok: false, error: 'Enter a valid email address.' });
  if (hasUser(email)) return res.status(409).json({ ok: false, error: 'An account with that email already exists.' });
  const hash = await hashPassword(password);
  putUser(email, hash);
  setAuthCookie(req, res, issueToken(email.toLowerCase()));
  res.json({ ok: true, user: { email: email.toLowerCase() } });
});

app.post('/api/auth/login', authLimiter, validate(credentialsSchema), async (req, res) => {
  const { email, password } = req.body;
  const keys = [`email:${email.toLowerCase()}`, `ip:${clientKey(req)}`];
  const locked = checkLock(keys);
  if (locked) {
    res.set('Retry-After', String(locked));
    return res.status(429).json({ ok: false, error: `Too many failed attempts. Try again in ${locked}s.` });
  }
  const user = getUser(email);
  // verifyPassword falls back to a dummy hash when the user is absent, so the
  // response time is the same whether or not the account exists.
  const ok = await verifyPassword(password, user && user.passwordHash);
  if (!user || !ok) {
    recordFailure(keys);
    return res.status(401).json({ ok: false, error: 'Invalid email or password.' });
  }
  recordSuccess(keys);
  setAuthCookie(req, res, issueToken(user.email));
  res.json({ ok: true, user: { email: user.email } });
});

app.post('/api/auth/logout', (req, res) => {
  clearAuthCookie(res);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// Non-failing session probe for the UI (always 200, so it never logs a console error).
app.get('/api/auth/session', (req, res) => {
  const token = req.cookies && req.cookies.sentry_token;
  const payload = token && verifyToken(token);
  const user = payload ? getUser(payload.sub) : null;
  res.json({ ok: true, authenticated: !!payload, user: payload ? { email: payload.sub, plan: (user && user.plan) || 'free' } : null });
});

// --- Billing (Stripe Checkout) — skips cleanly until STRIPE_SECRET_KEY is set --
app.get('/api/billing/plan', requireAuth, (req, res) => {
  const u = getUser(req.user.email);
  res.json({ ok: true, plan: (u && u.plan) || 'free', billingEnabled: billingConfigured() });
});

// Start a hosted Checkout session (must be logged in).
app.post('/api/billing/checkout', requireAuth, validate(billingSchema), async (req, res) => {
  try {
    const origin = `${req.protocol}://${req.get('host')}`;
    const session = await createCheckoutSession(req.user.email, req.body.plan, origin);
    res.json({ ok: true, url: session.url });
  } catch (e) {
    res.status(e.status || 400).json({ ok: false, error: e.message });
  }
});

// Stripe webhook — signature-verified; the ONLY thing that grants a paid plan.
app.post('/api/billing/webhook', express.raw({ type: '*/*' }), (req, res) => {
  let event;
  try {
    event = constructEvent(req.body, req.headers['stripe-signature']);
  } catch (e) {
    return res.status(400).json({ ok: false, error: `Webhook signature verification failed: ${e.message}` });
  }
  const change = planChangeFromEvent(event);
  if (change && change.email) setUserPlan(change.email, change.plan);
  res.json({ received: true });
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 60 * 1024 * 1024, files: 2000 }
});

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Headers a client must not control (would break the request or enable abuse).
const FORBIDDEN_HEADERS = new Set([
  'host', 'content-length', 'connection', 'transfer-encoding', 'upgrade',
  'proxy-authorization', 'te', 'trailer', 'expect'
]);

// Accept user-supplied auth headers as either an object or "Name: value" lines.
// Returns a clean {name: value} object suitable for authenticated scanning.
function sanitizeHeaders(raw) {
  let pairs = [];
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    pairs = Object.entries(raw);
  } else if (typeof raw === 'string') {
    pairs = raw.split(/\r?\n/).map((l) => {
      const i = l.indexOf(':');
      return i === -1 ? null : [l.slice(0, i), l.slice(i + 1)];
    }).filter(Boolean);
  }
  const out = {};
  for (let [name, value] of pairs) {
    name = String(name).trim();
    value = String(value).trim();
    if (!name || !value) continue;
    if (!/^[A-Za-z0-9-]+$/.test(name)) continue;       // valid header token only
    if (FORBIDDEN_HEADERS.has(name.toLowerCase())) continue;
    if (value.length > 4096) continue;
    out[name] = value;
    if (Object.keys(out).length >= 12) break;
  }
  return out;
}

function tag(findings, category) {
  return (findings || []).map((f) => ({ ...f, category }));
}

// Build a combined report from one or more category sections.
function buildReport(type, sections, baseMeta = {}) {
  // sections: [{ category, label, meta, findings, error }]
  const all = [];
  const categories = [];
  for (const s of sections) {
    const findings = tag(s.findings || [], s.category);
    all.push(...findings);
    categories.push({
      category: s.category,
      label: s.label,
      status: s.error ? 'error' : 'ok',
      error: s.error || null,
      meta: s.meta || {},
      counts: summarize(findings),
      total: findings.length
    });
  }
  const { score, grade, counts } = scoreFindings(all);
  all.sort((a, b) =>
    (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || a.category.localeCompare(b.category));
  return { ok: true, type, score, grade, counts, total: all.length, meta: baseMeta, categories, findings: all };
}

// Run a scanner and capture errors into a section instead of failing the whole report.
async function runSection(category, label, fn) {
  try {
    const r = await fn();
    return { category, label, meta: r.meta, findings: r.findings };
  } catch (e) {
    return { category, label, meta: {}, findings: [], error: e.message };
  }
}

// Quality audits share a single page fetch but produce three sections.
const AUDIT_LABELS = { perf: 'Performance', a11y: 'Accessibility', seo: 'SEO' };
async function auditSections(target) {
  try {
    const a = await scanAudits(target);
    return [
      { category: 'perf', label: AUDIT_LABELS.perf, meta: a.meta, findings: a.perf },
      { category: 'a11y', label: AUDIT_LABELS.a11y, meta: a.meta, findings: a.a11y },
      { category: 'seo', label: AUDIT_LABELS.seo, meta: a.meta, findings: a.seo }
    ];
  } catch (e) {
    return Object.keys(AUDIT_LABELS).map((c) => ({ category: c, label: AUDIT_LABELS[c], meta: {}, findings: [], error: e.message }));
  }
}

// --- Full website test: UI health + security + render ----------------------
// scanLimiter throttles expensive scans; validate() enforces the request schema.
app.post('/api/test/website', gate, scanLimiter, validate(websiteSchema), async (req, res) => {
  const target = req.body.url;          // validated, required, ≤2048 chars
  const includeRender = req.body.render; // boolean, default true
  const doAudits = req.body.audits;      // boolean, default true (performance / a11y / SEO)

  // Validate/normalize the target up front so an invalid or blocked URL returns
  // a clear error instead of a misleading "all suites unavailable" 100/A report.
  try {
    normalizeUrl(target);
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.message });
  }

  const authHeaders = sanitizeHeaders(req.body.headers);
  const authed = Object.keys(authHeaders).length > 0;

  try {
    const results = await runWithAuth(authHeaders, () => Promise.all([
      runSection('ui', 'Website health & UI', () => scanUi(target)),
      runSection('security', 'Security', () => scanUrl(target)),
      runSection('vuln', 'Vulnerabilities & OWASP', () => scanVuln(target)),
      ...(includeRender ? [runSection('render', 'JavaScript & render', () => scanRender(target, { authHeaders }))] : []),
      ...(doAudits ? [auditSections(target)] : [])
    ]));
    const sections = results.flat(); // auditSections returns an array of 3
    // If the network-dependent suites all failed (e.g. host unreachable), the
    // target couldn't be assessed — report that instead of a perfect score.
    const networkSections = sections.filter((s) => s.category !== 'render');
    if (networkSections.length && networkSections.every((s) => s.error)) {
      return res.status(400).json({ ok: false, error: networkSections[0].error });
    }
    const finalUrl = sections.find((s) => s.meta && s.meta.finalUrl);
    res.json(buildReport('website', sections, { target, authenticated: authed, finalUrl: finalUrl ? finalUrl.meta.finalUrl : target }));
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// --- API test --------------------------------------------------------------
app.post('/api/test/api', gate, scanLimiter, validate(apiSchema), async (req, res) => {
  const target = req.body.url;
  try {
    normalizeUrl(target);
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.message });
  }

  const authHeaders = sanitizeHeaders(req.body.headers);
  const authed = Object.keys(authHeaders).length > 0;
  const doFuzz = req.body.fuzz;               // default false
  const doAccess = req.body.access;           // default true
  const doEnumerate = req.body.enumerate;     // default false
  const fuzzOpts = {
    method: req.body.method,                  // validated enum (or undefined → GET)
    body: req.body.body,                       // validated ≤100k string (or undefined)
    contentType: req.body.contentType,
    allowWrite: req.body.allowWrite,           // default false
    rateLimit: req.body.rateLimit,             // default false
    customPayloads: req.body.customPayloads    // validated string[] (≤50 × ≤2000), else undefined
  };

  try {
    const sections = await runWithAuth(authHeaders, () => Promise.all([
      runSection('api', 'API endpoint', () => scanApi(target)),
      ...(doAccess ? [runSection('access', 'Access control & IDOR', () => scanAccess(target, fuzzOpts))] : []),
      ...(doEnumerate ? [runSection('spec', 'API surface (OpenAPI)', () => scanApiSpec(target))] : []),
      ...(doFuzz ? [runSection('fuzz', 'Parameter fuzzing', () => scanApiFuzz(target, fuzzOpts))] : [])
    ]));
    // If the core API check itself failed (host unreachable), surface that.
    const apiSection = sections.find((s) => s.category === 'api');
    if (apiSection && apiSection.error) return res.status(400).json({ ok: false, error: apiSection.error });
    res.json(buildReport('api', sections, { target, authenticated: authed, fuzzed: doFuzz }));
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Build all code-scan sections (secrets/deps + the native audits) from entries.
async function buildCodeSections(entries) {
  const scan = await scanCode(entries);
  const sections = [{ category: 'code', label: 'Source code', meta: scan.meta, findings: scan.findings }];
  try {
    const audit = scanCodeAudit(entries);
    sections.push(
      { category: 'seccode', label: 'Code security', meta: {}, findings: audit.seccode },
      { category: 'deps', label: 'Dependencies', meta: {}, findings: audit.deps },
      { category: 'quality', label: 'Code quality', meta: {}, findings: audit.quality },
      { category: 'frontend', label: 'Frontend quality', meta: {}, findings: audit.frontend },
      { category: 'config', label: 'Config & DevOps', meta: {}, findings: audit.config },
      { category: 'testing', label: 'Testing', meta: {}, findings: audit.testing },
      { category: 'hygiene', label: 'Project hygiene', meta: {}, findings: audit.hygiene }
    );
  } catch (e) { /* audit is best-effort; core code scan already succeeded */ }
  return sections;
}

// --- Source-code scan (upload) ---------------------------------------------
app.post('/api/scan/files', gate, fileLimiter, upload.any(), async (req, res) => {
  try {
    const files = req.files || [];
    if (!files.length) return res.status(400).json({ ok: false, error: 'No files were uploaded.' });

    let entries = [];
    for (const f of files) {
      const name = f.originalname || 'file';
      if (/\.zip$/i.test(name)) {
        try { entries.push(...entriesFromZip(f.buffer)); }
        catch (e) { return res.status(400).json({ ok: false, error: `Could not read zip "${name}": ${e.message}` }); }
      } else {
        entries.push({ path: name, buffer: f.buffer });
      }
    }
    if (!entries.length) return res.status(400).json({ ok: false, error: 'No analyzable files found in the upload.' });

    const sections = await buildCodeSections(entries);
    res.json(buildReport('code', sections, { files: files.length }));
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// --- Source-code scan (GitHub repo) ----------------------------------------
// SSRF-safe (host hard-coded to GitHub) + bomb-safe (size/entry caps).
app.post('/api/scan/github', gate, fileLimiter, validate(githubSchema), async (req, res) => {
  try {
    const { meta, entries } = await fetchRepoEntries(req.body.url);
    const sections = await buildCodeSections(entries);
    res.json(buildReport('code', sections, { repo: meta.repo, ref: meta.ref, files: meta.files }));
  } catch (e) {
    res.status(e.status || 400).json({ ok: false, error: e.message });
  }
});

// Centralized error handler — maps known errors to safe status codes and never
// leaks stack traces to the client (OWASP: improper error handling).
app.use((err, req, res, next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ ok: false, error: 'Upload too large (60 MB limit per file).' });
  }
  if (err && err.code && /^LIMIT_/.test(err.code)) {
    return res.status(400).json({ ok: false, error: 'Upload rejected (too many files or invalid form).' });
  }
  if (err && (err.type === 'entity.parse.failed' || err instanceof SyntaxError)) {
    return res.status(400).json({ ok: false, error: 'Invalid JSON in request body.' });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ ok: false, error: 'Request body too large (1 MB limit).' });
  }
  console.error('Unhandled error:', err && err.message);
  res.status(500).json({ ok: false, error: 'Unexpected server error.' });
});

app.listen(PORT, () => {
  console.log(`SentryScan running at http://localhost:${PORT}`);
});
