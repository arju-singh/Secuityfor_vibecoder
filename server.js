import express from 'express';
import multer from 'multer';
import path from 'node:path';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { scanUrl } from './src/scanners/urlScanner.js';
import { scanUi } from './src/scanners/uiScanner.js';
import { scanApi } from './src/scanners/apiScanner.js';
import { scanVuln } from './src/scanners/vulnScanner.js';
import { scanRender } from './src/scanners/renderScanner.js';
import { scanCode, entriesFromZip, scopeEntries } from './src/scanners/codeScanner.js';
import { scanCodeAudit } from './src/scanners/codeAuditScanner.js';
import { fetchRepoEntries, parseRepoUrl } from './src/scanners/githubScanner.js';
import { listSchedules, getSchedule, putSchedule, patchSchedule, deleteSchedule, CADENCE_MS } from './src/scheduler/scheduleStore.js';
import { saveScan, getScan, deleteScan, listScans, summaryOf } from './src/projects/scanStore.js';
import { getDismissals, setDismissal, clearDismissal } from './src/projects/dismissalStore.js';
import { findingFingerprint } from './src/projects/fingerprint.js';
import { buildAnalytics } from './src/analytics/analyticsService.js';
import { scanApiFuzz } from './src/scanners/apiFuzzScanner.js';
import { scanAccess } from './src/scanners/accessScanner.js';
import { scanApiSpec } from './src/scanners/apiSpecScanner.js';
import { scanVapt } from './src/scanners/vaptScanner.js';
import { scanAudits } from './src/scanners/auditScanner.js';
import { scoreFindings, summarize } from './src/scanners/scoring.js';
import { normalizeUrl, runWithAuth, enrichFinding, fetchWithTimeout } from './src/scanners/util.js';
import cookieParser from 'cookie-parser';
import { securityHeaders } from './src/middleware/security.js';
import { rateLimit, clientKey } from './src/middleware/rateLimit.js';
import { validate, websiteSchema, apiSchema, credentialsSchema, githubSchema, vaptSchema, billingSchema, forgotSchema, resetSchema } from './src/middleware/validate.js';
import { hashPassword, verifyPassword, issueToken, verifyToken, signScoped, verifyScoped, setAuthCookie, clearAuthCookie, requireAuth } from './src/auth/auth.js';
import { getUser, hasUser, putUser, setUserPlan, updateUser, findByCustomerId } from './src/auth/store.js';
import { checkLock, recordFailure, recordSuccess } from './src/auth/bruteforce.js';
import { createToken, consumeToken } from './src/auth/tokens.js';
import { isEmailConfigured, sendMail, verificationEmail, resetEmail } from './src/email/mailer.js';
import { isGoogleConfigured, getAuthUrl, exchangeCode } from './src/auth/oauth.js';
import { isConfigured as billingConfigured, createCheckoutSession, createPortalSession, constructEvent, planChangeFromEvent } from './src/billing/billing.js';

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
// Client-routed pages (Coverage / VAPT / How it works / Why us / Pricing / FAQ):
// serve the single-page app so deep links and refreshes resolve to the router.
app.get(['/coverage', '/vapt', '/how-it-works', '/why-us', '/pricing', '/faq', '/methodology'], (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html')));
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
// Global limiter on all API routes EXCEPT the Stripe webhook: Stripe redelivers
// from a small IP pool and retries aggressively, so IP-keyed limiting there could
// answer a retry burst with 429 and permanently drop a paid upgrade.
app.use('/api', (req, res, next) => (req.path === '/billing/webhook' ? next() : apiLimiter(req, res, next)));

// Gating of the scan endpoints. Signup is required to scan BY DEFAULT so every
// scan is tied to an account and saved to that user's project dashboard; set
// REQUIRE_AUTH=0 to allow anonymous scans (those aren't persisted).
// REQUIRE_VERIFIED=1 → must also have a verified email (implies auth).
const REQUIRE_AUTH = process.env.REQUIRE_AUTH !== '0';
const REQUIRE_VERIFIED = process.env.REQUIRE_VERIFIED === '1';
function gate(req, res, next) {
  if (!REQUIRE_AUTH && !REQUIRE_VERIFIED) return next();
  requireAuth(req, res, () => {
    if (REQUIRE_VERIFIED) {
      const u = getUser(req.user.email);
      if (!u || !u.emailVerified) {
        return res.status(403).json({ ok: false, error: 'Please verify your email before scanning — check your inbox for the verification link.' });
      }
    }
    next();
  });
}

// --- Authentication: JWT cookie auth (bcrypt) + brute-force prevention ------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const appBaseUrl = (req) => process.env.APP_URL || `${req.protocol}://${req.get('host')}`;

// Best-effort verification email — never blocks or fails the calling request.
async function sendVerification(req, email) {
  try {
    const token = createToken(email, 'verify');
    const link = `${appBaseUrl(req)}/api/auth/verify?token=${encodeURIComponent(token)}`;
    await sendMail({ to: email, ...verificationEmail(link) });
  } catch (e) {
    console.warn(`[auth] verification email not sent to ${email}: ${e.message}`);
  }
}

app.post('/api/auth/register', authLimiter, validate(credentialsSchema), async (req, res) => {
  const { email, password } = req.body;
  if (!EMAIL_RE.test(email)) return res.status(400).json({ ok: false, error: 'Enter a valid email address.' });
  if (hasUser(email)) return res.status(409).json({ ok: false, error: 'An account with that email already exists.' });
  const hash = await hashPassword(password);
  putUser(email, hash);
  await sendVerification(req, email.toLowerCase());
  setAuthCookie(req, res, issueToken(email.toLowerCase()));
  res.json({ ok: true, user: { email: email.toLowerCase(), plan: 'free', emailVerified: false }, emailSent: isEmailConfigured() });
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
  // Include plan/emailVerified so the UI can show the right billing controls
  // immediately after login, without waiting for a full page reload.
  res.json({ ok: true, user: { email: user.email, plan: user.plan || 'free', emailVerified: !!user.emailVerified } });
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
  res.json({
    ok: true,
    authenticated: !!payload,
    user: payload ? { email: payload.sub, plan: (user && user.plan) || 'free', emailVerified: !!(user && user.emailVerified) } : null
  });
});

// --- Email verification -----------------------------------------------------
// Consume the single-use token and mark the account verified, then bounce back
// to the app with a status flag the UI can surface.
app.get('/api/auth/verify', authLimiter, (req, res) => {
  const email = consumeToken('verify', String(req.query.token || ''));
  if (!email) return res.redirect('/?verify=invalid');
  updateUser(email, { emailVerified: true });
  res.redirect('/?verify=success');
});

// Resend the verification email to the currently logged-in user.
app.post('/api/auth/verify/request', authLimiter, requireAuth, async (req, res) => {
  const u = getUser(req.user.email);
  const sent = !!(u && !u.emailVerified);
  if (sent) await sendVerification(req, req.user.email);
  // Report a send only when one actually happened (an already-verified user gets
  // nothing sent, so don't claim otherwise).
  res.json({ ok: true, emailSent: sent && isEmailConfigured(), alreadyVerified: !!(u && u.emailVerified) });
});

// --- Password reset ---------------------------------------------------------
// Always responds 200 so the response can't be used to enumerate accounts.
app.post('/api/auth/forgot', authLimiter, validate(forgotSchema), async (req, res) => {
  const email = String(req.body.email).toLowerCase();
  if (EMAIL_RE.test(email) && hasUser(email)) {
    try {
      const token = createToken(email, 'reset');
      const link = `${appBaseUrl(req)}/reset.html?token=${encodeURIComponent(token)}`;
      await sendMail({ to: email, ...resetEmail(link) });
    } catch (e) { console.warn(`[auth] reset email not sent: ${e.message}`); }
  }
  res.json({ ok: true });
});

// Complete the reset using the token from the email.
app.post('/api/auth/reset', authLimiter, validate(resetSchema), async (req, res) => {
  const email = consumeToken('reset', req.body.token);
  if (!email) return res.status(400).json({ ok: false, error: 'This reset link is invalid or has expired.' });
  const hash = await hashPassword(req.body.password);
  updateUser(email, { passwordHash: hash });
  recordSuccess([`email:${email}`]); // clear any brute-force lock for this account
  res.json({ ok: true });
});

// --- Google OAuth (optional; endpoints report not-configured until set up) ---
const googleRedirectUri = (req) => `${appBaseUrl(req)}/api/auth/google/callback`;

app.get('/api/auth/google', authLimiter, (req, res) => {
  if (!isGoogleConfigured()) return res.status(503).json({ ok: false, error: 'Google sign-in is not configured.' });
  // The state is a signed, short-lived token mirrored in an httpOnly cookie —
  // the callback requires both to match, blocking OAuth CSRF / login-fixation.
  const state = signScoped({ purpose: 'oauth' }, 600);
  res.cookie('oauth_state', state, { httpOnly: true, sameSite: 'lax', secure: !!req.secure, maxAge: 600_000, path: '/' });
  res.redirect(getAuthUrl(state, googleRedirectUri(req)));
});

app.get('/api/auth/google/callback', authLimiter, async (req, res) => {
  if (!isGoogleConfigured()) return res.redirect('/?login=google_unavailable');
  const { code, state } = req.query;
  const cookieState = req.cookies && req.cookies.oauth_state;
  res.clearCookie('oauth_state', { path: '/' });
  const sp = state && verifyScoped(String(state));
  if (!code || !state || state !== cookieState || !sp || sp.purpose !== 'oauth') {
    return res.redirect('/?login=google_error');
  }
  try {
    const { email, verified } = await exchangeCode(String(code), googleRedirectUri(req));
    if (!hasUser(email)) putUser(email, null, { provider: 'google', emailVerified: verified });
    else if (verified) updateUser(email, { emailVerified: true });
    setAuthCookie(req, res, issueToken(email));
    res.redirect('/?login=success');
  } catch (e) {
    console.warn(`[auth] google callback failed: ${e.message}`);
    res.redirect('/?login=google_error');
  }
});

// --- Public feature flags for the frontend (what's configured on this server) -
app.get('/api/config', (req, res) => {
  res.json({
    ok: true,
    googleEnabled: isGoogleConfigured(),
    billingEnabled: billingConfigured(),
    emailEnabled: isEmailConfigured(),
    supportEmail: process.env.SUPPORT_EMAIL || 'support@sentryscan.app',
    analytics: {
      provider: process.env.ANALYTICS_PROVIDER || null,
      domain: process.env.ANALYTICS_DOMAIN || null,
      src: process.env.ANALYTICS_SRC || null
    }
  });
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

// Open the Stripe customer portal for self-service upgrade / downgrade / cancel.
app.post('/api/billing/portal', requireAuth, async (req, res) => {
  try {
    const u = getUser(req.user.email);
    const session = await createPortalSession(u && u.stripeCustomerId, `${appBaseUrl(req)}/?billing=portal`);
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
  if (change) {
    // Cancellation events may carry the customer but not the email — resolve it.
    let email = change.email;
    if (!email && change.customerId) { const u = findByCustomerId(change.customerId); email = u && u.email; }
    if (email) {
      setUserPlan(email, change.plan);
      if (change.customerId) updateUser(email, { stripeCustomerId: change.customerId });
    }
  }
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
  // Every finding funnels through here on its way into a report, so this is the
  // one place to guarantee category, Confidence, and Impact are all present.
  return (findings || []).map((f) => enrichFinding({ ...f, category }));
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

// Hard cap so a single slow/hanging suite can never stall the whole scan. The
// race only unblocks the response — the underlying scanner finishes/cleans up on
// its own — but the user always gets a timely report with the slow suite marked.
const SECTION_TIMEOUT_MS = num(process.env.SCAN_SECTION_TIMEOUT_MS, 30_000);
const RENDER_TIMEOUT_MS = num(process.env.SCAN_RENDER_TIMEOUT_MS, 55_000); // headless browser needs longer
function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${Math.round(ms / 1000)}s on this target.`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// Run a scanner and capture errors/timeouts into a section instead of failing
// the whole report — so one suite (or one unusual target) can't break the scan.
async function runSection(category, label, fn, timeoutMs = SECTION_TIMEOUT_MS) {
  try {
    const r = await withTimeout(Promise.resolve().then(fn), timeoutMs, label);
    return { category, label, meta: r.meta, findings: r.findings };
  } catch (e) {
    return { category, label, meta: {}, findings: [], error: e.message };
  }
}

// Quality audits share a single page fetch but produce three sections.
const AUDIT_LABELS = { perf: 'Performance', a11y: 'Accessibility', seo: 'SEO' };
async function auditSections(target) {
  try {
    const a = await withTimeout(Promise.resolve().then(() => scanAudits(target)), SECTION_TIMEOUT_MS, 'Quality audits');
    return [
      { category: 'perf', label: AUDIT_LABELS.perf, meta: a.meta, findings: a.perf },
      { category: 'a11y', label: AUDIT_LABELS.a11y, meta: a.meta, findings: a.a11y },
      { category: 'seo', label: AUDIT_LABELS.seo, meta: a.meta, findings: a.seo }
    ];
  } catch (e) {
    return Object.keys(AUDIT_LABELS).map((c) => ({ category: c, label: AUDIT_LABELS[c], meta: {}, findings: [], error: e.message }));
  }
}

// --- Shared scan runners ----------------------------------------------------
// The scan orchestration lives in these functions so both the interactive HTTP
// routes AND the scheduler (/api/schedule/run) execute scans identically. They
// return a finished report object or throw an Error (with an optional `.status`).

async function performWebsiteScan({ url, render = true, audits = true, vapt = false, effort = 'extended', headers } = {}) {
  normalizeUrl(url); // throws on invalid / blocked (SSRF) target → mapped to 400
  const authHeaders = sanitizeHeaders(headers);
  const authed = Object.keys(authHeaders).length > 0;
  const results = await runWithAuth(authHeaders, () => Promise.all([
    runSection('ui', 'Website health & UI', () => scanUi(url)),
    runSection('security', 'Security', () => scanUrl(url)),
    runSection('vuln', 'Vulnerabilities & OWASP', () => scanVuln(url, { effort })),
    ...(render ? [runSection('render', 'JavaScript & render', () => scanRender(url, { authHeaders }), RENDER_TIMEOUT_MS)] : []),
    ...(vapt ? [runSection('vapt', 'Active pen-test (VAPT)', () => scanVapt(url, { effort }))] : []),
    ...(audits ? [auditSections(url)] : [])
  ]));
  const sections = results.flat(); // auditSections returns an array of 3
  // If the network-dependent suites all failed (e.g. host unreachable), the
  // target couldn't be assessed — surface that instead of a misleading 100/A.
  const networkSections = sections.filter((s) => s.category !== 'render');
  if (networkSections.length && networkSections.every((s) => s.error)) {
    const e = new Error(networkSections[0].error); e.status = 400; throw e;
  }
  const finalUrl = sections.find((s) => s.meta && s.meta.finalUrl);
  return buildReport('website', sections, { target: url, authenticated: authed, effort, finalUrl: finalUrl ? finalUrl.meta.finalUrl : url });
}

async function performApiScan({ url, headers, fuzz = false, access = true, enumerate = false, vapt = false, method, body, contentType, allowWrite = false, rateLimit = false, customPayloads } = {}) {
  normalizeUrl(url);
  const authHeaders = sanitizeHeaders(headers);
  const authed = Object.keys(authHeaders).length > 0;
  const fuzzOpts = { method, body, contentType, allowWrite, rateLimit, customPayloads };
  const sections = await runWithAuth(authHeaders, () => Promise.all([
    runSection('api', 'API endpoint', () => scanApi(url)),
    ...(access ? [runSection('access', 'Access control & IDOR', () => scanAccess(url, fuzzOpts))] : []),
    ...(enumerate ? [runSection('spec', 'API surface (OpenAPI)', () => scanApiSpec(url))] : []),
    ...(vapt ? [runSection('vapt', 'Active pen-test (VAPT)', () => scanVapt(url, fuzzOpts))] : []),
    ...(fuzz ? [runSection('fuzz', 'Parameter fuzzing', () => scanApiFuzz(url, fuzzOpts))] : [])
  ]));
  const apiSection = sections.find((s) => s.category === 'api');
  if (apiSection && apiSection.error) { const e = new Error(apiSection.error); e.status = 400; throw e; }
  return buildReport('api', sections, { target: url, authenticated: authed, fuzzed: fuzz });
}

// Full VAPT assessment: the entire black-box battery against a single target —
// recon/health, security posture, OWASP vuln probes, the active pen-test engine,
// access-control, API checks + surface enumeration + injection fuzzing, and a
// headless render. allowWrite unlocks the state-changing probes (brute-force,
// race, write-fuzz). One combined, OWASP-mapped report. Reused by route +
// (potentially) scheduler, same as the other perform* runners.
async function performVaptScan({ url, headers, effort = 'extended', allowWrite = false } = {}) {
  normalizeUrl(url); // throws on invalid / blocked (SSRF) target → mapped to 400
  const authHeaders = sanitizeHeaders(headers);
  const authed = Object.keys(authHeaders).length > 0;
  const fuzzOpts = { method: 'GET', allowWrite, rateLimit: allowWrite };
  const results = await runWithAuth(authHeaders, () => Promise.all([
    runSection('ui', 'Recon & health', () => scanUi(url)),
    runSection('security', 'Security headers, TLS & exposure', () => scanUrl(url)),
    runSection('vuln', 'Vulnerabilities & OWASP', () => scanVuln(url, { effort })),
    runSection('vapt', 'Active pen-test (VAPT)', () => scanVapt(url, { effort, allowWrite, method: 'GET' })),
    runSection('access', 'Access control & IDOR', () => scanAccess(url, fuzzOpts)),
    runSection('api', 'API endpoint', () => scanApi(url)),
    runSection('spec', 'API surface (OpenAPI)', () => scanApiSpec(url)),
    runSection('fuzz', 'Injection & input fuzzing', () => scanApiFuzz(url, fuzzOpts)),
    runSection('render', 'JavaScript & render', () => scanRender(url, { authHeaders }), RENDER_TIMEOUT_MS)
  ]));
  const networkSections = results.filter((s) => s.category !== 'render');
  if (networkSections.length && networkSections.every((s) => s.error)) {
    const e = new Error(networkSections[0].error); e.status = 400; throw e;
  }
  const finalUrl = results.find((s) => s.meta && s.meta.finalUrl);
  return buildReport('vapt', results, { target: url, authenticated: authed, effort, mode: 'vapt', finalUrl: finalUrl ? finalUrl.meta.finalUrl : url });
}

async function performGithubScan({ url, effort = 'extended', paths } = {}) {
  const { meta, entries } = await fetchRepoEntries(url); // throws with .status on GitHub errors
  const scoped = scopeEntries(entries, paths);
  if (!scoped.length) {
    const e = new Error(`No files in ${meta.repo} matched the path scope (${(paths || []).join(', ')}).`); e.status = 400; throw e;
  }
  const sections = await buildCodeSections(scoped, effort);
  return buildReport('code', sections, {
    repo: meta.repo, ref: meta.ref, files: scoped.length,
    effort, scopedFrom: entries.length, scope: (paths || []).length ? paths : undefined
  });
}

// Save a finished report to the signed-in user's project dashboard and stamp the
// response with its id/project. A no-op for anonymous scans (REQUIRE_AUTH=0).
function persistScan(req, report) {
  if (!req.user || !req.user.email || !report || report.ok === false) return report;
  const project = (req.body && req.body.project) || 'Default';
  const saved = saveScan(req.user.email, project, report);
  if (saved) { report.scanId = saved.id; report.project = saved.project; }
  return report;
}

// --- Full website test: UI health + security + render ----------------------
// scanLimiter throttles expensive scans; validate() enforces the request schema.
app.post('/api/test/website', gate, scanLimiter, validate(websiteSchema), async (req, res) => {
  try {
    const report = await performWebsiteScan({
      url: req.body.url, render: req.body.render, audits: req.body.audits, vapt: req.body.vapt,
      effort: req.body.effort, headers: req.body.headers
    });
    res.json(persistScan(req, report));
  } catch (e) {
    res.status(e.status || 400).json({ ok: false, error: e.message });
  }
});

// --- API test --------------------------------------------------------------
app.post('/api/test/api', gate, scanLimiter, validate(apiSchema), async (req, res) => {
  try {
    const report = await performApiScan({
      url: req.body.url, headers: req.body.headers, fuzz: req.body.fuzz, access: req.body.access,
      enumerate: req.body.enumerate, vapt: req.body.vapt, method: req.body.method, body: req.body.body,
      contentType: req.body.contentType, allowWrite: req.body.allowWrite,
      rateLimit: req.body.rateLimit, customPayloads: req.body.customPayloads
    });
    res.json(persistScan(req, report));
  } catch (e) {
    res.status(e.status || 400).json({ ok: false, error: e.message });
  }
});

// --- Full VAPT assessment --------------------------------------------------
// Runs the entire scanner battery against one target and returns one combined,
// OWASP-mapped report. allowWrite unlocks the state-changing probes.
app.post('/api/test/vapt', gate, scanLimiter, validate(vaptSchema), async (req, res) => {
  try {
    const report = await performVaptScan({
      url: req.body.url, headers: req.body.headers,
      effort: req.body.effort, allowWrite: req.body.allowWrite
    });
    res.json(persistScan(req, report));
  } catch (e) {
    res.status(e.status || 400).json({ ok: false, error: e.message });
  }
});

// Build all code-scan sections (secrets/deps + the native audits) from entries.
// effort='regular' runs only the fast core secret/dependency scan; 'extended'
// (default) adds the deeper native audits (code security, quality, config, …).
async function buildCodeSections(entries, effort = 'extended') {
  const scan = await scanCode(entries);
  const sections = [{ category: 'code', label: 'Source code', meta: scan.meta, findings: scan.findings }];
  if (effort === 'regular') return sections;
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

    // Multipart text fields: effort ('regular'|'extended') and optional path scope.
    const effort = req.body.effort === 'regular' ? 'regular' : 'extended';
    const paths = parsePathsField(req.body.paths);
    const total = entries.length;
    entries = scopeEntries(entries, paths);
    if (!entries.length) {
      return res.status(400).json({ ok: false, error: `No files matched the path scope (${paths.join(', ')}).` });
    }

    const sections = await buildCodeSections(entries, effort);
    const report = buildReport('code', sections, { files: entries.length, effort, scopedFrom: total, scope: paths.length ? paths : undefined });
    res.json(persistScan(req, report));
  } catch (e) {
    // Deliberate, user-facing errors carry an explicit .status; anything else is
    // an unexpected internal failure whose message we must not leak to the client.
    if (e.status) return res.status(e.status).json({ ok: false, error: e.message });
    console.error('[scan/files]', e);
    res.status(500).json({ ok: false, error: 'The scan could not be completed. Please try again.' });
  }
});

// A multipart form can only send strings, so the path scope arrives as a
// newline/comma-separated field; normalize it to the same array shape the JSON
// (GitHub) route already validates.
function parsePathsField(v) {
  if (Array.isArray(v)) return v;
  if (typeof v !== 'string' || !v.trim()) return [];
  return v.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean).slice(0, 50);
}

// --- Source-code scan (GitHub repo) ----------------------------------------
// SSRF-safe (host hard-coded to GitHub) + bomb-safe (size/entry caps).
app.post('/api/scan/github', gate, fileLimiter, validate(githubSchema), async (req, res) => {
  try {
    const report = await performGithubScan({ url: req.body.url, effort: req.body.effort, paths: req.body.paths });
    res.json(persistScan(req, report));
  } catch (e) {
    res.status(e.status || 400).json({ ok: false, error: e.message });
  }
});

// --- Export a report to a webhook ------------------------------------------
// Forwards the report JSON to a user-supplied URL. Routed server-side because a
// browser can't POST cross-origin to an arbitrary host, and validated through
// the SAME SSRF guard (normalizeUrl) used for scan targets so this endpoint
// can't be abused to reach localhost / cloud-metadata / private ranges.
app.post('/api/export/webhook', gate, scanLimiter, async (req, res) => {
  const { url, report } = req.body || {};
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ ok: false, error: 'A webhook URL is required.' });
  }
  if (!report || typeof report !== 'object') {
    return res.status(400).json({ ok: false, error: 'A report payload is required.' });
  }
  let result;
  try {
    result = await deliverWebhook(url, report, req.body.format);
  } catch (e) {
    return res.status(e.status || 502).json({ ok: false, error: e.message });
  }
  return res.json(result);
});

// POST a report to a webhook, formatting for Slack when the host is Slack (or
// format='slack' is forced). Throws (with `.status`) on a blocked URL or an
// unreachable receiver. Shared by the export endpoint and the scheduler.
async function deliverWebhook(url, report, format) {
  let target;
  try {
    target = normalizeUrl(url); // throws on localhost / private / metadata hosts
  } catch (e) { e.status = 400; throw e; }
  const slack = format === 'slack' || /(^|\.)hooks\.slack\.com$/i.test(target.hostname);
  const payload = slack ? slackPayload(report) : { source: 'sentryscan', sentAt: new Date().toISOString(), report };
  let hook;
  try {
    hook = await fetchWithTimeout(target.href, {
      method: 'POST',
      timeout: 10000,
      redirect: 'manual', // don't follow a redirect to a private host (SSRF)
      noAuth: true,        // never leak the caller's scan-auth headers to the webhook
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'SentryScan-Webhook/1.0' },
      body: JSON.stringify(payload)
    });
  } catch (e) { const err = new Error(`Could not reach the webhook: ${e.message}`); err.status = 502; throw err; }
  // Report the receiver's status back; a 2xx/3xx means it was accepted.
  return { ok: hook.status < 400, status: hook.status, format: slack ? 'slack' : 'json' };
}

// Build a Slack message (Block Kit) summarizing a report and its top findings.
const SEV_EMOJI = { critical: '🟥', high: '🟧', medium: '🟨', low: '🟦', info: '⬜' };
function slackPayload(report) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const target = report.meta?.target || report.meta?.repo || report.type || 'scan';
  const counts = report.counts || {};
  const countLine = ['critical', 'high', 'medium', 'low', 'info']
    .filter((s) => counts[s]).map((s) => `${SEV_EMOJI[s]} ${counts[s]} ${s}`).join('   ') || 'No findings';
  const top = findings.filter((f) => !f.dismissed || f.dismissed === '').slice(0, 10);
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: `SentryScan: ${String(target).slice(0, 140)}` } },
    { type: 'section', text: { type: 'mrkdwn', text: `*Grade ${report.grade ?? '?'}* (${report.score ?? '?'}/100) · *${report.total ?? findings.length}* finding(s)\n${countLine}` } }
  ];
  top.forEach((f) => {
    const loc = f.location ? `\n\`${String(f.location).slice(0, 160)}\`` : '';
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: `${SEV_EMOJI[f.severity] || '•'} *${String(f.title).slice(0, 200)}*  _(${f.severity}${f.confidence ? ` · ${f.confidence} confidence` : ''})_${loc}` }
    });
  });
  if (findings.length > top.length) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: `_…and ${findings.length - top.length} more. Full report in SentryScan._` }] });
  }
  // `text` is the required notification fallback (screen readers / mobile).
  return { text: `SentryScan ${report.grade ?? ''} — ${report.total ?? findings.length} finding(s) on ${target}`, blocks };
}

// --- Export findings to Jira (creates one issue per finding) ----------------
// Credentials come from env (JIRA_BASE_URL / JIRA_EMAIL / JIRA_API_TOKEN /
// JIRA_PROJECT_KEY) and may be overridden per-request. The base URL is run
// through normalizeUrl (SSRF guard) exactly like a scan target.
const JIRA_SEV_PRIORITY = { critical: 'Highest', high: 'High', medium: 'Medium', low: 'Low', info: 'Lowest' };
app.post('/api/export/jira', gate, scanLimiter, async (req, res) => {
  const b = req.body || {};
  const baseUrl = b.baseUrl || process.env.JIRA_BASE_URL;
  const email = b.email || process.env.JIRA_EMAIL;
  const token = b.apiToken || process.env.JIRA_API_TOKEN;
  const projectKey = b.projectKey || process.env.JIRA_PROJECT_KEY;
  const findings = Array.isArray(b.findings) ? b.findings : [];
  if (!baseUrl || !email || !token || !projectKey) {
    return res.status(400).json({ ok: false, error: 'Jira not configured — provide baseUrl, email, apiToken and projectKey (or set JIRA_* env vars).' });
  }
  if (!findings.length) return res.status(400).json({ ok: false, error: 'No findings to export.' });
  let base;
  try { base = normalizeUrl(baseUrl); } catch (e) { return res.status(400).json({ ok: false, error: e.message }); }

  const auth = 'Basic ' + Buffer.from(`${email}:${token}`).toString('base64');
  const issueUrl = new URL('/rest/api/3/issue', base.origin).href;
  // Cap the batch so one export can't create hundreds of issues by accident.
  const batch = findings.slice(0, num(process.env.JIRA_MAX_ISSUES, 25));
  const created = [];
  const errors = [];
  for (const f of batch) {
    try {
      const hook = await fetchWithTimeout(issueUrl, {
        method: 'POST', timeout: 12000, redirect: 'manual', noAuth: true,
        headers: { Authorization: auth, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(jiraIssue(projectKey, f))
      });
      const data = await hook.json().catch(() => ({}));
      if (hook.status >= 200 && hook.status < 300 && data.key) created.push(data.key);
      else errors.push(data.errorMessages?.join('; ') || `HTTP ${hook.status}`);
    } catch (e) { errors.push(e.message); }
  }
  return res.json({ ok: created.length > 0, created, count: created.length, errors: errors.slice(0, 5), skipped: findings.length - batch.length });
});

// Jira issue body in Atlassian Document Format (ADF).
function jiraIssue(projectKey, f) {
  const para = (t) => ({ type: 'paragraph', content: [{ type: 'text', text: String(t || '—') }] });
  const heading = (t) => ({ type: 'heading', attrs: { level: 4 }, content: [{ type: 'text', text: t }] });
  const content = [heading('Details'), para(f.description)];
  if (f.impact) content.push(heading('Impact'), para(f.impact));
  if (f.location) content.push(heading('Location'), para(f.location));
  if (f.evidence) content.push(heading('Evidence'), para(f.evidence));
  if (f.remediation) content.push(heading('Recommended fix'), para(f.remediation));
  if (f.reproduction) content.push(heading('Reproduce'), para(f.reproduction));
  content.push(para(`Severity: ${f.severity} · Confidence: ${f.confidence || 'n/a'}${f.owasp ? ` · ${f.owasp}` : ''}`));
  return {
    fields: {
      project: { key: projectKey },
      summary: `[${String(f.severity || '').toUpperCase()}] ${String(f.title || 'Finding').slice(0, 240)}`,
      issuetype: { name: 'Bug' },
      description: { type: 'doc', version: 1, content }
    }
  };
}

// ============================================================================
// Project dashboard — everything a signed-in user's account knows about a
// project: saved scans, aggregate stats + score trend, in-project schedules,
// and a de-duplicated findings rollup with per-account dismissals applied.
// ============================================================================

// Open severity counts for a scan's findings, minus the user's dismissals.
function openCounts(findings, dismissals) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings || []) {
    if (dismissals[findingFingerprint(f)]) continue;
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }
  return counts;
}

// Aggregate one project's scans into a dashboard card.
function projectAggregate(name, scans, dismissals) {
  const sorted = [...scans].sort((a, b) => a.ts.localeCompare(b.ts)); // oldest→newest
  const latest = sorted[sorted.length - 1];
  return {
    name,
    scanCount: scans.length,
    lastScanAt: latest ? latest.ts : null,
    latest: latest ? { id: latest.id, grade: latest.grade, score: latest.score, type: latest.type, target: latest.target, total: latest.total } : null,
    open: latest ? openCounts(latest.findings, dismissals) : null,
    trend: sorted.slice(-20).map((s) => ({ ts: s.ts, score: s.score, grade: s.grade }))
  };
}

app.get('/api/projects', requireAuth, (req, res) => {
  const scans = listScans(req.user.email);
  const dismissals = getDismissals(req.user.email);
  const byProject = new Map();
  for (const s of scans) {
    if (!byProject.has(s.project)) byProject.set(s.project, []);
    byProject.get(s.project).push(s);
  }
  const projects = [...byProject.entries()]
    .map(([name, list]) => projectAggregate(name, list, dismissals))
    .sort((a, b) => (b.lastScanAt || '').localeCompare(a.lastScanAt || ''));
  res.json({ ok: true, projects });
});

app.get('/api/projects/:name', requireAuth, (req, res) => {
  const name = req.params.name;
  const scans = listScans(req.user.email, name);
  if (!scans.length) return res.status(404).json({ ok: false, error: 'No scans in that project yet.' });
  const dismissals = getDismissals(req.user.email);

  // Findings rollup: current state per distinct target (its latest scan), unioned
  // and de-duplicated by fingerprint, with dismissals applied. This is "the open
  // issues across the whole project right now".
  const latestByTarget = new Map();
  for (const s of scans) { // scans are newest-first
    if (!latestByTarget.has(s.target)) latestByTarget.set(s.target, s);
  }
  const seen = new Map();
  for (const s of latestByTarget.values()) {
    for (const f of s.findings || []) {
      const fp = findingFingerprint(f);
      if (seen.has(fp)) continue;
      const d = dismissals[fp];
      seen.set(fp, { ...f, fingerprint: fp, scanId: s.id, fromTarget: s.target, dismissed: d ? d.reason : null, dismissedAt: d ? d.ts : null });
    }
  }
  const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const rollup = [...seen.values()].sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));

  const schedules = listSchedules(req.user.email)
    .filter((s) => (s.project || 'Default') === name)
    .map((s) => ({ id: s.id, name: s.name, type: s.type, target: s.target, cadence: s.cadence, enabled: s.enabled, lastRunAt: s.lastRunAt, lastStatus: s.lastStatus, lastGrade: s.lastGrade, lastScore: s.lastScore, nextRunAt: s.nextRunAt }));

  res.json({
    ok: true,
    project: projectAggregate(name, scans, dismissals),
    scans: scans.map(summaryOf),
    schedules,
    rollup
  });
});

// Full saved report, with the user's dismissals annotated onto each finding.
app.get('/api/scans/:id', requireAuth, (req, res) => {
  const scan = getScan(req.params.id);
  if (!scan || scan.ownerEmail !== String(req.user.email).trim().toLowerCase()) {
    return res.status(404).json({ ok: false, error: 'Scan not found.' });
  }
  const dismissals = getDismissals(req.user.email);
  const findings = (scan.findings || []).map((f) => {
    const d = dismissals[findingFingerprint(f)];
    return d ? { ...f, dismissed: d.reason, dismissedAt: d.ts } : f;
  });
  // Shape it like a live report so the existing results view can render it.
  res.json({ ok: true, type: scan.type, score: scan.score, grade: scan.grade, total: scan.total, counts: scan.counts, categories: scan.categories || [], meta: scan.meta, project: scan.project, scanId: scan.id, savedAt: scan.ts, findings });
});

app.delete('/api/scans/:id', requireAuth, (req, res) => {
  const scan = getScan(req.params.id);
  if (!scan || scan.ownerEmail !== String(req.user.email).trim().toLowerCase()) {
    return res.status(404).json({ ok: false, error: 'Scan not found.' });
  }
  deleteScan(scan.id);
  res.json({ ok: true });
});

// Aggregate analytics ("VART") across all of the signed-in user's saved scans.
// Owner-scoped and auth-only (never a public/shareable URL); computed purely from
// stored data with no external calls; every finding it returns is secret-masked.
app.get('/api/analytics', requireAuth, (req, res) => {
  try {
    res.json(buildAnalytics(req.user.email));
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Could not build analytics.' });
  }
});

// Per-account finding dismissals (sync across devices; apply to every scan).
app.get('/api/dismissals', requireAuth, (req, res) => {
  res.json({ ok: true, dismissals: getDismissals(req.user.email) });
});
app.post('/api/dismissals', requireAuth, (req, res) => {
  const fp = req.body && req.body.fingerprint;
  if (!fp || typeof fp !== 'string') return res.status(400).json({ ok: false, error: 'A finding fingerprint is required.' });
  const rec = setDismissal(req.user.email, fp, req.body.reason, req.body.title);
  res.json({ ok: true, dismissal: rec });
});
app.delete('/api/dismissals/:fingerprint', requireAuth, (req, res) => {
  clearDismissal(req.user.email, req.params.fingerprint);
  res.json({ ok: true });
});

// ============================================================================
// Recurring scheduled scans (cron-ready)
// ----------------------------------------------------------------------------
// A schedule persists a scan config + cadence and pushes each run's report to an
// optional webhook. Two ways to drive them, non-exclusive:
//   1. External cron → POST /api/schedule/run (recommended; works even if the
//      process sleeps between runs). Protected by SCHEDULER_TOKEN.
//   2. In-process timer when ENABLE_SCHEDULER=1 (needs an always-on server).
// Only website/api/github targets are schedulable — uploads have no file to
// re-read on each run.
const SCHEDULE_MAX_PER_USER = num(process.env.SCHEDULE_MAX_PER_USER, 25);
const SCHEDULE_MAX_PER_RUN = num(process.env.SCHEDULE_MAX_PER_RUN, 25);

// Validate a create/update request into a stored schedule shape, or throw.
function buildScheduleFromBody(body, ownerEmail, existing) {
  const b = body || {};
  const name = String(b.name || '').trim().slice(0, 100) || 'Untitled schedule';
  const type = b.type;
  if (!['website', 'api', 'github'].includes(type)) {
    const e = new Error('type must be one of: website, api, github'); e.status = 400; throw e;
  }
  const target = String(b.target || '').trim();
  if (!target) { const e = new Error('A target URL is required.'); e.status = 400; throw e; }
  // Reject an invalid/blocked target up front so it never silently no-ops later.
  if (type === 'github') {
    if (!parseRepoUrl(target)) { const e = new Error('Provide a GitHub repository URL, e.g. https://github.com/owner/repo'); e.status = 400; throw e; }
  } else {
    try { normalizeUrl(target); } catch (e) { e.status = 400; throw e; }
  }
  const cadence = b.cadence;
  if (!CADENCE_MS[cadence]) { const e = new Error(`cadence must be one of: ${Object.keys(CADENCE_MS).join(', ')}`); e.status = 400; throw e; }
  if (b.webhook) { try { normalizeUrl(b.webhook); } catch (e) { const err = new Error(`webhook: ${e.message}`); err.status = 400; throw err; } }

  // Only keep scan options that apply to the chosen type; ignore the rest.
  const o = b.options && typeof b.options === 'object' ? b.options : {};
  const options = {};
  if (type === 'website') {
    options.render = o.render !== false;
    options.audits = o.audits !== false;
    options.vapt = !!o.vapt;
    options.effort = o.effort === 'regular' ? 'regular' : 'extended';
  } else if (type === 'api') {
    options.fuzz = !!o.fuzz; options.access = o.access !== false;
    options.enumerate = !!o.enumerate; options.rateLimit = !!o.rateLimit;
    options.vapt = !!o.vapt;
  } else if (type === 'github') {
    options.effort = o.effort === 'regular' ? 'regular' : 'extended';
    options.paths = Array.isArray(o.paths) ? o.paths.filter((p) => typeof p === 'string').slice(0, 50) : [];
  }
  // Optional auth headers for authenticated website/api scans (stored 0600).
  if ((type === 'website' || type === 'api') && o.headers && typeof o.headers === 'object' && !Array.isArray(o.headers)) {
    options.headers = o.headers;
  }

  return {
    id: existing ? existing.id : randomUUID(),
    ownerEmail: String(ownerEmail).trim().toLowerCase(),
    name, type, target, cadence, options,
    webhook: b.webhook ? String(b.webhook).trim() : null,
    webhookFormat: b.webhookFormat === 'slack' ? 'slack' : 'json',
    project: String(b.project || 'Default').trim().slice(0, 60) || 'Default',
    enabled: b.enabled !== false,
    createdAt: existing ? existing.createdAt : new Date().toISOString(),
    lastRunAt: existing ? existing.lastRunAt : null,
    lastStatus: existing ? existing.lastStatus : null,
    lastScore: existing ? existing.lastScore : null,
    lastError: existing ? existing.lastError : null,
    // Due immediately on the next run tick after creation.
    nextRunAt: existing ? existing.nextRunAt : new Date().toISOString()
  };
}

// Never return stored auth headers to the client.
function redactSchedule(s) {
  const { options, ...rest } = s;
  const safeOptions = { ...options };
  if (safeOptions.headers) safeOptions.headers = `(${Object.keys(safeOptions.headers).length} header(s) set)`;
  return { ...rest, options: safeOptions };
}

app.get('/api/schedule', requireAuth, (req, res) => {
  res.json({ ok: true, schedules: listSchedules(req.user.email).map(redactSchedule) });
});

app.post('/api/schedule', requireAuth, scanLimiter, (req, res) => {
  const existingCount = listSchedules(req.user.email).length;
  if (existingCount >= SCHEDULE_MAX_PER_USER) {
    return res.status(429).json({ ok: false, error: `Schedule limit reached (${SCHEDULE_MAX_PER_USER}). Delete one first.` });
  }
  let sched;
  try { sched = buildScheduleFromBody(req.body, req.user.email); }
  catch (e) { return res.status(e.status || 400).json({ ok: false, error: e.message }); }
  putSchedule(sched);
  res.status(201).json({ ok: true, schedule: redactSchedule(sched) });
});

app.delete('/api/schedule/:id', requireAuth, (req, res) => {
  const sched = getSchedule(req.params.id);
  if (!sched || sched.ownerEmail !== String(req.user.email).trim().toLowerCase()) {
    return res.status(404).json({ ok: false, error: 'Schedule not found.' });
  }
  deleteSchedule(sched.id);
  res.json({ ok: true });
});

// Run one of your own schedules on demand (the "Run now" button). Owner-scoped
// and rate-limited — distinct from the token-gated cron endpoint, which runs
// everyone's due schedules with no user session.
app.post('/api/schedule/:id/run', requireAuth, scanLimiter, async (req, res) => {
  const sched = getSchedule(req.params.id);
  if (!sched || sched.ownerEmail !== String(req.user.email).trim().toLowerCase()) {
    return res.status(404).json({ ok: false, error: 'Schedule not found.' });
  }
  const result = await runOneSchedule(sched);
  res.json({ ok: true, result });
});

// Run a single schedule now: execute the scan, deliver the webhook, record the
// outcome, and advance nextRunAt. Never throws — failures are captured on the
// schedule record so one bad target can't abort a whole run.
async function runOneSchedule(sched) {
  const startedAt = new Date().toISOString();
  const interval = CADENCE_MS[sched.cadence] || CADENCE_MS.daily;
  const nextRunAt = new Date(Date.now() + interval).toISOString();
  try {
    let report;
    if (sched.type === 'website') report = await performWebsiteScan({ url: sched.target, ...sched.options });
    else if (sched.type === 'api') report = await performApiScan({ url: sched.target, ...sched.options });
    else report = await performGithubScan({ url: sched.target, ...sched.options });

    // Save the run to the owner's project dashboard (same as an interactive scan).
    try { saveScan(sched.ownerEmail, sched.project, report); } catch { /* best-effort */ }

    let delivery = null;
    if (sched.webhook) {
      // Tag the report with the schedule's project so the receiver can attribute it.
      const tagged = { ...report, meta: { ...report.meta, project: sched.project, schedule: sched.name } };
      try { delivery = await deliverWebhook(sched.webhook, tagged, sched.webhookFormat); }
      catch (e) { delivery = { ok: false, error: e.message }; }
    }
    patchSchedule(sched.id, {
      lastRunAt: startedAt, nextRunAt, lastStatus: 'ok', lastError: null,
      lastScore: report.score, lastGrade: report.grade, lastTotal: report.total,
      lastDelivery: delivery
    });
    return { id: sched.id, name: sched.name, ok: true, score: report.score, grade: report.grade, total: report.total, delivery };
  } catch (e) {
    patchSchedule(sched.id, { lastRunAt: startedAt, nextRunAt, lastStatus: 'error', lastError: e.message });
    return { id: sched.id, name: sched.name, ok: false, error: e.message };
  }
}

// Select and run the schedules that are due (or a single one when id/force given).
async function runDueSchedules({ id = null, force = false } = {}) {
  const now = Date.now();
  let due = listSchedules().filter((s) => s.enabled !== false);
  if (id) due = due.filter((s) => s.id === id);
  else due = due.filter((s) => !s.nextRunAt || new Date(s.nextRunAt).getTime() <= now);
  if (!force && !id) due = due.slice(0, SCHEDULE_MAX_PER_RUN);
  const ran = [];
  // Sequential: scheduled scans are background work — don't stampede targets.
  for (const s of due) ran.push(await runOneSchedule(s));
  return { ran, count: ran.length };
}

// Cron entry point. Auth is a shared secret (constant-time compared) rather than
// a user session, because a cron job has no cookie. If SCHEDULER_TOKEN is unset
// the endpoint refuses to run — it never falls open.
function schedulerTokenOk(req) {
  const expected = process.env.SCHEDULER_TOKEN;
  if (!expected) return false;
  const got = (req.get('authorization') || '').replace(/^Bearer\s+/i, '') || req.get('x-scheduler-token') || '';
  const a = Buffer.from(got); const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

app.post('/api/schedule/run', async (req, res) => {
  if (!process.env.SCHEDULER_TOKEN) {
    return res.status(503).json({ ok: false, error: 'Scheduler is not enabled — set SCHEDULER_TOKEN to allow cron-triggered runs.' });
  }
  if (!schedulerTokenOk(req)) return res.status(401).json({ ok: false, error: 'Invalid scheduler token.' });
  try {
    const result = await runDueSchedules({ id: req.body?.id || null, force: !!req.body?.force });
    res.json({ ok: true, ...result });
  } catch (e) {
    console.error('[schedule/run]', e);
    res.status(500).json({ ok: false, error: 'Scheduled run failed.' });
  }
});

// Optional in-process timer for always-on deployments. Off unless ENABLE_SCHEDULER=1.
if (process.env.ENABLE_SCHEDULER === '1') {
  const everyMs = num(process.env.SCHEDULER_TICK_MS, 5 * 60 * 1000); // check every 5 min
  setInterval(() => { runDueSchedules().catch(() => { /* logged on the schedule record */ }); }, everyMs).unref();
  console.log(`[scheduler] in-process timer on — checking every ${Math.round(everyMs / 1000)}s`);
}

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
