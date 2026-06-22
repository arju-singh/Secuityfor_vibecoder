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
import { scanApiFuzz } from './src/scanners/apiFuzzScanner.js';
import { scanAccess } from './src/scanners/accessScanner.js';
import { scanApiSpec } from './src/scanners/apiSpecScanner.js';
import { scanAudits } from './src/scanners/auditScanner.js';
import { scoreFindings, summarize } from './src/scanners/scoring.js';
import { normalizeUrl, runWithAuth } from './src/scanners/util.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

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
app.post('/api/test/website', async (req, res) => {
  const target = req.body && req.body.url;
  if (!target) return res.status(400).json({ ok: false, error: 'A "url" field is required.' });
  const includeRender = req.body.render !== false;

  // Validate/normalize the target up front so an invalid or blocked URL returns
  // a clear error instead of a misleading "all suites unavailable" 100/A report.
  try {
    normalizeUrl(target);
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.message });
  }

  const authHeaders = sanitizeHeaders(req.body.headers);
  const authed = Object.keys(authHeaders).length > 0;
  const doAudits = req.body.audits !== false; // performance / a11y / SEO, on by default

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
app.post('/api/test/api', async (req, res) => {
  const target = req.body && req.body.url;
  if (!target) return res.status(400).json({ ok: false, error: 'A "url" field is required.' });
  try {
    normalizeUrl(target);
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.message });
  }

  const authHeaders = sanitizeHeaders(req.body.headers);
  const authed = Object.keys(authHeaders).length > 0;
  const doFuzz = req.body.fuzz === true;
  const doAccess = req.body.access !== false; // access-control checks on by default
  const doEnumerate = req.body.enumerate === true;
  const fuzzOpts = {
    method: req.body.method,
    body: typeof req.body.body === 'string' ? req.body.body : undefined,
    contentType: req.body.contentType,
    allowWrite: req.body.allowWrite === true,
    rateLimit: req.body.rateLimit === true,
    customPayloads: Array.isArray(req.body.customPayloads)
      ? req.body.customPayloads.filter((s) => typeof s === 'string' && s.length <= 2000).slice(0, 15)
      : undefined
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

// --- Source-code scan ------------------------------------------------------
app.post('/api/scan/files', upload.any(), async (req, res) => {
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

    const scan = await scanCode(entries);
    const sections = [{ category: 'code', label: 'Source code', meta: scan.meta, findings: scan.findings }];
    // Native static-analysis audits (quality, frontend, config, testing, hygiene).
    try {
      const audit = scanCodeAudit(entries);
      sections.push(
        { category: 'quality', label: 'Code quality', meta: {}, findings: audit.quality },
        { category: 'frontend', label: 'Frontend quality', meta: {}, findings: audit.frontend },
        { category: 'config', label: 'Config & DevOps', meta: {}, findings: audit.config },
        { category: 'testing', label: 'Testing', meta: {}, findings: audit.testing },
        { category: 'hygiene', label: 'Project hygiene', meta: {}, findings: audit.hygiene }
      );
    } catch (e) { /* audit is best-effort; core code scan already succeeded */ }
    res.json(buildReport('code', sections, { files: files.length }));
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.use((err, req, res, next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ ok: false, error: 'Upload too large (60 MB limit per file).' });
  }
  res.status(500).json({ ok: false, error: err.message || 'Unexpected server error.' });
});

app.listen(PORT, () => {
  console.log(`SentryScan running at http://localhost:${PORT}`);
});
