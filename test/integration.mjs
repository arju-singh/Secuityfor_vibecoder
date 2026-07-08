// Integration test: stand up a deliberately-vulnerable local server and prove
// the fuzzer and authenticated scanning actually detect/exercise real bugs.
// Run with: SENTRYSCAN_ALLOW_LOCAL=1 node test/integration.mjs  (or `npm test`)
process.env.SENTRYSCAN_ALLOW_LOCAL = '1';

import express from 'express';
import { scanApiFuzz } from '../src/scanners/apiFuzzScanner.js';
import { scanAccess } from '../src/scanners/accessScanner.js';
import { scanApiSpec } from '../src/scanners/apiSpecScanner.js';
import { scanAudits } from '../src/scanners/auditScanner.js';
import { scanCodeAudit } from '../src/scanners/codeAuditScanner.js';
import { validateBody, websiteSchema, apiSchema, credentialsSchema, forgotSchema, resetSchema } from '../src/middleware/validate.js';
import { rateLimit } from '../src/middleware/rateLimit.js';
import { hashPassword, verifyPassword, issueToken, verifyToken } from '../src/auth/auth.js';
import * as bf from '../src/auth/bruteforce.js';
import { createToken, consumeToken } from '../src/auth/tokens.js';
import { isEmailConfigured, sendMail } from '../src/email/mailer.js';
import { isGoogleConfigured } from '../src/auth/oauth.js';
import { parseRepoUrl, safeExtract } from '../src/scanners/githubScanner.js';
import AdmZip from 'adm-zip';
import crypto from 'node:crypto';
import { putUser, setUserPlan, getUser, updateUser } from '../src/auth/store.js';
import { runWithAuth, fetchWithTimeout } from '../src/scanners/util.js';
import { scanVapt } from '../src/scanners/vaptScanner.js';
import { maskSecrets, maskFinding } from '../src/analytics/mask.js';
import { buildAnalytics } from '../src/analytics/analyticsService.js';
import { saveScan, deleteScan } from '../src/projects/scanStore.js';

let passed = 0, failed = 0;
function assert(cond, msg) {
  if (cond) { passed++; console.log('  ✓', msg); }
  else { failed++; console.log('  ✗ FAIL:', msg); }
}

// --- Deliberately-vulnerable test app --------------------------------------
const app = express();
app.use(express.json());

// Vulnerable POST: SQLi via the JSON body's username field.
app.post('/login', (req, res) => {
  const username = req.body && req.body.username;
  if (typeof username === 'string' && username.includes("'")) {
    return res.status(200).send(`You have an error in your SQL syntax near '${username}'`);
  }
  res.json({ ok: true });
});

// Vulnerable POST with a NESTED body field: user.name.
app.post('/profile', (req, res) => {
  const name = req.body && req.body.user && req.body.user.name;
  if (typeof name === 'string' && name.includes("'")) {
    return res.status(200).send(`You have an error in your SQL syntax near '${name}'`);
  }
  res.json({ ok: true });
});

// Boolean-injectable endpoint: a tautology returns a row, a contradiction empty.
app.get('/items', (req, res) => {
  const id = String(req.query.id || '');
  if (/AND\s+1=2|AND\s+'1'='2/i.test(id)) return res.json({ items: [] });
  if (/AND\s+1=1|AND\s+'1'='1/i.test(id)) return res.json({ items: [{ id: 1, name: 'widget', price: 9 }] });
  if (/^\d+$/.test(id)) return res.json({ items: [{ id: Number(id), name: 'widget', price: 9 }] });
  res.json({ items: [] });
});
// Non-injectable: ignores the parameter entirely (must NOT be "confirmed").
app.get('/safe-items', (req, res) => res.json({ items: [{ id: 1, name: 'fixed-result' }] }));

app.get('/search', (req, res) => {
  let q = req.query.q;
  if (Array.isArray(q)) return res.status(500).send('TypeError: q.match is not a function'); // type confusion
  q = q == null ? '' : String(q);
  if (q.length > 5000) return res.status(500).send('Request entity too large');               // oversized
  if (q.includes("'")) return res.status(200).send(`You have an error in your SQL syntax; check near '${q}'`); // SQLi
  if (q.includes('etc/passwd')) return res.send('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:');             // traversal
  if (/[;|]\s*id/.test(q)) return res.send('uid=33(www-data) gid=33(www-data) groups=33(www-data)');           // cmd injection
  // SSTI: a real vulnerable template engine evaluates the injected arithmetic,
  // so compute whatever N*M was injected (e.g. ${1234*1234} -> 1522756).
  { const mm = q.match(/(\d+)\s*\*\s*(\d+)/); if (mm) return res.send(`Result: ${Number(mm[1]) * Number(mm[2])}`); }
  res.set('content-type', 'text/html').send(`<html><body>You searched for: ${q}</body></html>`);                // reflected XSS (unencoded)
});

// IDOR: any integer order ID is directly addressable; >1000 is "not found".
app.get('/api/orders/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1 || id > 1000) return res.status(404).json({ error: 'not found' });
  res.json({ id, owner: `user_${id}`, total: id * 10, items: [`item-${id}-a`, `item-${id}-b`], note: `Order number ${id} details for the owner.` });
});

// Endpoint that ignores auth entirely (broken access control).
app.get('/api/public', (req, res) => res.json({ data: 'this is always served', service: 'demo', fixed: true }));

// 403 normally, but bypassable with a spoofed X-Forwarded-For header.
app.get('/protected', (req, res) => {
  if (req.get('x-forwarded-for') === '127.0.0.1') return res.json({ secret: 'you bypassed the gate' });
  res.status(403).json({ error: 'forbidden' });
});

// A page with deliberate quality issues (no label, zoom disabled, no meta desc).
app.get('/page', (req, res) => res.type('html').send(
  '<!doctype html><html lang="en"><head>' +
  '<meta name="viewport" content="width=device-width, user-scalable=no">' +
  '<title>Hi</title></head><body>' +
  '<form><input type="text" name="q"></form><a href="/x"></a><h1>T</h1></body></html>'));

// A minimal OpenAPI spec describing two GET endpoints.
app.get('/openapi.json', (req, res) => res.json({
  openapi: '3.0.0', info: { title: 'demo', version: '1' },
  paths: { '/api/public': { get: {} }, '/api/orders/{id}': { get: {} } }
}));

// Auth-protected endpoint: only returns the secret with the right bearer token.
app.get('/secret', (req, res) => {
  if (req.get('authorization') === 'Bearer good-token') return res.json({ secret: 'flag{authenticated}' });
  res.status(401).json({ error: 'unauthorized' });
});

// VAPT surface: reflects an attacker Host header + arbitrary Origin (with
// credentials), sets an insecure session cookie, and leaks a JWT with alg:none.
app.get('/vapt', (req, res) => {
  const origin = req.get('origin');
  if (origin) { res.set('Access-Control-Allow-Origin', origin); res.set('Access-Control-Allow-Credentials', 'true'); }
  res.set('Set-Cookie', 'sessionid=abc123; SameSite=None; Path=/');
  const xfh = req.get('x-forwarded-host') || 'default';
  const jwt = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.';
  res.type('html').send(`<html><body>Welcome. host=${xfh} token=${jwt}</body></html>`);
});
app.get('/admin', (req, res) => res.type('html').send('<h1>Admin panel</h1><p>internal</p>'));
app.get('/.aws/credentials', (req, res) => res.type('text').send('aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY'));

const server = app.listen(0);
await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${server.address().port}`;

try {
  // --- 1) API parameter fuzzing finds the injected bugs --------------------
  console.log('\n[1] API parameter fuzzing against vulnerable /search?q=:');
  const fuzz = await scanApiFuzz(`${base}/search?q=hello`);
  const titles = fuzz.findings.map((f) => f.title).join(' | ');
  console.log('    findings:', fuzz.findings.map((f) => `${f.severity}:${f.title}`).join(', '));
  assert(/SQL injection/i.test(titles), 'detects SQL injection');
  assert(/Reflected XSS/i.test(titles), 'detects reflected XSS (unencoded HTML)');
  assert(/Path traversal/i.test(titles), 'detects path traversal');
  assert(/Command injection/i.test(titles), 'detects command injection');
  assert(/template injection/i.test(titles), 'detects server-side template injection');
  assert(/error|500|Type confusion/i.test(titles), 'detects unhandled error / type confusion');

  // --- 2) Clean endpoint produces no false positives -----------------------
  console.log('\n[2] Fuzzing a SAFE endpoint (no reflection, no errors):');
  const safeApp = express();
  safeApp.get('/ok', (req, res) => res.json({ ok: true })); // ignores input entirely
  const safeServer = safeApp.listen(0);
  await new Promise((r) => safeServer.once('listening', r));
  const safeBase = `http://127.0.0.1:${safeServer.address().port}`;
  const safe = await scanApiFuzz(`${safeBase}/ok?q=1`);
  const realIssues = safe.findings.filter((f) => f.severity !== 'info');
  console.log('    non-info findings:', realIssues.length);
  assert(realIssues.length === 0, 'no false positives on a safe endpoint');
  safeServer.close();

  // --- 2b) JSON body fuzzing (opt-in write method) finds body-field bugs ---
  console.log('\n[2b] Body fuzzing a vulnerable POST /login (allowWrite=true):');
  const bodyFuzz = await scanApiFuzz(`${base}/login`, {
    method: 'POST', body: JSON.stringify({ username: 'admin', password: 'x' }), allowWrite: true
  });
  const bTitles = bodyFuzz.findings.map((f) => f.title).join(' | ');
  console.log('    findings:', bodyFuzz.findings.map((f) => `${f.severity}:${f.title}`).join(', '));
  assert(/SQL injection \(body field "username"\)/i.test(bTitles), 'detects SQLi in a JSON body field');

  // --- 2c) Write fuzzing is REFUSED without explicit opt-in ----------------
  console.log('\n[2c] Write fuzzing without opt-in is refused (no requests sent):');
  const refused = await scanApiFuzz(`${base}/login`, { method: 'POST', body: JSON.stringify({ username: 'a' }), allowWrite: false });
  assert(refused.findings.some((f) => /POST fuzzing is disabled/i.test(f.title)), 'POST fuzzing refused unless allowWrite is set');

  // --- 2d) Nested / array body field fuzzing -------------------------------
  console.log('\n[2d] Nested body field fuzzing (user.name in a POST body):');
  const nested = await scanApiFuzz(`${base}/profile`, {
    method: 'POST', body: JSON.stringify({ user: { name: 'bob' }, tags: ['x', 'y'] }), allowWrite: true
  });
  assert(nested.findings.some((f) => /SQL injection \(body field "user\.name"\)/i.test(f.title)), 'detects SQLi in a NESTED body field (user.name)');
  assert((nested.meta.bodyFieldsFuzzed || []).includes('tags.0'), 'discovers array element paths (tags.0)');

  // --- 2e) Custom payloads -------------------------------------------------
  console.log('\n[2e] Custom payload list:');
  const custom = await scanApiFuzz(`${base}/search?q=hi`, { customPayloads: ["CUSTOMPAY'LOAD"] });
  assert(custom.meta.customPayloadCount === 1, 'custom payload registered');
  assert(custom.findings.some((f) => /custom payload/i.test(f.title)), 'custom payload triggers a finding');

  // --- 2e2) Non-destructive SQLi CONFIRMATION (boolean-based) --------------
  console.log('\n[2e2] Boolean-based SQLi confirmation (non-destructive PoC):');
  const confirmed = await scanApiFuzz(`${base}/items?id=1`);
  assert(confirmed.findings.some((f) => /Confirmed SQL injection — boolean-based/.test(f.title)), 'confirms boolean-based SQLi without extracting data');
  const cf = confirmed.findings.find((f) => /Confirmed SQL injection/.test(f.title));
  assert(cf && /^curl /.test(cf.reproduction || ''), 'confirmed finding carries a curl reproduction');
  assert(cf && /sqlmap/.test(cf.handoff || ''), 'confirmed finding carries a sqlmap hand-off command');
  const noFp = await scanApiFuzz(`${base}/safe-items?id=1`);
  assert(!noFp.findings.some((f) => /Confirmed SQL injection/.test(f.title)), 'no false confirmation on a non-injectable endpoint');

  // --- 2f) Access control: IDOR heuristic ----------------------------------
  console.log('\n[2f] IDOR detection on /api/orders/5:');
  const idor = await scanAccess(`${base}/api/orders/5`);
  assert(idor.findings.some((f) => /IDOR/i.test(f.title)), 'detects sequential-ID IDOR');

  // --- 2g) Access control: broken auth enforcement -------------------------
  console.log('\n[2g] Broken access control (endpoint ignores auth):');
  const broken = await runWithAuth({ Authorization: 'Bearer any' }, () => scanAccess(`${base}/api/public`));
  assert(broken.findings.some((f) => /without authentication/i.test(f.title)), 'flags endpoint that serves identical data with/without auth');

  // --- 2h) Access control: properly enforced endpoint = no false positive --
  console.log('\n[2h] Properly enforced endpoint is NOT flagged:');
  const enforced = await runWithAuth({ Authorization: 'Bearer good-token' }, () => scanAccess(`${base}/secret`));
  assert(enforced.meta.authEnforced === true, 'recognises enforced auth (401 anonymous)');
  assert(!enforced.findings.some((f) => /without authentication/i.test(f.title)), 'no false positive on enforced endpoint');

  // --- 2i) Auth bypass on a 403 endpoint -----------------------------------
  console.log('\n[2i] 401/403 bypass detection:');
  const bypass = await scanAccess(`${base}/protected`);
  assert(bypass.findings.some((f) => /bypass/i.test(f.title)), 'detects header-based authorization bypass');

  // --- 2j) Rate-limit detection --------------------------------------------
  console.log('\n[2j] Missing rate limiting:');
  const rl = await scanAccess(`${base}/api/public`, { rateLimit: true });
  assert(rl.findings.some((f) => /No rate limiting/i.test(f.title)), 'flags absence of rate limiting');

  // --- 2k) OpenAPI-driven endpoint enumeration -----------------------------
  console.log('\n[2k] OpenAPI endpoint enumeration:');
  const spec = await scanApiSpec(`${base}`);
  assert(spec.findings.some((f) => /OpenAPI spec discovered/i.test(f.title)), 'discovers & parses the OpenAPI spec');
  assert(spec.meta.getEndpoints === 2, 'enumerates the documented GET endpoints');
  assert(spec.findings.some((f) => /without authentication/i.test(f.title)), 'flags documented endpoints reachable without auth');

  // --- 2l) Quality audits: performance / accessibility / SEO ---------------
  console.log('\n[2l] Quality audits (perf / a11y / SEO):');
  const aud = await scanAudits(`${base}/page`);
  assert(aud.a11y.some((f) => /without an accessible label/i.test(f.title)), 'a11y: detects unlabeled form field');
  assert(aud.a11y.some((f) => /Pinch-zoom disabled/i.test(f.title)), 'a11y: detects disabled zoom');
  assert(aud.seo.some((f) => /Missing meta description/i.test(f.title)), 'seo: detects missing meta description');
  assert(aud.perf.some((f) => /not compressed/i.test(f.title)), 'perf: detects missing compression');

  // --- 3) Authenticated scanning actually sends credentials ----------------
  console.log('\n[3] Authenticated scanning sends auth headers end-to-end:');
  const anon = await fetchWithTimeout(`${base}/secret`, { timeout: 5000 });
  assert(anon.status === 401, 'anonymous request to /secret is 401');
  await runWithAuth({ Authorization: 'Bearer good-token' }, async () => {
    const r = await fetchWithTimeout(`${base}/secret`, { timeout: 5000 });
    const body = await r.json();
    assert(r.status === 200 && body.secret === 'flag{authenticated}', 'authenticated request to /secret returns the secret');
  });
  // --- 4) Native code audits (quality / frontend / config / testing / hygiene)
  console.log('\n[4] Code-audit static checks:');
  const enc = (s) => Buffer.from(s);
  const codeEntries = [
    { path: 'package.json', buffer: enc(JSON.stringify({ name: 'demo', dependencies: { express: '^4', lodash: '*' } })) },
    { path: 'src/app.js', buffer: enc("import express from 'express';\nimport made from 'totally-made-up-pkg';\nconsole.log(1);console.log(2);console.log(3);console.log(4);console.log(5);\nconst u='http://localhost:3000';\nconst s=process.env.NEXT_PUBLIC_API_SECRET;\nfetch('/x').then(r=>r.json());\nasync function f(a){return a.map(async x=>await g(x));}\n// TODO: finish\nexpress();made();\n") },
    { path: 'src/App.jsx', buffer: enc('export default function App(){return (<div><img src="/x.png"><a target="_blank" href="/y">y</a></div>);}') },
    { path: 'src/app.test.js', buffer: enc("test('nothing', () => {});") },
    { path: 'src/auth.js', buffer: enc("import crypto from 'crypto';\nconst h = crypto.createHash('md5').update(password).digest('hex');\nif (password === req.body.pass) login();\nlocalStorage.setItem('jwt', token);\njwt.sign(payload, 'hardcoded-secret-value', { algorithm: 'none' });\nconst apiToken = crypto.randomBytes(8).toString('hex');\nif (req.headers['x-api-key'] === apiKey) ok();\napp.post('/login', (req,res)=>{ res.end(); });\n") },
    { path: '.env', buffer: enc('SECRET=abc123') }
  ];
  const ca = scanCodeAudit(codeEntries);
  assert(ca.quality.some((f) => /hallucinated|undeclared/i.test(f.title)), 'quality: detects undeclared/AI-hallucinated import');
  assert(ca.quality.some((f) => /await inside \.map/i.test(f.title)), 'quality: detects await inside .map()');
  assert(ca.quality.some((f) => /without a \.catch/i.test(f.title)), 'quality: detects .then() without .catch()');
  assert(ca.seccode.some((f) => /client-exposed secret/i.test(f.title)), 'seccode: detects client-exposed secret env var');
  assert(ca.deps.some((f) => /loosely-pinned/i.test(f.title)), 'deps: detects loose version pinning');
  assert(ca.frontend.some((f) => /<img> without alt/i.test(f.title)), 'frontend: detects img without alt');
  assert(ca.frontend.some((f) => /No React Error Boundary/i.test(f.title)), 'frontend: detects missing React error boundary');
  assert(ca.frontend.some((f) => /noopener/i.test(f.title)), 'frontend: detects target=_blank without noopener');
  assert(ca.config.some((f) => /localhost/i.test(f.title)), 'config: detects hardcoded localhost');
  assert(ca.testing.some((f) => /empty test/i.test(f.title)), 'testing: detects empty test body');
  assert(ca.hygiene.some((f) => /\.env file/i.test(f.title)), 'hygiene: detects committed .env');
  // Auth-security checks (JWT cookie auth / bcrypt / brute-force)
  assert(ca.seccode.some((f) => /weak algorithm \(md5\/sha1\)/i.test(f.title)), 'seccode: detects weak password hashing (use bcrypt)');
  assert(ca.seccode.some((f) => /localStorage\/sessionStorage/i.test(f.title)), 'seccode: detects JWT in localStorage (use httpOnly cookie)');
  assert(ca.seccode.some((f) => /"none" algorithm/i.test(f.title)), 'seccode: detects JWT none algorithm');
  assert(ca.seccode.some((f) => /hardcoded JWT/i.test(f.title)), 'seccode: detects hardcoded JWT secret');
  assert(ca.seccode.some((f) => /brute-force protection/i.test(f.title)), 'seccode: detects login without brute-force protection');
  assert(ca.seccode.some((f) => /weak \/ low-entropy/i.test(f.title)), 'seccode: detects weak/short token generation (randomBytes(8))');
  assert(ca.seccode.some((f) => /plaintext API\/access-key/i.test(f.title)), 'seccode: detects plaintext access-key comparison');
  // Auth-security positives + custom-lockout false-positive fix
  const goodAuth = scanCodeAudit([{ path: 'auth.js', buffer: enc(
    "import bcrypt from 'bcryptjs';\n" +
    "const hash = await bcrypt.hash(password, 12);\n" +
    "res.cookie('sid', token, { httpOnly: true, secure: true, sameSite: 'strict' });\n" +
    "const sessionToken = crypto.randomBytes(32).toString('base64url');\n" +
    "app.post('/login', (req,res)=>{ if (checkLock(keys)) return res.status(429).end(); recordFailure(keys); });\n"
  ) }]).seccode;
  assert(goodAuth.some((f) => /Strong password hashing/i.test(f.title)), 'seccode+: affirms bcrypt password hashing');
  assert(goodAuth.some((f) => /Hardened session cookie/i.test(f.title)), 'seccode+: affirms hardened (httpOnly+secure+sameSite) cookie');
  assert(goodAuth.some((f) => /secure token generation/i.test(f.title)), 'seccode+: affirms cryptographically-secure token generation');
  assert(goodAuth.some((f) => /Brute-force lockout detected/i.test(f.title)), 'seccode+: affirms custom brute-force lockout');
  assert(!goodAuth.some((f) => /Login endpoint without brute-force/i.test(f.title)), 'seccode+: no false positive on custom (non-library) lockout');
  // --- 5) Input validation (schema, types, limits, unknown fields) ---------
  console.log('\n[5] Request validation:');
  assert(validateBody(websiteSchema, { url: 'x', evil: 1 }).ok === false, 'rejects unexpected fields');
  assert(validateBody(websiteSchema, {}).ok === false, 'rejects missing required url');
  assert(validateBody(websiteSchema, { url: 'x', render: 'yes' }).ok === false, 'rejects wrong type (render)');
  assert(validateBody(websiteSchema, { url: 'a'.repeat(3000) }).ok === false, 'rejects oversized url');
  const okv = validateBody(websiteSchema, { url: 'https://example.com' });
  assert(okv.ok && okv.value.render === true && okv.value.audits === true, 'accepts valid input + applies defaults');
  assert(validateBody(apiSchema, { url: 'x', method: 'TRACE' }).ok === false, 'rejects method not in enum');
  assert(validateBody(apiSchema, { url: 'x', method: 'post' }).value.method === 'POST', 'normalizes method to uppercase');
  assert(validateBody(apiSchema, { url: 'x', customPayloads: Array(99).fill('p') }).ok === false, 'rejects too many custom payloads');

  // --- 6) Rate limiting (429 after max, Retry-After) -----------------------
  console.log('\n[6] Rate limiting:');
  const fakeReq = () => ({ ip: '203.0.113.7', socket: { remoteAddress: '203.0.113.7' }, headers: {} });
  const fakeRes = () => ({ code: 200, headers: {}, body: null, set(k, v) { this.headers[k] = v; return this; }, status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; } });
  const limiter = rateLimit({ windowMs: 10000, max: 2, name: 'test' });
  let passed = 0; const next = () => { passed++; };
  limiter(fakeReq(), fakeRes(), next);
  limiter(fakeReq(), fakeRes(), next);
  const blocked = fakeRes();
  limiter(fakeReq(), blocked, next);
  assert(passed === 2, 'allows requests up to the limit');
  assert(blocked.code === 429 && blocked.body && blocked.body.ok === false, 'returns 429 once over the limit');
  assert(blocked.headers['Retry-After'], 'sets a Retry-After header on 429');
  // --- 7) Authentication: bcrypt + JWT + brute-force ----------------------
  console.log('\n[7] Authentication:');
  const h = await hashPassword('S3curePass!');
  assert(h.startsWith('$2') && h !== 'S3curePass!', 'bcrypt stores a salted hash, not plaintext');
  assert(await verifyPassword('S3curePass!', h) === true, 'correct password verifies');
  assert(await verifyPassword('wrong-password', h) === false, 'wrong password rejected');
  assert(await verifyPassword('whatever', null) === false, 'absent user compares safely (no throw)');
  const tok = issueToken('user@example.com');
  assert(verifyToken(tok) && verifyToken(tok).sub === 'user@example.com', 'valid JWT verifies to its subject');
  assert(verifyToken(tok + 'tampered') === null, 'tampered JWT is rejected');
  assert(verifyToken('not-a-token') === null, 'garbage token rejected');
  const keys = ['email:bf@test', 'ip:198.51.100.9'];
  for (let i = 0; i < 5; i++) bf.recordFailure(keys);
  assert(bf.checkLock(keys) > 0, 'account locks out after repeated failures');
  bf.recordSuccess(keys);
  assert(bf.checkLock(keys) === 0, 'successful login clears the lockout');
  assert(validateBody(credentialsSchema, { email: 'a@b.com' }).ok === false, 'login requires a password');
  assert(validateBody(credentialsSchema, { email: 'a@b.com', password: 'short' }).ok === false, 'rejects passwords under 8 chars');
  // --- 8) GitHub repo scanner (SSRF-safe parsing + safe extraction) -------
  console.log('\n[8] GitHub repo scanner:');
  assert(parseRepoUrl('https://github.com/owner/repo').repo === 'repo', 'parses owner/repo');
  assert(parseRepoUrl('https://github.com/owner/repo.git').repo === 'repo', 'strips .git suffix');
  assert(parseRepoUrl('https://github.com/owner/repo/tree/main').ref === 'main', 'parses branch ref');
  assert(parseRepoUrl('http://evil.com/owner/repo') === null, 'rejects non-github host (SSRF protection)');
  assert(parseRepoUrl('https://gitlab.com/a/b') === null, 'rejects non-github host (gitlab)');
  assert(parseRepoUrl('https://github.com/../../etc') === null, 'rejects path traversal in URL');
  const z = new AdmZip();
  z.addFile('myrepo-abc123/app.js', Buffer.from('const k = "AKIAIOSFODNN7EXAMPLE";'));
  z.addFile('myrepo-abc123/node_modules/dep.js', Buffer.from('ignored();'));
  const ents = safeExtract(z.toBuffer());
  assert(ents.some((e) => e.path === 'app.js'), 'safeExtract strips the archive top folder');
  assert(!ents.some((e) => e.path.includes('node_modules')), 'safeExtract skips node_modules');

  // --- 9) Plan persistence in the user store (billing itself is covered in [14]) --
  console.log('\n[9] Plan store:');
  putUser('plan@test.com', 'x');
  setUserPlan('plan@test.com', 'pro', new Date(Date.now() + 86400000).toISOString());
  assert(getUser('plan@test.com').plan === 'pro', 'setUserPlan persists the plan to the user store');
  assert(!!getUser('plan@test.com').planExpiresAt, 'setUserPlan records the expiry timestamp');
  setUserPlan('plan@test.com', 'free', null);
  assert(getUser('plan@test.com').plan === 'free' && !('planExpiresAt' in getUser('plan@test.com')), 'dropping to free clears the expiry');

  // --- 10) Launch features: store, single-use tokens, email/OAuth guards ---
  console.log('\n[10] Launch features (store / tokens / email / OAuth):');
  // Store helpers
  putUser('store@test.com', 'h0');
  assert(getUser('store@test.com').emailVerified === false, 'putUser defaults emailVerified=false');
  updateUser('store@test.com', { plan: 'pro', emailVerified: true });
  assert(getUser('store@test.com').emailVerified === true, 'updateUser merges fields');
  assert(getUser('store@test.com').plan === 'pro', 'updateUser merges a second field in the same call');
  updateUser('store@test.com', { verifyNonce: 'abc' });
  updateUser('store@test.com', { verifyNonce: null });
  assert(!('verifyNonce' in getUser('store@test.com')), 'updateUser(null) clears a field');
  assert(updateUser('nobody@test.com', { x: 1 }) === null, 'updateUser returns null for unknown user');

  // Single-use scoped tokens (email verification + password reset)
  putUser('tok@test.com', 'h1');
  const vTok = createToken('tok@test.com', 'verify');
  assert(consumeToken('verify', vTok) === 'tok@test.com', 'verify token consumes to the right email');
  assert(consumeToken('verify', vTok) === null, 'verify token is single-use (second consume fails)');
  const rTok = createToken('tok@test.com', 'reset');
  assert(consumeToken('verify', rTok) === null, 'a reset token cannot be used as a verify token (purpose-scoped)');
  assert(consumeToken('reset', rTok + 'x') === null, 'tampered reset token is rejected');
  assert(consumeToken('reset', rTok) === 'tok@test.com', 'valid reset token consumes correctly');

  // Validation schemas for the new endpoints
  assert(validateBody(forgotSchema, {}).ok === false, 'forgot requires an email');
  assert(validateBody(forgotSchema, { email: 'a@b.com' }).ok === true, 'forgot accepts an email');
  assert(validateBody(resetSchema, { token: 't' }).ok === false, 'reset requires a password');
  assert(validateBody(resetSchema, { token: 't', password: 'short' }).ok === false, 'reset rejects passwords under 8 chars');
  assert(validateBody(resetSchema, { token: 't', password: 'longenough' }).ok === true, 'reset accepts token + valid password');

  // --- 11) VAPT active pen-test scanner ------------------------------------
  console.log('\n[11] VAPT scanner against the deliberately-weak /vapt surface:');
  const vapt = await scanVapt(`${base}/vapt`, { effort: 'regular' });
  const vt = vapt.findings.map((f) => f.title).join(' | ');
  assert(vapt.type === 'vapt', 'vapt scanner returns type "vapt"');
  assert(/Host header injection/i.test(vt), 'vapt detects reflected forwarding-header (host header injection)');
  assert(/CORS reflects arbitrary Origin with credentials/i.test(vt), 'vapt detects CORS credential exposure');
  assert(/JWT accepts "alg: none"/i.test(vt), 'vapt detects a JWT with alg:none');
  assert(/SameSite=None without Secure/i.test(vt), 'vapt detects an insecure session cookie');
  assert(/Exposed sensitive resource|Reachable sensitive path/i.test(vt), 'vapt enumerates an exposed sensitive path');
  const jwtFinding = vapt.findings.find((f) => /JWT/i.test(f.title));
  assert(jwtFinding && !/eyJzdWIiOiIxIn0/.test(JSON.stringify(jwtFinding)), 'vapt masks the raw JWT value in evidence');

  // --- 12) Secret masking --------------------------------------------------
  console.log('\n[12] Analytics secret masking:');
  assert(maskSecrets('t eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcdef123456 x').includes('[REDACTED JWT]'), 'mask redacts JWTs');
  assert(maskSecrets('use AKIAIOSFODNN7EXAMPLE now').includes('[REDACTED AWS key id]'), 'mask redacts AWS key ids');
  assert(maskSecrets('password=SuperSecret123!').includes('[REDACTED]'), 'mask redacts password= values');
  assert(maskSecrets('A normal remediation sentence about headers.') === 'A normal remediation sentence about headers.', 'mask leaves ordinary prose intact');
  const mf = maskFinding({ severity: 'high', category: 'vapt', title: 'x', evidence: 'AKIAIOSFODNN7EXAMPLE' });
  assert(mf.evidence.includes('[REDACTED') && mf.severity === 'high' && mf.category === 'vapt', 'maskFinding masks evidence but keeps structural fields');

  // --- 13) Analytics aggregation (VART) ------------------------------------
  console.log('\n[13] Analytics aggregation across saved scans:');
  const anEmail = `vart-test-${Date.now()}@example.test`;
  assert(buildAnalytics(anEmail).empty === true, 'analytics reports empty for a user with no scans');
  const findingsA = [
    { severity: 'high', category: 'vuln', title: 'Reflected XSS', owasp: 'A03:2021 Injection', confidence: 'high', evidence: 'AKIAIOSFODNN7EXAMPLE', location: '/x', impact: 'i', remediation: 'encode output' },
    { severity: 'medium', category: 'security', title: 'Missing HSTS', owasp: 'A05:2021 Security Misconfiguration', confidence: 'medium', location: '/', remediation: 'add HSTS' }
  ];
  const repBase = { ok: true, type: 'website', total: 2, meta: { target: 'https://a.example.test' }, categories: [], findings: findingsA };
  const sc1 = saveScan(anEmail, 'Default', { ...repBase, score: 70, grade: 'C', counts: { critical: 0, high: 1, medium: 1, low: 0, info: 0 } });
  const sc2 = saveScan(anEmail, 'Default', { ...repBase, score: 85, grade: 'B', counts: { critical: 0, high: 1, medium: 1, low: 0, info: 0 } });
  try {
    const an = buildAnalytics(anEmail);
    assert(an.ok && !an.empty, 'analytics builds for a user with saved scans');
    assert(an.totals.scans === 2, 'analytics counts every saved scan');
    assert(an.totals.open >= 1 && an.posture && typeof an.posture.score === 'number', 'analytics computes open findings + a posture score');
    assert(an.owaspBreakdown.some((o) => o.code === 'A03'), 'analytics builds an OWASP Top-10 breakdown');
    assert(an.trend.length === 2, 'analytics builds a score trend across scans');
    assert(an.topFindings.length >= 1 && an.topFindings.every((f) => !/AKIAIOSFODNN7EXAMPLE/.test(JSON.stringify(f))), 'analytics masks secrets in the ranked top-findings list');
  } finally {
    deleteScan(sc1.id); deleteScan(sc2.id);
  }
  assert(buildAnalytics(anEmail).empty === true, 'analytics cleanup left no residual test scans');

  // Optional-integration guards (off by default in tests)
  assert(isEmailConfigured() === false, 'email reports not-configured without RESEND_API_KEY');
  assert((await sendMail({ to: 'x@y.com', subject: 's', text: 't' })).dev === true, 'sendMail no-ops to dev console when unconfigured');
  assert(isGoogleConfigured() === false, 'Google OAuth reports not-configured without client id/secret');

  console.log('\n[14] Razorpay billing + plan capabilities:');
  // Configure a dummy key pair, then dynamically import so the module reads them.
  process.env.RAZORPAY_KEY_ID = 'rzp_test_dummy';
  process.env.RAZORPAY_KEY_SECRET = 'test_secret_key';
  const rzp = await import('../src/billing/razorpay.js');
  assert(rzp.isConfigured() === true, 'razorpay reports configured when key id + secret are set');
  assert(rzp.PLANS.starter.amount === 59900 && rzp.PLANS.pro.amount === 89900 && rzp.PLANS.business.amount === 199900, 'plan amounts are 599/899/1999 (paise)');
  assert(rzp.isValidPlan('pro') && !rzp.isValidPlan('team'), 'plan validation matches the catalog');
  assert(rzp.catalog().length === 3, 'public catalog lists the three paid plans');
  assert(rzp.planHasCap('free', 'website') && rzp.planHasCap('free', 'api') && !rzp.planHasCap('free', 'code'), 'free: website+api yes, code upload no');
  assert(rzp.planHasCap('starter', 'code') && rzp.planHasCap('starter', 'authscan') && !rzp.planHasCap('starter', 'vapt'), 'starter unlocks code+authscan, not vapt');
  assert(rzp.planHasCap('pro', 'vapt') && rzp.planHasCap('pro', 'github') && rzp.planHasCap('pro', 'fuzz') && rzp.planHasCap('pro', 'analytics') && rzp.planHasCap('pro', 'export_integrations'), 'pro unlocks vapt/github/fuzz/analytics/export');
  assert(!rzp.planHasCap('pro', 'schedule') && rzp.planHasCap('business', 'schedule'), 'scheduling is business-only');
  assert(rzp.planRank('business') > rzp.planRank('pro') && rzp.planRank('pro') > rzp.planRank('starter') && rzp.planRank('starter') > rzp.planRank('free'), 'plan ranks are strictly ordered');
  assert(rzp.effectivePlan({ plan: 'pro', planExpiresAt: new Date(Date.now() + 86400000).toISOString() }) === 'pro', 'an active paid plan stays paid');
  assert(rzp.effectivePlan({ plan: 'pro', planExpiresAt: new Date(Date.now() - 86400000).toISOString() }) === 'free', 'a lapsed paid plan downgrades to free');
  assert(rzp.effectivePlan({ plan: 'free' }) === 'free', 'free stays free');
  const oid = 'order_ABC', pid = 'pay_XYZ';
  const goodSig = crypto.createHmac('sha256', 'test_secret_key').update(`${oid}|${pid}`).digest('hex');
  assert(rzp.verifyPaymentSignature(oid, pid, goodSig) === true, 'a valid payment signature verifies');
  assert(rzp.verifyPaymentSignature(oid, pid, 'deadbeef') === false, 'a forged payment signature is rejected');
  assert(rzp.verifyPaymentSignature('order_other', pid, goodSig) === false, 'signature is bound to the exact order+payment');
  assert(rzp.planGrantFromEvent({ event: 'payment.captured', payload: { payment: { entity: { notes: { email: 'a@b.com', plan: 'pro' } } } } })?.plan === 'pro', 'webhook payment.captured maps to a plan grant');
  assert(rzp.planGrantFromEvent({ event: 'payment.failed', payload: {} }) === null, 'non-capture events grant nothing');
  // Anti-tamper: the granted plan comes from the order (amount-bound), never the client.
  assert(rzp.planFromOrder({ notes: { plan: 'pro', email: 'a@b.com' }, amount: 89900 }).plan === 'pro', 'planFromOrder reads the plan the order was created for');
  let mismatchErr = false; try { rzp.planFromOrder({ notes: { plan: 'business' }, amount: 89900 }); } catch { mismatchErr = true; }
  assert(mismatchErr, 'planFromOrder rejects an amount that does not match the claimed plan (blocks tier bypass)');
  let unknownErr = false; try { rzp.planFromOrder({ notes: { plan: 'gold' }, amount: 100 }); } catch { unknownErr = true; }
  assert(unknownErr, 'planFromOrder rejects an unknown plan');
} finally {
  server.close();
}

console.log(`\n${failed === 0 ? '✅ ALL PASSED' : '❌ FAILURES'}: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
