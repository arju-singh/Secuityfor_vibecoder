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
import { validateBody, websiteSchema, apiSchema, credentialsSchema } from '../src/middleware/validate.js';
import { rateLimit } from '../src/middleware/rateLimit.js';
import { hashPassword, verifyPassword, issueToken, verifyToken } from '../src/auth/auth.js';
import * as bf from '../src/auth/bruteforce.js';
import { runWithAuth, fetchWithTimeout } from '../src/scanners/util.js';

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
  if (q.includes('7*7')) return res.send('Result: 49');                                                         // SSTI
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
    { path: 'src/auth.js', buffer: enc("import crypto from 'crypto';\nconst h = crypto.createHash('md5').update(password).digest('hex');\nif (password === req.body.pass) login();\nlocalStorage.setItem('jwt', token);\njwt.sign(payload, 'hardcoded-secret-value', { algorithm: 'none' });\napp.post('/login', (req,res)=>{ res.end(); });\n") },
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
} finally {
  server.close();
}

console.log(`\n${failed === 0 ? '✅ ALL PASSED' : '❌ FAILURES'}: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
