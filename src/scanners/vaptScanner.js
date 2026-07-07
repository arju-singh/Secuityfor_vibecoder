// VAPT — active penetration-test engine. Goes a step past the passive security
// suites (urlScanner/vulnScanner) and the access suite: it actively manipulates
// requests (spoofed forwarding headers, arbitrary Origins, verb tampering) and
// enumerates a curated attack surface, then reports what the target actually
// did. Everything here is READ-ONLY / GET-safe by default — the only state-
// changing behaviour (the login brute-force resistance probe) is gated behind
// opts.allowWrite, mirroring accessScanner/apiFuzzScanner.
//
// SCOPE HONESTY: like the other black-box suites these are signals a human should
// confirm under their own authorization. Secrets that surface (JWTs, cookies) are
// masked in evidence so exported reports never leak a live token.
import { URL } from 'node:url';
import { finding, fetchWithTimeout, normalizeUrl, currentAuthHeaders } from './util.js';
import { curl } from './repro.js';

const A01 = 'A01:2021 Broken Access Control';
const A02 = 'A02:2021 Cryptographic Failures';
const A05 = 'A05:2021 Security Misconfiguration';
const A07 = 'A07:2021 Identification and Authentication Failures';

// A unique, harmless marker we inject and then look for reflected back.
const CANARY = 'sentryscan-vapt-canary.example';

// Mask a token/secret so evidence shows enough to identify it but never the whole
// value. Keeps the first 10 and last 4 characters for long strings.
function maskToken(s) {
  const str = String(s || '');
  if (str.length <= 16) return str.length > 6 ? str.slice(0, 3) + '…' : '…';
  return str.slice(0, 10) + '…' + str.slice(-4) + ` (${str.length} chars, masked)`;
}

// Bounded-concurrency map so enumeration can't open hundreds of sockets at once
// or blow the 30s section budget. Preserves input order in the result array.
async function pool(items, worker, concurrency = 6) {
  const out = new Array(items.length);
  let i = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      try { out[idx] = await worker(items[idx], idx); }
      catch { out[idx] = null; }
    }
  });
  await Promise.all(runners);
  return out;
}

async function fetchSafe(url, o = {}) {
  const res = await fetchWithTimeout(url, { timeout: 7000, redirect: 'manual', ...o });
  const body = (await res.text().catch(() => '')).slice(0, 120000);
  const headers = {};
  res.headers.forEach((v, k) => { headers[k] = v; });
  return { status: res.status, headers, body, location: res.headers.get('location') || '' };
}

// --- 1. Host-header / forwarding-header injection --------------------------
// Many apps build absolute URLs (password-reset links, redirects, cached pages)
// from the Host / X-Forwarded-Host header. If our canary comes back reflected,
// an attacker can poison those links or the cache.
async function probeHostHeader(u) {
  const findings = [];
  const variants = [
    { 'X-Forwarded-Host': CANARY },
    { 'X-Forwarded-Host': CANARY, 'X-Forwarded-Scheme': 'https' },
    { 'Forwarded': `host=${CANARY}` },
    { 'X-Host': CANARY }
  ];
  for (const h of variants) {
    let r;
    try { r = await fetchSafe(u.href, { headers: h }); } catch { continue; }
    const inLocation = r.location.includes(CANARY);
    const inBody = r.body.includes(CANARY);
    if (inLocation || inBody) {
      const where = inLocation ? `redirect Location: ${r.location.slice(0, 200)}` : 'the response body';
      const f = finding('high', 'Host header injection (reflected forwarding header)',
        `The app reflected an attacker-controlled ${Object.keys(h)[0]} header into ${inLocation ? 'a redirect target' : 'the page'}. This enables password-reset poisoning (reset links point at an attacker host), web-cache poisoning, and open-redirect style attacks.`,
        'Never build absolute URLs or trust routing from client-supplied Host/X-Forwarded-* headers. Pin the canonical host server-side (allow-list) and ignore forwarding headers unless they come from a trusted proxy.',
        `sent ${JSON.stringify(h)} → canary reflected in ${where}`, u.pathname, A05, { confidence: 'high' });
      f.reproduction = curl('GET', u.href, { headers: h });
      findings.push(f);
      break; // one confirmed instance is enough
    }
  }
  return findings;
}

// --- 2. CORS credential exposure -------------------------------------------
// urlScanner flags a wildcard ACAO; this goes deeper: does the server REFLECT an
// arbitrary Origin, and does it pair that with Allow-Credentials:true (which lets
// evil.com read authenticated responses in a victim's browser)?
async function probeCors(u) {
  const findings = [];
  const evil = 'https://' + CANARY;
  const tests = [{ label: 'arbitrary Origin', origin: evil }, { label: 'Origin: null', origin: 'null' }];
  for (const t of tests) {
    let r;
    try { r = await fetchSafe(u.href, { headers: { Origin: t.origin } }); } catch { continue; }
    const acao = r.headers['access-control-allow-origin'];
    const acac = (r.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
    if (!acao) continue;
    const reflects = acao === t.origin || acao === '*';
    if (reflects && acac && acao !== '*') {
      // Reflected arbitrary origin + credentials = account-takeover-grade CORS.
      const f = finding('critical', 'CORS reflects arbitrary Origin with credentials',
        `The server echoed the ${t.label} back in Access-Control-Allow-Origin AND set Access-Control-Allow-Credentials: true. Any site a logged-in user visits can then read this endpoint's authenticated responses (session data, tokens, PII).`,
        'Never reflect the Origin header. Use a strict server-side allow-list of trusted origins; if credentials are required, never combine that with a wildcard or reflected origin.',
        `Origin: ${t.origin} → Access-Control-Allow-Origin: ${acao}; Access-Control-Allow-Credentials: true`, u.pathname, A05, { confidence: 'high' });
      f.reproduction = curl('GET', u.href, { headers: { Origin: t.origin } });
      findings.push(f);
      break;
    }
    if (reflects && acao !== '*') {
      const f = finding('medium', 'CORS reflects an arbitrary Origin',
        `The server echoed the ${t.label} in Access-Control-Allow-Origin without a credentials flag. Cross-origin sites can read this endpoint's (non-credentialed) responses; risk rises sharply if credentials are ever enabled.`,
        'Replace Origin reflection with a fixed server-side allow-list of trusted origins.',
        `Origin: ${t.origin} → Access-Control-Allow-Origin: ${acao}`, u.pathname, A05);
      f.reproduction = curl('GET', u.href, { headers: { Origin: t.origin } });
      findings.push(f);
      break;
    }
  }
  return findings;
}

// --- 3. JWT weaknesses ------------------------------------------------------
function b64urlToJson(seg) {
  try {
    const b = Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return JSON.parse(b);
  } catch { return null; }
}
function collectJwts(base) {
  const found = new Set();
  const re = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}/g;
  const haystacks = [base.body, base.headers['set-cookie'] || ''];
  const auth = currentAuthHeaders() || {};
  for (const v of Object.values(auth)) if (typeof v === 'string') haystacks.push(v);
  for (const h of haystacks) for (const m of String(h).match(re) || []) found.add(m);
  return [...found].slice(0, 5);
}
function probeJwt(u, base) {
  const findings = [];
  for (const jwt of collectJwts(base)) {
    const [h] = jwt.split('.');
    const header = b64urlToJson(h);
    const payload = b64urlToJson(jwt.split('.')[1]);
    if (!header) continue;
    const alg = String(header.alg || '').toLowerCase();
    if (alg === 'none') {
      findings.push(finding('critical', 'JWT accepts "alg: none"',
        'A JSON Web Token in use declares alg:none — an unsigned token. If the server honours it, anyone can forge a token with any claims (any user, any role) and be trusted.',
        'Reject alg:none. Pin the accepted algorithm(s) server-side and always verify the signature against your key.',
        `JWT header alg=none; token ${maskToken(jwt)}`, u.pathname, A02, { confidence: 'high' }));
    } else if (alg === 'hs256') {
      findings.push(finding('low', 'JWT uses HS256 (symmetric) — verify key strength & algorithm pinning',
        'The token is signed with HS256 (a shared secret). If that secret is weak/guessable it can be brute-forced offline, and if the verifier also accepts RS256 an attacker can pull off an algorithm-confusion forgery using the public key as the HMAC secret.',
        'Use a long random secret (≥256-bit), pin the algorithm on verification, and prefer asymmetric (RS256/ES256) for tokens issued to third parties.',
        `JWT header alg=HS256; token ${maskToken(jwt)}`, u.pathname, A02));
    }
    if (payload && payload.exp === undefined) {
      findings.push(finding('medium', 'JWT has no expiry (exp claim)',
        'A JWT in use has no exp claim, so it never expires. A stolen token then grants indefinite access — there is no natural window that limits the damage of a leak.',
        'Always set a short exp on access tokens and implement refresh/rotation. Consider a server-side revocation list for logout.',
        `JWT payload has no exp; token ${maskToken(jwt)}`, u.pathname, A07));
    }
  }
  return findings;
}

// --- 4. Session-cookie hardening (prefix + SameSite specifics) --------------
const SESSIONISH = /(sess|sid|auth|token|jwt|login|remember)/i;
function splitSetCookie(raw) {
  // Set-Cookie can be folded into one header with commas; split on the comma that
  // precedes a "name=" pair (avoids splitting inside Expires=Wed, 01 Jan…).
  return String(raw || '').split(/,(?=\s*[A-Za-z0-9_.-]+=)/).map((c) => c.trim()).filter(Boolean);
}
function probeCookies(u, base) {
  const findings = [];
  const isHttps = u.protocol === 'https:';
  for (const cookie of splitSetCookie(base.headers['set-cookie'])) {
    const name = cookie.split('=')[0].trim();
    const attrs = cookie.toLowerCase();
    if (!SESSIONISH.test(name)) continue;
    const secure = /;\s*secure/.test(attrs);
    const sameSite = (attrs.match(/samesite=(\w+)/) || [])[1];
    if (sameSite === 'none' && !secure) {
      findings.push(finding('high', `Session cookie "${name}" is SameSite=None without Secure`,
        'A SameSite=None cookie is sent on cross-site requests; without the Secure flag it also rides plaintext HTTP and modern browsers reject it outright, breaking sessions or exposing the cookie to network attackers.',
        'Set both SameSite=None AND Secure, or use SameSite=Lax/Strict if cross-site delivery isn’t needed.',
        cookie.slice(0, 160), u.pathname, A05, { confidence: 'high' }));
    }
    if (name.startsWith('__Host-') && (!secure || !/path=\//.test(attrs) || /domain=/.test(attrs))) {
      findings.push(finding('medium', `Cookie "${name}" violates the __Host- prefix rules`,
        'A __Host- prefixed cookie must be Secure, have Path=/, and carry no Domain attribute — browsers reject it otherwise, silently dropping the protection the prefix was meant to give.',
        'Serve __Host- cookies with Secure; Path=/ and no Domain attribute.',
        cookie.slice(0, 160), u.pathname, A05));
    } else if (isHttps && !secure) {
      findings.push(finding('medium', `Session cookie "${name}" is missing the Secure flag`,
        'A session cookie without Secure can be transmitted over plaintext HTTP, where a network attacker can capture it and hijack the session.',
        'Add the Secure attribute to all session/auth cookies (and prefer HttpOnly + SameSite).',
        cookie.slice(0, 160), u.pathname, A05));
    }
  }
  return findings;
}

// --- 5. Attack-surface enumeration -----------------------------------------
// Curated paths beyond urlScanner's 11: admin panels, framework debug consoles,
// CI/CD & IaC files, cloud config, and backup/dump patterns. Scaled by effort.
const CORE_PATHS = [
  '/admin', '/administrator', '/.git/config', '/.env.local', '/.env.production',
  '/actuator/health', '/actuator/env', '/debug', '/graphql', '/swagger-ui.html',
  '/.aws/credentials', '/config.json'
];
const EXTENDED_PATHS = [
  '/wp-admin/', '/phpmyadmin/', '/.gitlab-ci.yml', '/Dockerfile', '/docker-compose.yml',
  '/.dockerenv', '/.npmrc', '/.terraform', '/terraform.tfstate', '/id_rsa',
  '/.ssh/id_rsa', '/backup.sql', '/dump.sql', '/database.sql', '/.env.bak',
  '/api/swagger.json', '/openapi.json', '/actuator/heapdump', '/actuator/mappings',
  '/server-info', '/.well-known/security.txt', '/console', '/__debug__/', '/metrics'
];
// Body signatures that make a 200 clearly sensitive rather than a soft-404 shell.
const SENSITIVE_SIG = [
  { re: /aws_access_key_id|aws_secret_access_key/i, what: 'AWS credentials' },
  { re: /-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----/, what: 'a private key' },
  { re: /"terraform_version"|"lineage"/, what: 'Terraform state (may contain secrets)' },
  { re: /\bDB_PASSWORD=|\bSECRET_KEY=|\bAPI_KEY=/i, what: 'environment secrets' },
  { re: /_links.*actuator|"diskSpace"|"heapdump"/i, what: 'Spring Actuator internals' },
  { re: /<title>phpMyAdmin|Powered by phpMyAdmin/i, what: 'a phpMyAdmin console' }
];
async function probeSurface(u, extended, softLen) {
  const list = extended ? [...CORE_PATHS, ...EXTENDED_PATHS] : CORE_PATHS;
  const results = await pool(list, async (p) => {
    const target = new URL(p, u.origin).href;
    let r;
    try { r = await fetchSafe(target, {}); } catch { return null; }
    if (r.status < 200 || r.status >= 400) return null;
    // Skip generic 200 shells that look like the soft-404 (SPA catch-all).
    if (softLen != null && Math.abs(r.body.length - softLen) < 40 && r.body.length > 0) return null;
    const sig = SENSITIVE_SIG.find((s) => s.re.test(r.body));
    return { path: p, target, status: r.status, len: r.body.length, sig };
  });
  const findings = [];
  for (const hit of results.filter(Boolean)) {
    if (hit.sig) {
      findings.push(finding('high', `Exposed sensitive resource: ${hit.path}`,
        `${hit.target} responded ${hit.status} and its body matched ${hit.sig.what}. This exposes secrets or internal detail that materially eases compromise.`,
        'Remove or authenticate this resource; rotate any credentials it exposed; block sensitive paths at the edge.',
        `HTTP ${hit.status}, ${hit.len} bytes, matched: ${hit.sig.what}`, hit.path, A05, { confidence: 'high' }));
    } else {
      findings.push(finding('low', `Reachable sensitive path: ${hit.path}`,
        `${hit.target} is reachable (HTTP ${hit.status}). Admin panels, debug consoles, and dev/CI files should not be publicly accessible — each is an entry point or an information leak.`,
        'Restrict this path to trusted networks/authenticated admins, or remove it from production.',
        `HTTP ${hit.status}, ${hit.len} bytes`, hit.path, A05));
    }
  }
  return findings;
}

// --- 6. Web-cache-deception probe ------------------------------------------
// If /account is authenticated but /account/nonexistent.css returns the SAME
// authenticated body AND a cache header, a shared cache may store the private
// page under a static-looking URL that anyone can then fetch.
async function probeCacheDeception(u, base) {
  if (base.status !== 200 || base.body.length < 40) return [];
  const tricked = new URL(u.href);
  tricked.pathname = (u.pathname.replace(/\/$/, '') || '') + '/sentryscan.css';
  let r;
  try { r = await fetchSafe(tricked.href, {}); } catch { return []; }
  const cacheHdr = r.headers['cache-control'] || r.headers['cf-cache-status'] || r.headers['x-cache'] || '';
  const cacheable = /public|max-age=[1-9]|hit/i.test(cacheHdr);
  const similar = r.status === 200 && Math.abs(r.body.length - base.body.length) < base.body.length * 0.15;
  if (similar && cacheable) {
    const f = finding('medium', 'Possible web cache deception',
      `Appending a static-looking suffix (.css) to the path returned the same 200 content as the real page, together with a cacheable response (${cacheHdr}). A shared/CDN cache could store this (possibly authenticated) page under a URL an attacker can request.`,
      'Cache by content-type/route allow-list rather than URL suffix; never cache authenticated responses; set Cache-Control: private/no-store on personalised pages.',
      `${tricked.pathname} → HTTP ${r.status}, cache: ${cacheHdr}`, u.pathname, A05);
    f.reproduction = curl('GET', tricked.href);
    return [f];
  }
  return [];
}

// --- 7. HTTP verb / method-override tampering ------------------------------
// A 401/403 that flips to 200 when the method is overridden means access rules
// are keyed on the verb and can be tricked.
async function probeMethodOverride(u, base) {
  if (![401, 403].includes(base.status)) return [];
  const overrides = [
    { 'X-HTTP-Method-Override': 'GET' },
    { 'X-HTTP-Method': 'GET' },
    { 'X-Method-Override': 'GET' }
  ];
  for (const h of overrides) {
    let r;
    try { r = await fetchSafe(u.href, { method: 'POST', headers: h }); } catch { continue; }
    if (r.status === 200) {
      const f = finding('high', 'Authorization bypass via method-override header',
        `The endpoint returned ${base.status} for a normal GET but 200 when sent as POST with ${JSON.stringify(h)}. Access rules keyed on the HTTP verb can be bypassed by overriding the method.`,
        'Apply authorization independently of the HTTP method; ignore method-override headers unless explicitly required and safe.',
        `${JSON.stringify(h)} → HTTP 200 (baseline ${base.status})`, u.pathname, A01, { confidence: 'high' });
      f.reproduction = curl('POST', u.href, { headers: h });
      return [f];
    }
  }
  return [];
}

// --- 8. Brute-force resistance (opt-in, write) -----------------------------
// Only runs with allowWrite + a POST method/body (a login request the user
// supplied). Fires a small burst of the same request and watches for 429/lockout.
async function probeBruteForce(u, opts) {
  const N = 12;
  const statuses = {};
  for (let i = 0; i < N; i++) {
    try {
      const res = await fetchWithTimeout(u.href, {
        method: opts.method, timeout: 6000, redirect: 'manual',
        headers: opts.body ? { 'Content-Type': opts.contentType || 'application/json' } : undefined,
        body: opts.body
      });
      statuses[res.status] = (statuses[res.status] || 0) + 1;
      if (res.status === 429) {
        return finding('info', 'Brute-force throttling is active',
          `Received HTTP 429 after ${i + 1} rapid ${opts.method} requests — the endpoint throttles repeated attempts.`,
          'Good — keep rate limiting and account lockout on authentication endpoints.',
          `after ${i + 1} requests: ${JSON.stringify(statuses)}`, u.pathname, A07);
      }
    } catch { /* ignore */ }
  }
  return finding('high', 'No brute-force protection on authentication endpoint',
    `Sent ${N} rapid ${opts.method} requests with no HTTP 429 / lockout. Login endpoints without throttling are open to credential stuffing and password brute-forcing.`,
    'Enforce per-account and per-IP rate limiting, exponential backoff, and account lockout/CAPTCHA on repeated failures.',
    `${N} requests → ${JSON.stringify(statuses)}`, u.pathname, A07, { confidence: 'high' });
}

export async function scanVapt(input, opts = {}) {
  const u = normalizeUrl(input);
  const extended = opts.effort !== 'regular';
  const findings = [];
  const meta = { target: u.href, owaspCovered: [A01, A02, A05, A07], effort: extended ? 'extended' : 'regular' };

  // One baseline fetch reused by several probes (cookies, JWTs, cache, methods).
  let base;
  try { base = await fetchSafe(u.href, { redirect: 'manual' }); }
  catch (e) { throw new Error(`Could not load ${u.href}: ${e.message}`); }
  meta.status = base.status;

  // A soft-404 length reference so surface enumeration can ignore SPA shells.
  let softLen = null;
  try {
    const rnd = new URL('/sentryscan-' + Date.now().toString(36) + '-404', u.origin).href;
    const r404 = await fetchSafe(rnd, {});
    if (r404.status === 200) softLen = r404.body.length;
  } catch { /* ignore */ }

  const groups = await Promise.all([
    probeHostHeader(u).catch(() => []),
    probeCors(u).catch(() => []),
    Promise.resolve(probeJwt(u, base)),
    Promise.resolve(probeCookies(u, base)),
    probeSurface(u, extended, softLen).catch(() => []),
    probeCacheDeception(u, base).catch(() => []),
    probeMethodOverride(u, base).catch(() => [])
  ]);
  for (const g of groups) findings.push(...g);

  // Opt-in, state-changing: brute-force resistance on a supplied login request.
  if (opts.allowWrite && opts.method && !['GET', 'HEAD'].includes(String(opts.method).toUpperCase())) {
    try { findings.push(await probeBruteForce(u, opts)); } catch { /* ignore */ }
  }

  if (!findings.length) {
    findings.push(finding('info', 'No active pen-test signals detected',
      'The active checks (host-header injection, CORS credential exposure, JWT/cookie weaknesses, surface enumeration, cache deception, verb tampering) did not surface an issue on this target. Business-logic and multi-step abuse still require manual testing.',
      'Continue with manual, authenticated pen-testing for authorization and workflow logic — automated black-box checks can’t cover those.',
      null, u.pathname, A05));
  }
  return { type: 'vapt', meta, findings };
}
