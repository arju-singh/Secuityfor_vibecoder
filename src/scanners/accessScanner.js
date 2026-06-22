// Access-control scanner (OWASP A01). Black-box checks for the bugs that depend
// on authorization logic rather than payloads:
//   • Authentication enforcement — does the endpoint serve the same data with and
//     without credentials? (broken access control / missing auth)
//   • IDOR heuristic — are sequential object IDs directly addressable, returning
//     distinct real objects while out-of-range IDs 404?
//   • Race-condition probe (opt-in, write-only, experimental) — do concurrent
//     identical requests all succeed where only one should?
//
// HONEST SCOPE: these are SIGNALS, not proofs. Confirming IDOR/access-control
// bugs requires a second account; confirming a race requires knowing the action
// is meant to be single-use. Business-logic / workflow-abuse testing is NOT
// automatable here and remains a manual exercise (see the Learn tab methodology).
import { URL } from 'node:url';
import { finding, fetchWithTimeout, normalizeUrl, currentAuthHeaders } from './util.js';
import { curl } from './repro.js';

const A01 = 'A01:2021 Broken Access Control';
const A04 = 'A04:2021 Insecure Design';

async function get(url, o = {}) {
  const res = await fetchWithTimeout(url, { timeout: 9000, redirect: 'follow', ...o });
  const text = (await res.text().catch(() => '')).slice(0, 200000);
  return { status: res.status, text, len: text.length };
}

// Two bodies are "similar" if their lengths are within 10% — a cheap proxy for
// "the same resource was returned".
function similar(a, b) {
  if (!a.length && !b.length) return true;
  const hi = Math.max(a.length, b.length), lo = Math.min(a.length, b.length);
  return hi > 0 && lo / hi >= 0.9;
}

// Find a numeric object ID in the query string or the path (last numeric segment).
function findId(u) {
  for (const [k, v] of u.searchParams) if (/^\d+$/.test(v) && v.length <= 9) return { kind: 'query', key: k, val: parseInt(v, 10) };
  const segs = u.pathname.split('/');
  for (let i = segs.length - 1; i >= 0; i--) if (/^\d+$/.test(segs[i]) && segs[i].length <= 9) return { kind: 'path', idx: i, val: parseInt(segs[i], 10) };
  return null;
}
function withId(u, id, info) {
  const t = new URL(u.href);
  if (info.kind === 'query') t.searchParams.set(info.key, String(id));
  else { const segs = t.pathname.split('/'); segs[info.idx] = String(id); t.pathname = segs.join('/'); }
  return t.href;
}

async function probeIdor(u, authed, hasAuth) {
  const id = findId(u);
  if (!id || authed.status !== 200 || authed.len < 30) return null;
  const neighborId = id.val > 1 ? id.val - 1 : id.val + 1;
  const farId = id.val + 100000;
  let neighbor, far;
  try { neighbor = await get(withId(u, neighborId, id)); far = await get(withId(u, farId, id)); }
  catch { return null; }

  // A distinct neighbour object + a not-found far ID => sequential, addressable
  // objects. (If the neighbour equals our object, it's likely a catch-all/SPA
  // route, not an IDOR — so we don't flag it.)
  // Distinct = a real, different object came back (exact content differs). The
  // far-ID-missing guard prevents false positives on SPA/catch-all routes, which
  // return the same shell for every ID (so the far ID would also be 200).
  const farMissing = far.status >= 400 || far.len < neighbor.len * 0.5;
  const distinct = neighbor.status === 200 && neighbor.len >= 20 && neighbor.text !== authed.text;
  if (!distinct || !farMissing) return null;

  const where = id.kind === 'query' ? `parameter "${id.key}"` : 'a path segment';
  // Higher confidence when we're authenticated (objects are likely user-scoped).
  const f = finding(hasAuth ? 'medium' : 'low', `Possible IDOR via ${where}`,
    `Changing the object ID (${id.val} → ${neighborId}) returned a different valid object, while an out-of-range ID (${farId}) was not found — sequential IDs are directly addressable. If these objects belong to other users and aren't authorization-checked, this is an IDOR. Confirm with a second account.`,
    'Enforce per-object authorization (the caller must be allowed the specific object), and use unguessable IDs (UUIDs) as defense-in-depth.',
    `ids tested: ${id.val} (orig), ${neighborId} (HTTP ${neighbor.status}), ${farId} (HTTP ${far.status})`, null, A01);
  f.reproduction = curl('GET', withId(u, neighborId, id), { headers: currentAuthHeaders() || undefined });
  return f;
}

// 401/403 bypass attempts — header spoofing and path mutations that a real
// browser/user wouldn't send. If any returns 200, the gate is bypassable.
async function probeAuthBypass(u, baseline) {
  if (![401, 403].includes(baseline.status)) return [];
  const path = u.pathname + (u.search || '');
  const headerSets = [
    { 'X-Forwarded-For': '127.0.0.1' },
    { 'X-Forwarded-Host': '127.0.0.1' },
    { 'X-Original-URL': path },
    { 'X-Rewrite-URL': path },
    { 'X-Custom-IP-Authorization': '127.0.0.1' },
    { 'X-Originating-IP': '127.0.0.1' }
  ];
  for (const h of headerSets) {
    try {
      const r = await get(u.href, { headers: h, noAuth: true });
      if (r.status === 200) {
        const f = finding('high', 'Authorization bypass via request header',
          `The endpoint returned 401/403 normally but 200 when sent the header ${JSON.stringify(h)}. A trusted-header check can be spoofed by anyone, bypassing access control.`,
          'Never trust client-supplied headers (X-Forwarded-*, X-Original-URL, etc.) for authorization; enforce auth in application logic.',
          `${JSON.stringify(h)} → HTTP 200 (baseline ${baseline.status})`, null, A01);
        f.reproduction = curl('GET', u.href, { headers: h });
        return [f];
      }
    } catch { /* ignore */ }
  }
  const pathVariants = [u.pathname + '/', u.pathname + '/.', u.pathname.toUpperCase(), u.pathname + '%2f', '/%2e' + u.pathname];
  for (const pv of pathVariants) {
    try {
      const t = new URL(u.href); t.pathname = pv;
      const r = await get(t.href, { noAuth: true });
      if (r.status === 200) {
        const f = finding('high', 'Authorization bypass via path mutation',
          `The endpoint returned 401/403 for ${u.pathname} but 200 for the equivalent path "${pv}". Path-based access rules can be bypassed with encoding/normalisation tricks.`,
          'Normalise the request path before applying access rules; enforce authorization in the application, not just at the proxy/path layer.',
          `${pv} → HTTP 200 (baseline ${baseline.status})`, null, A01);
        f.reproduction = curl('GET', t.href);
        return [f];
      }
    } catch { /* ignore */ }
  }
  return [];
}

// Send rapid sequential requests and watch for HTTP 429 / Retry-After.
async function probeRateLimit(u) {
  const N = 25;
  const statuses = {};
  for (let i = 0; i < N; i++) {
    try {
      const res = await fetchWithTimeout(u.href, { timeout: 6000, redirect: 'manual' });
      statuses[res.status] = (statuses[res.status] || 0) + 1;
      if (res.status === 429) {
        return finding('info', 'Rate limiting is active',
          `Received HTTP 429 after ${i + 1} rapid requests — throttling appears to be in place.`,
          'Good — keep rate limiting on sensitive and expensive endpoints.',
          `Retry-After: ${res.headers.get('retry-after') || 'n/a'}`, null, A04);
      }
    } catch { /* ignore */ }
  }
  return finding('low', 'No rate limiting observed',
    `Sent ${N} rapid requests with no HTTP 429 response. Endpoints without rate limiting are exposed to brute-force, credential-stuffing, enumeration, and scraping.`,
    'Apply rate limiting / throttling (per IP and per account) on login, search, and other sensitive or expensive endpoints.',
    `${N} requests → ${JSON.stringify(statuses)}`, null, A04);
}

async function sendWrite(url, opts) {
  const o = { method: opts.method, timeout: 9000, redirect: 'follow' };
  if (opts.body) { o.headers = { 'Content-Type': opts.contentType || 'application/json' }; o.body = opts.body; }
  const res = await fetchWithTimeout(url, o);
  return res.status;
}

async function probeRace(u, opts) {
  const N = 10;
  const results = await Promise.allSettled(Array.from({ length: N }, () => sendWrite(u.href, opts)));
  const ok = results.filter((r) => r.status === 'fulfilled' && r.value >= 200 && r.value < 300).length;
  return finding('info', 'Race-condition probe (experimental)',
    `Sent ${N} concurrent ${opts.method} requests; ${ok} returned a 2xx success. If this action is meant to succeed only once (redeem a coupon, withdraw funds, submit once), multiple concurrent successes can indicate a race condition. Low-confidence signal — confirm manually.`,
    'Use atomic DB operations, row locks, or idempotency keys for state-changing actions.',
    `${ok}/${N} concurrent requests succeeded`, null, A01);
}

export async function scanAccess(input, opts = {}) {
  const u = normalizeUrl(input);
  const findings = [];
  const meta = { target: u.href, owaspCovered: [A01] };
  const hasAuth = !!currentAuthHeaders();

  let authed;
  try { authed = await get(u.href); }
  catch (e) { throw new Error(`Could not load ${u.href}: ${e.message}`); }
  meta.status = authed.status;

  // 1) Authentication enforcement (needs credentials to compare).
  if (hasAuth) {
    try {
      const anon = await get(u.href, { noAuth: true });
      if (authed.status === 200 && anon.status === 200 && similar(authed.text, anon.text)) {
        findings.push(finding('low', 'Endpoint returns data without authentication',
          'The endpoint returns the same 200 response with and without your credentials, so it does not enforce authentication. Confirm this resource is meant to be public — if not, it is broken access control.',
          'Require and verify authentication/authorization on every non-public endpoint.',
          `authenticated HTTP ${authed.status} ≈ anonymous HTTP ${anon.status} (similar body)`, null, A01));
      } else if (authed.status === 200 && (anon.status === 401 || anon.status === 403)) {
        meta.authEnforced = true;
      }
    } catch { /* ignore */ }
  } else {
    findings.push(finding('info', 'Authentication not provided — access control not fully tested',
      'No credentials were supplied, so authenticated-vs-anonymous access could not be compared. Add a token/cookie in the "Authenticated request" box to test for broken access control.',
      'Provide a session cookie or bearer token to enable access-control testing.', null, null, A01));
  }

  // 2) IDOR heuristic.
  const idor = await probeIdor(u, authed, hasAuth);
  if (idor) findings.push(idor);

  // 2b) 401/403 bypass attempts (only meaningful on a protected endpoint).
  findings.push(...await probeAuthBypass(u, authed));

  // 2c) Rate-limit probe — opt-in (sends a burst of requests).
  if (opts.rateLimit) {
    try { findings.push(await probeRateLimit(u)); } catch { /* ignore */ }
  }

  // 3) Race-condition probe — only for opt-in write requests.
  if (opts.allowWrite && opts.method && !['GET', 'HEAD'].includes(String(opts.method).toUpperCase())) {
    try { findings.push(await probeRace(u, opts)); } catch { /* ignore */ }
  }

  if (!findings.length || (findings.length === 1 && findings[0].severity === 'info' && meta.authEnforced)) {
    findings.push(finding('info', 'No access-control signals detected',
      'Authentication appears enforced and no sequential-ID (IDOR) pattern was found. Note: business-logic and workflow-abuse flaws cannot be detected automatically — test those manually.',
      'Manually verify object-level authorization and multi-step workflow integrity.', null, null, A01));
  }
  return { type: 'access', meta, findings };
}
