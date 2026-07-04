// Shared helpers for the live scanners (URL normalization + SSRF guard,
// fetch with timeout, and a uniform finding shape).
import { URL } from 'node:url';
import { isIP } from 'node:net';
import { AsyncLocalStorage } from 'node:async_hooks';

export const USER_AGENT = 'SentryScan/2.0 (+website-tester)';
export const DEFAULT_TIMEOUT = 12000;

// Request-scoped authentication headers. A scan wrapped in runWithAuth() makes
// every fetchWithTimeout() call inside it (including deeply-nested probes)
// automatically carry the user's auth headers — that's what turns an anonymous
// scan into an authenticated one without threading params through every call.
const authStore = new AsyncLocalStorage();

export function runWithAuth(headers, fn) {
  if (!headers || !Object.keys(headers).length) return fn();
  return authStore.run(headers, fn);
}
export function currentAuthHeaders() {
  return authStore.getStore() || null;
}

// `extra` is an optional trailing options object so the 7-positional call sites
// used across every scanner keep working unchanged. A scanner that knows better
// than the central default (util `enrichFinding`) can pass an explicit
// confidence ('high' | 'medium' | 'low') and/or a bespoke impact sentence.
export function finding(severity, title, description, remediation, evidence, location, owasp, extra = {}) {
  return {
    severity,
    title,
    description,
    remediation: remediation || null,
    evidence: evidence || null,
    location: location || null,
    owasp: owasp || null,
    confidence: extra.confidence || null,
    impact: extra.impact || null
  };
}

// Impact templates keyed by OWASP Top-10 (2021) prefix. "What could go wrong if
// you don't address it." Used as the default when a finding doesn't carry its
// own impact sentence.
const IMPACT_BY_OWASP = {
  A01: 'An attacker could reach data or actions outside their authorization — reading or modifying other users’ records, or performing admin-only operations.',
  A02: 'Sensitive data (credentials, keys, tokens, personal information) could be exposed or decrypted, enabling account takeover or data theft.',
  A03: 'Untrusted input reaching an interpreter could let an attacker read/modify the database, execute commands, or run script in a victim’s browser.',
  A04: 'A design weakness could be abused to bypass intended business or security controls.',
  A05: 'A misconfiguration hands an attacker reconnaissance detail or a foothold that makes further exploitation easier.',
  A06: 'A known-vulnerable component could be exploited using public, off-the-shelf exploit code.',
  A07: 'Weak authentication could allow account takeover through credential stuffing, brute force, session theft, or token forgery.',
  A08: 'Tampered code or data could be delivered to users — e.g. a compromised dependency or CDN injecting malicious script.',
  A09: 'Gaps in logging/monitoring let an attack progress undetected, delaying response and increasing the eventual damage.',
  A10: 'The server could be coerced into making requests to internal systems, exposing metadata, internal services, or acting as a proxy.'
};

const IMPACT_BY_SEVERITY = {
  critical: 'If unaddressed, this is directly exploitable and could lead to full compromise of the affected data or system.',
  high: 'If unaddressed, this gives an attacker a strong, realistic path toward compromising data or accounts.',
  medium: 'If unaddressed, this weakens the app’s defenses and can be chained with other issues to cause real harm.',
  low: 'If unaddressed, this is a minor exposure that mostly aids an attacker’s reconnaissance.',
  info: 'Informational — no direct harm, but worth noting for defense-in-depth.'
};

// Categories whose findings are about quality/reliability/maintainability rather
// than an attacker path — the security-framed fallback above would misdescribe
// them, so they get a neutral impact instead.
const NON_SECURITY_CATEGORIES = new Set(['ui', 'render', 'perf', 'a11y', 'seo', 'quality', 'frontend', 'config', 'testing', 'hygiene']);
const IMPACT_QUALITY = {
  critical: 'If unaddressed, this is likely to break core functionality or badly degrade the user experience.',
  high: 'If unaddressed, this materially degrades reliability, performance, accessibility, or maintainability.',
  medium: 'If unaddressed, this is a noticeable quality or maintainability gap worth fixing.',
  low: 'If unaddressed, this is a minor quality or polish issue.',
  info: 'Informational — a best-practice note, no direct harm.'
};

// Fill Confidence and Impact when a scanner didn't set them explicitly, so every
// finding in a report carries both. Confidence is a deterministic heuristic:
// something we directly observed (evidence or a working reproduction) is high;
// otherwise medium. Deterministic config checks that expose evidence therefore
// read as high, while caveated single-signal probes should pass their own lower
// confidence. Mutates and returns the finding.
export function enrichFinding(f) {
  if (!f.confidence) {
    f.confidence = (f.evidence || f.reproduction) ? 'high' : 'medium';
  }
  if (!f.impact) {
    const key = typeof f.owasp === 'string' ? (f.owasp.match(/A\d{2}/) || [])[0] : null;
    if (key && IMPACT_BY_OWASP[key]) {
      f.impact = IMPACT_BY_OWASP[key];
    } else if (NON_SECURITY_CATEGORIES.has(f.category)) {
      f.impact = IMPACT_QUALITY[f.severity] || IMPACT_QUALITY.info;
    } else {
      f.impact = IMPACT_BY_SEVERITY[f.severity] || IMPACT_BY_SEVERITY.info;
    }
  }
  return f;
}

// True if an IPv4/IPv6 literal falls in a loopback / private / link-local /
// unique-local range. Only called on strings already known to be IP literals
// (via net.isIP), so it never mis-flags a hostname that merely starts with "10.".
function isPrivateIp(host) {
  const v = isIP(host);
  if (v === 4) {
    const p = host.split('.').map(Number);
    if (p[0] === 10) return true;                                  // 10.0.0.0/8
    if (p[0] === 127) return true;                                 // 127.0.0.0/8 loopback
    if (p[0] === 0) return true;                                   // 0.0.0.0/8
    if (p[0] === 192 && p[1] === 168) return true;                 // 192.168.0.0/16
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;     // 172.16.0.0/12
    if (p[0] === 169 && p[1] === 254) return true;                 // 169.254.0.0/16 link-local (metadata)
    return false;
  }
  if (v === 6) {
    const h = host.toLowerCase().replace(/^\[|\]$/g, '');
    if (h === '::1' || h === '::') return true;                    // loopback / unspecified
    if (/^f[cd][0-9a-f]{2}:/.test(h)) return true;                 // fc00::/7 unique-local
    if (/^fe[89ab][0-9a-f]:/.test(h)) return true;                 // fe80::/10 link-local
    if (/^::ffff:/.test(h)) return isPrivateIp(h.replace(/^::ffff:/, '')); // IPv4-mapped
    return false;
  }
  return false;
}

// The host-level SSRF check, shared by normalizeUrl (user input) and the redirect
// follower (each hop). Throws when a host must not be reached. `allowLocal` mirrors
// the SENTRYSCAN_ALLOW_LOCAL opt-in for scanning your own dev servers.
export function assertHostAllowed(host, allowLocal = process.env.SENTRYSCAN_ALLOW_LOCAL === '1') {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');

  // Cloud metadata endpoints are ALWAYS blocked — an SSRF to these leaks
  // credentials, and there is no legitimate reason to scan them.
  if (h === '169.254.169.254' || h === 'metadata.google.internal') {
    throw new Error('Scanning of cloud metadata endpoints is not allowed.');
  }

  if (allowLocal) return;

  // localhost / private ranges are blocked by default (SSRF protection).
  if (
    h === 'localhost' || h.endsWith('.localhost') ||
    isPrivateIp(h) ||
    h.endsWith('.local') ||
    h.endsWith('.internal')
  ) {
    throw new Error('Scanning of localhost / private network addresses is not allowed. Set SENTRYSCAN_ALLOW_LOCAL=1 to scan your own local/dev servers.');
  }
}

export function normalizeUrl(input) {
  let raw = String(input || '').trim();
  if (!raw) throw new Error('No URL provided.');
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  const u = new URL(raw);
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http and https URLs are supported.');
  assertHostAllowed(u.hostname.toLowerCase());
  return u;
}

export async function fetchWithTimeout(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), opts.timeout || DEFAULT_TIMEOUT);
  const start = Date.now();
  try {
    // opts.noAuth forces an anonymous request even inside an authenticated scan
    // (used to compare authenticated vs anonymous access for access-control tests).
    const auth = opts.noAuth ? {} : (authStore.getStore() || {});
    const headers = { 'User-Agent': USER_AGENT, ...auth, ...(opts.headers || {}) };
    const wantFollow = (opts.redirect || 'follow') === 'follow';

    // When following redirects, do it MANUALLY so the SSRF guard runs on every
    // hop — otherwise a scanned site could 302 us to http://169.254.169.254/ (or
    // an internal host) and native `fetch` would follow it blindly, defeating the
    // guard that only saw the original user-supplied URL. Non-follow callers
    // (redirect: 'manual'/'error') keep native behavior.
    if (!wantFollow) {
      const res = await fetch(url, { ...opts, signal: ctrl.signal, redirect: opts.redirect, headers });
      res._elapsedMs = Date.now() - start;
      return res;
    }

    let current = String(url);
    let res;
    for (let hop = 0; hop <= 5; hop++) {
      res = await fetch(current, { ...opts, signal: ctrl.signal, redirect: 'manual', headers });
      const loc = res.status >= 300 && res.status < 400 && res.headers.get('location');
      if (!loc) break;
      if (hop === 5) break; // give up after 5 redirects; return the 3xx as-is
      const next = new URL(loc, current);
      if (!/^https?:$/.test(next.protocol)) {
        throw new Error(`Refusing to follow a redirect to a non-http(s) URL: ${next.protocol}`);
      }
      assertHostAllowed(next.hostname.toLowerCase()); // throws → aborts the scan hop, as intended
      current = next.href;
    }
    res._elapsedMs = Date.now() - start;
    res._finalUrl = current;
    return res;
  } finally {
    clearTimeout(t);
  }
}

export function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}
