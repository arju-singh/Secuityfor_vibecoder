// Shared helpers for the live scanners (URL normalization + SSRF guard,
// fetch with timeout, and a uniform finding shape).
import { URL } from 'node:url';
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

export function finding(severity, title, description, remediation, evidence, location, owasp) {
  return {
    severity,
    title,
    description,
    remediation: remediation || null,
    evidence: evidence || null,
    location: location || null,
    owasp: owasp || null
  };
}

export function normalizeUrl(input) {
  let raw = String(input || '').trim();
  if (!raw) throw new Error('No URL provided.');
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  const u = new URL(raw);
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http and https URLs are supported.');
  const host = u.hostname.toLowerCase();

  // Cloud metadata endpoints are ALWAYS blocked — an SSRF to these leaks
  // credentials, and there is no legitimate reason to scan them.
  if (host === '169.254.169.254' || host === 'metadata.google.internal') {
    throw new Error('Scanning of cloud metadata endpoints is not allowed.');
  }

  // localhost / private ranges are blocked by default (SSRF protection), but a
  // user running SentryScan locally can opt in to scan their own dev servers.
  if (process.env.SENTRYSCAN_ALLOW_LOCAL !== '1') {
    const blocked = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
    if (
      blocked.includes(host) ||
      /^(?:10|127)\./.test(host) ||
      /^192\.168\./.test(host) ||
      /^172\.(1[6-9]|2[0-9]|3[01])\./.test(host) ||
      host.endsWith('.local') ||
      host.endsWith('.internal')
    ) {
      throw new Error('Scanning of localhost / private network addresses is not allowed. Set SENTRYSCAN_ALLOW_LOCAL=1 to scan your own local/dev servers.');
    }
  }
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
    const res = await fetch(url, {
      ...opts,
      signal: ctrl.signal,
      redirect: opts.redirect || 'follow',
      // Auth headers sit below call-site headers so a probe can still override
      // a specific header (e.g. Origin) when it needs to.
      headers: { 'User-Agent': USER_AGENT, ...auth, ...(opts.headers || {}) }
    });
    res._elapsedMs = Date.now() - start;
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
