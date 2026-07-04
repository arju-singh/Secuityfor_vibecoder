// API endpoint tester. Probes an HTTP(S) endpoint for reachability, status,
// timing, payload validity, CORS, supported methods, and auth behavior.
import { finding, fetchWithTimeout, normalizeUrl } from './util.js';

export async function scanApi(input) {
  const u = normalizeUrl(input);
  const findings = [];
  const meta = { target: u.href };
  const isHttps = u.protocol === 'https:';

  if (!isHttps) {
    findings.push(finding('high', 'API served over plain HTTP',
      'The endpoint is not using HTTPS; requests and tokens travel in cleartext.',
      'Serve the API over HTTPS only.'));
  }

  // Primary GET
  let res, bodyText = '';
  try {
    res = await fetchWithTimeout(u.href, { method: 'GET', timeout: 15000, redirect: 'follow', headers: { Accept: 'application/json, */*' } });
    bodyText = await res.text();
  } catch (e) {
    throw new Error(`Could not reach API ${u.href}: ${e.message}`);
  }

  meta.status = res.status;
  meta.responseTimeMs = res._elapsedMs || 0;
  const ctype = (res.headers.get('content-type') || '').split(';')[0];
  meta.contentType = ctype;
  meta.responseBytes = Buffer.byteLength(bodyText);

  // Status semantics
  if (res.status >= 500) {
    findings.push(finding('critical', `Server error (HTTP ${res.status})`,
      'The endpoint returned a 5xx server error on a basic GET.',
      'Investigate server logs; the endpoint is failing.', String(res.status)));
  } else if (res.status === 404) {
    findings.push(finding('high', 'Endpoint not found (HTTP 404)',
      'The endpoint returns 404 — the path may be wrong or removed.',
      'Verify the API path.', '404'));
  } else if (res.status === 401 || res.status === 403) {
    findings.push(finding('info', `Authentication required (HTTP ${res.status})`,
      'The endpoint requires authentication, which is expected for protected APIs.',
      'Provide valid credentials/token to test authorized responses.', String(res.status)));
  } else if (res.status >= 400) {
    findings.push(finding('medium', `Client error (HTTP ${res.status})`,
      'The endpoint returned a 4xx response to a plain GET.',
      'Confirm required parameters, headers, or method.', String(res.status)));
  }

  // Timing
  if (meta.responseTimeMs > 3000) {
    findings.push(finding('medium', `Slow API response (${(meta.responseTimeMs / 1000).toFixed(1)}s)`,
      'The endpoint took over 3 seconds to respond.',
      'Profile and optimize the endpoint; add caching where possible.', meta.responseTimeMs + 'ms'));
  }

  // JSON validity (when it claims JSON or looks like JSON)
  const looksJson = /json/i.test(ctype) || /^[\s\r\n]*[[{]/.test(bodyText);
  if (looksJson) {
    try {
      const parsed = JSON.parse(bodyText);
      meta.jsonValid = true;
      meta.jsonType = Array.isArray(parsed) ? `array[${parsed.length}]` : typeof parsed;
    } catch (e) {
      meta.jsonValid = false;
      findings.push(finding('high', 'Invalid JSON response',
        'The endpoint advertises or resembles JSON but the body failed to parse.',
        'Return well-formed JSON and a correct application/json content-type.', e.message));
    }
    if (!/json/i.test(ctype)) {
      findings.push(finding('low', 'JSON body without JSON content-type',
        `The body parses as JSON but content-type is "${ctype || 'unset'}".`,
        'Set Content-Type: application/json so clients parse it correctly.', ctype || 'unset'));
    }
  }

  // Security headers relevant to APIs
  if (!res.headers.get('x-content-type-options')) {
    findings.push(finding('low', 'Missing X-Content-Type-Options',
      'Responses may be MIME-sniffed by browsers.',
      'Add X-Content-Type-Options: nosniff.'));
  }
  if (isHttps && !res.headers.get('strict-transport-security')) {
    findings.push(finding('medium', 'Missing HSTS header',
      'The API is served over HTTPS but sends no Strict-Transport-Security header, so a client’s first request can be downgraded to HTTP and tokens intercepted.',
      'Add Strict-Transport-Security: max-age=31536000; includeSubDomains.', 'unset'));
  }
  const acao = res.headers.get('access-control-allow-origin');
  meta.cors = acao || 'none';
  if (acao === '*' && res.headers.get('access-control-allow-credentials') === 'true') {
    findings.push(finding('high', 'Insecure CORS (wildcard + credentials)',
      'Allow-Origin "*" with Allow-Credentials true is invalid and exposes credentialed data.',
      'Reflect a specific trusted origin when credentials are allowed.', acao));
  } else if (acao === '*') {
    findings.push(finding('low', 'Wildcard CORS policy',
      'Any website can read responses from this endpoint.',
      'Restrict CORS to trusted origins for non-public data.', acao));
  }

  // Supported methods via OPTIONS
  try {
    const opt = await fetchWithTimeout(u.href, { method: 'OPTIONS', timeout: 8000, redirect: 'manual' });
    const allow = opt.headers.get('allow') || opt.headers.get('access-control-allow-methods');
    if (allow) {
      meta.allowedMethods = allow;
      const methods = allow.toUpperCase();
      if (/\b(PUT|DELETE|PATCH)\b/.test(methods)) {
        findings.push(finding('info', 'State-changing methods advertised',
          `The endpoint advertises methods: ${allow}.`,
          'Ensure write methods enforce authentication and authorization.', allow));
      }
    }
  } catch { /* OPTIONS may be unsupported */ }

  // Server disclosure
  const server = res.headers.get('server');
  if (server && /\d/.test(server)) {
    findings.push(finding('low', 'Server version disclosed',
      `The Server header reveals "${server}".`,
      'Genericize the Server header.', server));
  }

  return { type: 'api', meta, findings };
}
