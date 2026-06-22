// OpenAPI / Swagger-driven endpoint enumeration. Finds the API's own spec
// (or accepts a spec URL directly), parses the documented paths, and probes the
// GET endpoints to map the live attack surface and spot documented endpoints
// that respond without authentication.
//
// SAFETY: probes documented GET endpoints only (read), with path parameters
// filled by a harmless "1". Capped. Use only on APIs you are authorized to test.
import { URL } from 'node:url';
import { finding, fetchWithTimeout, normalizeUrl } from './util.js';

const A01 = 'A01:2021 Broken Access Control';
const A09 = 'A09:2021 Security Logging & Monitoring Failures';

const SPEC_PATHS = ['/openapi.json', '/swagger.json', '/v3/api-docs', '/v2/api-docs', '/api-docs', '/swagger/v1/swagger.json', '/openapi'];
const MAX_PROBE = 25;

async function tryFetchSpec(url) {
  try {
    const res = await fetchWithTimeout(url, { timeout: 8000, redirect: 'follow' });
    if (res.status !== 200) return null;
    const text = (await res.text().catch(() => '')).slice(0, 3_000_000);
    const spec = JSON.parse(text);
    if (spec && spec.paths && typeof spec.paths === 'object' && (spec.openapi || spec.swagger)) return { spec, url };
  } catch { /* not a JSON spec here */ }
  return null;
}

// Where the API is actually served (spec `servers`/`basePath`, else the origin).
function resolveBase(spec, specUrl) {
  const specOrigin = new URL(specUrl).origin;
  if (Array.isArray(spec.servers) && spec.servers[0] && spec.servers[0].url) {
    try { return new URL(spec.servers[0].url, specOrigin).href.replace(/\/$/, ''); } catch { /* fall through */ }
  }
  if (spec.basePath) return specOrigin + spec.basePath.replace(/\/$/, '');
  return specOrigin;
}

const fillParams = (p) => p.replace(/\{[^}]+\}/g, '1');

export async function scanApiSpec(input) {
  const u = normalizeUrl(input);
  const meta = { target: u.href };

  // The input itself might be a spec; otherwise probe common locations.
  let found = await tryFetchSpec(u.href);
  if (!found) {
    for (const p of SPEC_PATHS) {
      found = await tryFetchSpec(u.origin + p);
      if (found) break;
    }
  }
  if (!found) {
    return { type: 'spec', meta, findings: [finding('info', 'No OpenAPI/Swagger spec found',
      `Looked at the URL and common locations (${SPEC_PATHS.join(', ')}) but found no JSON OpenAPI/Swagger document to enumerate. (YAML specs are not parsed.)`,
      'If the API publishes a spec, pass its URL directly; otherwise enumeration is not possible.')] };
  }

  const { spec, url: specUrl } = found;
  const base = resolveBase(spec, specUrl);
  meta.specUrl = specUrl;
  meta.base = base;

  const getPaths = [];
  for (const [p, ops] of Object.entries(spec.paths)) {
    if (ops && typeof ops === 'object' && (ops.get || ops.GET)) getPaths.push(p);
  }
  const totalPaths = Object.keys(spec.paths).length;
  meta.documentedPaths = totalPaths;
  meta.getEndpoints = getPaths.length;

  const findings = [];
  findings.push(finding('info', `OpenAPI spec discovered — ${totalPaths} documented path(s)`,
    `Found an OpenAPI/Swagger spec at ${specUrl} describing ${totalPaths} path(s) (${getPaths.length} with GET). A published spec hands attackers your full API surface — ensure that's intended.`,
    'Restrict access to API documentation in production if the API is not meant to be public.', specUrl, null, A09));

  // Probe a bounded set of GET endpoints (path params filled with "1").
  const probeList = getPaths.slice(0, MAX_PROBE);
  const openNoAuth = [];
  await Promise.allSettled(probeList.map(async (p) => {
    const target = base + fillParams(p);
    try {
      const res = await fetchWithTimeout(target, { timeout: 7000, redirect: 'manual', noAuth: true });
      if (res.status === 200) openNoAuth.push(p);
    } catch { /* ignore */ }
  }));

  if (openNoAuth.length) {
    findings.push(finding('low', `${openNoAuth.length} documented endpoint(s) respond 200 without authentication`,
      'These documented endpoints returned data to an unauthenticated request. Confirm each is meant to be public — any that expose user or internal data are broken access control.',
      'Require authentication/authorization on every non-public documented endpoint.',
      openNoAuth.slice(0, 12).map((p) => 'GET ' + p).join('\n'), null, A01));
  }
  if (getPaths.length > MAX_PROBE) {
    findings.push(finding('info', `Probed ${MAX_PROBE} of ${getPaths.length} GET endpoints`,
      `Enumeration was capped at ${MAX_PROBE} endpoints to stay light-touch; ${getPaths.length - MAX_PROBE} more are documented.`,
      'Review the remaining documented endpoints manually.'));
  }
  return { type: 'spec', meta, findings };
}
