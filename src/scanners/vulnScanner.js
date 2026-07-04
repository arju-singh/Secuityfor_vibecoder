// OWASP-aligned vulnerability scanner. Performs non-destructive checks of the
// class used by baseline DAST tools (e.g. OWASP ZAP baseline): header/CSP
// weaknesses, outdated components, misconfiguration probes, data exposure, and
// light reflected-input / SQL-error signature checks. Every finding is mapped
// to an OWASP Top 10 (2021) category.
//
// SAFETY: All requests are single, benign, and non-destructive. Use only on
// systems you own or are authorized to assess.
import * as cheerio from 'cheerio';
import { URL } from 'node:url';
import http from 'node:http';
import https from 'node:https';
import { finding, fetchWithTimeout, normalizeUrl } from './util.js';

// Raw HTTP request for methods WHATWG `fetch` forbids (TRACE, TRACK, ...). Node's
// fetch throws `'TRACE' HTTP method is unsupported`, so the TRACE probe has to go
// through the low-level http(s) client. Resolves to { status, body } or rejects.
function rawRequest(rawUrl, method, timeout = 7000) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(rawUrl); } catch (e) { return reject(e); }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(u, { method, timeout, headers: { 'User-Agent': 'SentryScan/2.0 (+website-tester)' } }, (res) => {
      let body = '';
      res.on('data', (c) => { if (body.length < 8192) body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

const OWASP = {
  A01: 'A01:2021 Broken Access Control',
  A02: 'A02:2021 Cryptographic Failures',
  A03: 'A03:2021 Injection',
  A05: 'A05:2021 Security Misconfiguration',
  A06: 'A06:2021 Vulnerable & Outdated Components',
  A07: 'A07:2021 Identification & Authentication Failures',
  A08: 'A08:2021 Software & Data Integrity Failures',
  A09: 'A09:2021 Security Logging & Monitoring Failures'
};

// ---- Sensitive data signatures in served content -------------------------
// A single 0–255 octet, so version strings like "10.669.606.225" don't match.
const OCT = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const PRIV_IP_RE = new RegExp(
  `\\b(?:10\\.${OCT}\\.${OCT}\\.${OCT}` +
  `|192\\.168\\.${OCT}\\.${OCT}` +
  `|172\\.(?:1[6-9]|2\\d|3[01])\\.${OCT}\\.${OCT})\\b`, 'g');

const DATA_SIGNATURES = [
  { id: 'aws-key', re: /\bAKIA[0-9A-Z]{16}\b/g, title: 'AWS access key exposed in page', sev: 'critical', owasp: OWASP.A02 },
  { id: 'google-key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g, title: 'Google API key exposed in page', sev: 'high', owasp: OWASP.A02 },
  { id: 'stripe-pub', re: /\bpk_live_[0-9a-zA-Z]{20,}\b/g, title: 'Stripe live publishable key in page', sev: 'low', owasp: OWASP.A02 },
  { id: 'stripe-secret', re: /\bsk_live_[0-9a-zA-Z]{20,}\b/g, title: 'Stripe SECRET key exposed in page', sev: 'critical', owasp: OWASP.A02 },
  { id: 'private-key', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, title: 'Private key block in page source', sev: 'critical', owasp: OWASP.A02 },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, title: 'JWT exposed in page source', sev: 'medium', owasp: OWASP.A02 },
  { id: 'priv-ip', re: PRIV_IP_RE, title: 'Internal IP address disclosed', sev: 'low', owasp: OWASP.A05 }
];

// ---- SQL error signatures (for the single-quote probe) -------------------
const SQL_ERRORS = [
  /you have an error in your sql syntax/i,
  /warning:\s+mysqli?/i,
  /unclosed quotation mark after the character string/i,
  /quoted string not properly terminated/i,
  /pg::syntaxerror|psql:|postgresql.*error/i,
  /ora-\d{5}/i,
  /sqlite3?::|sqlite_error/i,
  /odbc.*driver/i
];

function abs(base, href) { try { return new URL(href, base).href; } catch { return null; } }

// opts.effort: 'extended' (default) runs the full probe set including the
// extra-request probes (open redirect, injection, dev endpoints, GraphQL, …);
// 'regular' runs only the checks derived from the single landing-page fetch,
// for fast, low-traffic incremental re-scans.
export async function scanVuln(input, opts = {}) {
  const extended = opts.effort !== 'regular';
  const u = normalizeUrl(input);
  const origin = u.origin;
  const findings = [];
  const meta = { target: u.href, owaspCovered: Object.values(OWASP) };

  // Fetch the landing page once.
  let res, html = '', headers, finalUrl = u.href, isHttps;
  try {
    res = await fetchWithTimeout(u.href, { redirect: 'follow', timeout: 15000 });
    finalUrl = res.url;
    headers = res.headers;
    isHttps = new URL(finalUrl).protocol === 'https:';
    const ctype = headers.get('content-type') || '';
    const body = await res.text();
    if (/text\/html|application\/xhtml/i.test(ctype)) html = body.slice(0, 800000);
    meta.finalUrl = finalUrl;
    meta.status = res.status;
  } catch (e) {
    throw new Error(`Could not load ${u.href}: ${e.message}`);
  }

  const $ = html ? cheerio.load(html) : null;

  // ---- 1) CSP weakness analysis (A05) ------------------------------------
  const csp = headers.get('content-security-policy') || '';
  if (csp) {
    if (/'unsafe-inline'/.test(csp)) {
      findings.push(finding('medium', "CSP allows 'unsafe-inline'",
        "The Content-Security-Policy permits inline scripts/styles, largely defeating XSS protection.",
        "Remove 'unsafe-inline'; use nonces or hashes for required inline code.", null, null, OWASP.A05));
    }
    if (/'unsafe-eval'/.test(csp)) {
      findings.push(finding('medium', "CSP allows 'unsafe-eval'",
        "The CSP permits eval(), enabling a class of injection attacks.",
        "Remove 'unsafe-eval' and refactor code that relies on dynamic evaluation.", null, null, OWASP.A05));
    }
    if (/(?:default|script)-src[^;]*\*(?!\.)/.test(csp)) {
      findings.push(finding('medium', 'CSP uses wildcard source',
        'A wildcard (*) script/default source lets scripts load from any origin.',
        'Restrict sources to explicit trusted origins.', null, null, OWASP.A05));
    }
    if (!/object-src/.test(csp)) {
      findings.push(finding('low', "CSP missing object-src",
        "Without object-src 'none', plugins/embeds can be abused.",
        "Add object-src 'none' to the policy.", null, null, OWASP.A05));
    }
    if (!/base-uri/.test(csp)) {
      findings.push(finding('low', 'CSP missing base-uri',
        'Without base-uri, attackers can hijack relative URLs via injected <base>.',
        "Add base-uri 'self' to the policy.", null, null, OWASP.A05));
    }
  }

  // ---- 2) HSTS quality (A02) when present --------------------------------
  const hsts = headers.get('strict-transport-security') || '';
  if (hsts) {
    const m = hsts.match(/max-age=(\d+)/i);
    const maxAge = m ? parseInt(m[1], 10) : 0;
    if (maxAge < 15552000) {
      findings.push(finding('low', 'Weak HSTS max-age',
        `HSTS max-age is ${maxAge}s; below the recommended 6 months (15552000s).`,
        'Increase max-age and add includeSubDomains; preload.', hsts, null, OWASP.A02));
    }
    if (!/includesubdomains/i.test(hsts)) {
      findings.push(finding('low', 'HSTS missing includeSubDomains',
        'Subdomains are not covered by HSTS.',
        'Add includeSubDomains (and preload once verified).', hsts, null, OWASP.A02));
    }
  }

  // ---- 3) Cross-origin isolation headers (A05, info) ---------------------
  if (!headers.get('cross-origin-opener-policy')) {
    findings.push(finding('info', 'Missing Cross-Origin-Opener-Policy',
      'COOP helps isolate the page from cross-origin attacks (e.g. XS-Leaks).',
      'Consider Cross-Origin-Opener-Policy: same-origin.', null, null, OWASP.A05));
  }
  if (!headers.get('x-permitted-cross-domain-policies')) {
    findings.push(finding('info', 'Missing X-Permitted-Cross-Domain-Policies',
      'Adobe cross-domain policy controls are not set.',
      'Add X-Permitted-Cross-Domain-Policies: none.', null, null, OWASP.A05));
  }
  if (!headers.get('cross-origin-embedder-policy')) {
    findings.push(finding('info', 'Missing Cross-Origin-Embedder-Policy',
      'COEP, together with COOP, enables cross-origin isolation that mitigates Spectre-style and XS-Leak attacks.',
      'Consider Cross-Origin-Embedder-Policy: require-corp (once subresources send CORP/CORS).', null, null, OWASP.A05));
  }
  if (!headers.get('cross-origin-resource-policy')) {
    findings.push(finding('info', 'Missing Cross-Origin-Resource-Policy',
      'CORP lets the server declare which origins may embed a resource, blocking some cross-origin leak/side-channel attacks.',
      'Consider Cross-Origin-Resource-Policy: same-origin (or same-site) on sensitive resources.', null, null, OWASP.A05));
  }

  // ---- 4) Subresource Integrity (A08) ------------------------------------
  if ($) {
    const sriIssues = [];
    $('script[src]').each((_, el) => {
      const src = $(el).attr('src') || '';
      const absUrl = abs(finalUrl, src);
      if (absUrl && new URL(absUrl).origin !== origin && !$(el).attr('integrity')) sriIssues.push(absUrl);
    });
    $('link[rel="stylesheet"][href]').each((_, el) => {
      const href = $(el).attr('href') || '';
      const absUrl = abs(finalUrl, href);
      if (absUrl && new URL(absUrl).origin !== origin && !$(el).attr('integrity')) sriIssues.push(absUrl);
    });
    if (sriIssues.length) {
      findings.push(finding('medium', `${sriIssues.length} third-party resource(s) without Subresource Integrity`,
        'Cross-origin scripts/styles load without an integrity hash; a compromised CDN could inject malicious code.',
        'Add an integrity="sha384-…" and crossorigin attribute to external <script>/<link> tags.',
        [...new Set(sriIssues)].slice(0, 6).join('\n'), null, OWASP.A08));
    }

    // ---- 5) Outdated JS libraries (A06) ----------------------------------
    const libFindings = detectOutdatedLibs($, html, finalUrl);
    findings.push(...libFindings);

    // ---- 6) Technology / version disclosure (A06) ------------------------
    const generator = $('meta[name="generator"]').attr('content');
    if (generator && /\d/.test(generator)) {
      findings.push(finding('low', 'CMS/generator version disclosed',
        `A generator meta tag reveals "${generator}".`,
        'Remove version info from the generator meta tag.', generator, null, OWASP.A06));
    }
    if (/wp-content|wp-includes/i.test(html)) {
      meta.cms = 'WordPress';
      findings.push(finding('info', 'WordPress detected',
        'The site appears to run WordPress. Ensure core, themes, and plugins are current and the admin panel is protected.',
        'Keep WordPress updated, limit login attempts, and hide version details.', null, null, OWASP.A06));
    }

    // ---- 7) Forms / auth hygiene (A07) -----------------------------------
    $('form').each((_, el) => {
      const $f = $(el);
      const hasPw = $f.find('input[type="password"]').length > 0;
      if (!hasPw) return;
      const autocomplete = ($f.attr('autocomplete') || '').toLowerCase();
      const pwAutocomplete = ($f.find('input[type="password"]').attr('autocomplete') || '').toLowerCase();
      if (autocomplete !== 'off' && pwAutocomplete !== 'off' && pwAutocomplete !== 'new-password' && pwAutocomplete !== 'current-password') {
        findings.push(finding('info', 'Password field allows browser autocomplete',
          'A login/password form does not restrict autocomplete, which can matter on shared machines.',
          'Set autocomplete appropriately (e.g. "current-password" / "new-password").', null, null, OWASP.A07));
      }
      const method = ($f.attr('method') || 'get').toLowerCase();
      const hasHidden = $f.find('input[type="hidden"]').length > 0;
      if (method === 'post' && !hasHidden) {
        findings.push(finding('low', 'POST form without apparent CSRF token',
          'A state-changing form has no hidden token field, a common sign of missing CSRF protection.',
          'Include and validate an anti-CSRF token on all state-changing forms.', null, null, OWASP.A01));
      }
    });

    // ---- 8) Sensitive data in page source (A02/A09) ----------------------
    for (const sig of DATA_SIGNATURES) {
      sig.re.lastIndex = 0;
      const found = html.match(sig.re);
      if (found && found.length) {
        findings.push(finding(sig.sev, sig.title,
          `${found.length} match(es) of ${sig.id} were found in the served page source.`,
          'Remove sensitive values from client-delivered content; serve secrets only server-side.',
          redact(found[0]), null, sig.owasp));
      }
    }

    // ---- 9) Source map exposure (A05) ------------------------------------
    const mapRef = html.match(/sourceMappingURL=([^\s"'*]+\.map)/i);
    if (mapRef) {
      const mapUrl = abs(finalUrl, mapRef[1]);
      if (mapUrl) {
        try {
          const mr = await fetchWithTimeout(mapUrl, { method: 'GET', timeout: 7000, headers: { Range: 'bytes=0-200' } });
          if (mr.status === 200) {
            findings.push(finding('low', 'Source map publicly accessible',
              'A JavaScript source map is reachable, exposing original (pre-minified) source code.',
              'Do not deploy .map files to production, or restrict access to them.', mapUrl, null, OWASP.A05));
          }
        } catch { /* not reachable */ }
      }
    }
  }

  // ---- 10) Probes that need extra requests (run in parallel) -------------
  // Skipped on 'regular' effort — these are the bulk of the scanner's outbound
  // traffic; 'extended' is the deep-dive that runs them all.
  if (extended) {
    const probes = await Promise.allSettled([
      probeSecurityTxt(origin),
      probeTrace(finalUrl),
      probeCorsReflection(finalUrl),
      probeDirListing(origin),
      probeInjection(u),
      probeOpenRedirect(u),
      probeHttpMethods(finalUrl),
      probeDevEndpoints(origin),
      probeGraphql(origin)
    ]);
    for (const p of probes) {
      if (p.status === 'fulfilled' && p.value) findings.push(...p.value);
    }
  }
  meta.effort = extended ? 'extended' : 'regular';

  return { type: 'vuln', meta, findings };
}

function redact(v) {
  if (!v) return v;
  return v.length <= 10 ? v.slice(0, 3) + '***' : v.slice(0, 6) + '…' + v.slice(-4);
}

// ---- Outdated library detection ------------------------------------------
function detectOutdatedLibs($, html, base) {
  const findings = [];
  const scripts = [];
  $('script[src]').each((_, el) => scripts.push($(el).attr('src') || ''));
  const joined = scripts.join('\n') + '\n' + html.slice(0, 200000);

  // jQuery
  const jq = joined.match(/jquery[-.]?(\d+\.\d+\.\d+)/i) || html.match(/jQuery\s+v?(\d+\.\d+\.\d+)/i);
  if (jq) {
    const ver = jq[1];
    if (cmpVer(ver, '3.5.0') < 0) {
      findings.push(finding('medium', `Outdated jQuery ${ver}`,
        'jQuery before 3.5.0 contains known XSS vulnerabilities (CVE-2020-11022/11023).',
        'Upgrade jQuery to 3.5.0 or later.', `jQuery ${ver}`, null, OWASP.A06));
    } else {
      findings.push(finding('info', `jQuery ${ver} detected`,
        'jQuery version is disclosed; keep it current.',
        'Track jQuery advisories and update regularly.', `jQuery ${ver}`, null, OWASP.A06));
    }
  }
  // AngularJS 1.x (EOL)
  const ng = joined.match(/angular[.-]?(?:js)?[@/]?(\d+\.\d+\.\d+)/i);
  if (ng && cmpVer(ng[1], '2.0.0') < 0) {
    findings.push(finding('medium', `End-of-life AngularJS ${ng[1]}`,
      'AngularJS 1.x reached end-of-life and no longer receives security fixes.',
      'Migrate off AngularJS 1.x to a supported framework.', `AngularJS ${ng[1]}`, null, OWASP.A06));
  }
  // Bootstrap < 4 (XSS in older versions)
  const bs = joined.match(/bootstrap[-.]?(\d+\.\d+\.\d+)/i);
  if (bs && cmpVer(bs[1], '4.3.1') < 0) {
    findings.push(finding('low', `Outdated Bootstrap ${bs[1]}`,
      'Bootstrap before 4.3.1 has known XSS issues in some components.',
      'Upgrade Bootstrap to 4.3.1+ (or current).', `Bootstrap ${bs[1]}`, null, OWASP.A06));
  }
  return findings;
}

function cmpVer(a, b) {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); }
  return 0;
}

// ---- Probe: /.well-known/security.txt ------------------------------------
async function probeSecurityTxt(origin) {
  try {
    const res = await fetchWithTimeout(origin + '/.well-known/security.txt', { method: 'GET', timeout: 7000, redirect: 'manual' });
    // A 3xx means the file exists but is served from a canonical location — treat
    // it as present. Only a genuine 4xx/5xx (or absence) is "missing".
    if (res.status >= 300 && res.status < 400) return [];
    if (res.status !== 200) {
      return [finding('info', 'No security.txt found',
        'There is no /.well-known/security.txt for coordinated vulnerability disclosure (RFC 9116).',
        'Publish a security.txt with a contact for reporting vulnerabilities.', null, null, OWASP.A09)];
    }
  } catch { /* ignore */ }
  return [];
}

// ---- Probe: HTTP TRACE (Cross-Site Tracing) ------------------------------
async function probeTrace(url) {
  try {
    // fetch() cannot send TRACE — use the raw client. A 200 that echoes the
    // request (the TRACE method reflects headers back) confirms XST is possible.
    const res = await rawRequest(url, 'TRACE', 7000);
    if (res.status === 200 && /TRACE\s|via:|x-forwarded|user-agent/i.test(res.body)) {
      return [finding('medium', 'HTTP TRACE method enabled',
        'The server responds to TRACE and echoes the request, enabling Cross-Site Tracing (XST) which can expose headers/cookies.',
        'Disable the TRACE method at the web server.', `HTTP ${res.status}`, null, OWASP.A05)];
    }
  } catch { /* method blocked / connection refused - good */ }
  return [];
}

// ---- Probe: CORS reflection ----------------------------------------------
async function probeCorsReflection(url) {
  const evil = 'https://sentryscan-probe.example';
  try {
    const res = await fetchWithTimeout(url, { method: 'GET', timeout: 7000, redirect: 'manual', headers: { Origin: evil } });
    const acao = res.headers.get('access-control-allow-origin');
    const acac = res.headers.get('access-control-allow-credentials');
    if (acao === evil) {
      const sev = acac === 'true' ? 'high' : 'medium';
      return [finding(sev, 'CORS reflects arbitrary Origin',
        `The server echoed an attacker-supplied Origin in Access-Control-Allow-Origin${acac === 'true' ? ' with credentials allowed' : ''}, letting malicious sites read responses.`,
        'Validate Origin against an allowlist; never reflect arbitrary origins, especially with credentials.', `ACAO: ${acao}`, null, OWASP.A05)];
    }
  } catch { /* ignore */ }
  return [];
}

// ---- Probe: directory listing --------------------------------------------
async function probeDirListing(origin) {
  const dirs = ['/images/', '/uploads/', '/css/', '/js/', '/files/', '/backup/'];
  const out = [];
  await Promise.allSettled(dirs.map(async (d) => {
    try {
      const res = await fetchWithTimeout(origin + d, { method: 'GET', timeout: 6000, redirect: 'manual' });
      if (res.status === 200) {
        const body = (await res.text().catch(() => '')).slice(0, 3000);
        if (/<title>\s*Index of \//i.test(body) || /Directory listing for/i.test(body)) {
          out.push(finding('medium', `Directory listing enabled at ${d}`,
            `${origin + d} returns an auto-generated index, exposing the file structure.`,
            'Disable directory listing (e.g. Options -Indexes in Apache, autoindex off in nginx).',
            origin + d, null, OWASP.A05));
        }
      }
    } catch { /* ignore */ }
  }));
  return out;
}

// ---- Probe: light reflected-XSS + SQL-error signature --------------------
// Only runs when the URL already has query parameters. Single, benign request
// per technique; never submits payloads that execute or modify data.
async function probeInjection(u) {
  const params = [...u.searchParams.keys()];
  if (!params.length) return [];
  const out = [];
  const target = params[0];

  // Reflected-input canary (harmless, non-executing marker)
  try {
    const canary = 'sentryscanXSS9181';
    const test = new URL(u.href);
    test.searchParams.set(target, canary);
    const res = await fetchWithTimeout(test.href, { timeout: 8000, redirect: 'follow' });
    const body = await res.text().catch(() => '');
    if (body.includes(canary)) {
      // Reflected unencoded in an HTML context is the XSS signal.
      const htmlContext = new RegExp('[<>"\'][^<>]{0,40}' + canary + '|' + canary + '[^<>]{0,40}[<>"\']');
      const sev = htmlContext.test(body) ? 'high' : 'low';
      out.push(finding(sev, `Reflected input in response (param "${target}")`,
        'A value supplied in the URL is reflected back in the page. If it is not properly output-encoded, this is a reflected-XSS vector.',
        'Context-aware output-encode all user input and apply a strict CSP.',
        `param=${target}`, null, OWASP.A03,
        { confidence: htmlContext.test(body) ? 'medium' : 'low' }));
    }
  } catch { /* ignore */ }

  // SQL error signature (single quote, non-destructive)
  try {
    const test = new URL(u.href);
    test.searchParams.set(target, (test.searchParams.get(target) || '1') + "'");
    const res = await fetchWithTimeout(test.href, { timeout: 8000, redirect: 'follow' });
    const body = await res.text().catch(() => '');
    if (SQL_ERRORS.some((re) => re.test(body))) {
      out.push(finding('high', `Possible SQL injection (param "${target}")`,
        'Appending a single quote to a parameter triggered a database error message, indicating unsanitized input reaching SQL.',
        'Use parameterized queries / prepared statements and validate input. Verify manually before remediation sign-off.',
        `param=${target}`, null, OWASP.A03, { confidence: 'medium' }));
    }
  } catch { /* ignore */ }

  return out;
}

// ---- Probe: open redirect (A01) ------------------------------------------
// Tests whether a redirect-style parameter sends users to an attacker-chosen
// external host. Single benign request per candidate param; follows nothing.
const REDIRECT_PARAMS = ['next', 'url', 'redirect', 'redirect_uri', 'return', 'returnUrl', 'dest', 'destination', 'continue', 'goto'];
const REDIRECT_CANARY_HOST = 'sentryscan-redirect.example';

async function probeOpenRedirect(u) {
  // Test params already present on the URL, plus a couple of common names on the path.
  const present = [...u.searchParams.keys()].filter((k) => REDIRECT_PARAMS.includes(k.toLowerCase()));
  const candidates = present.length ? present : REDIRECT_PARAMS.slice(0, 3);
  const out = [];
  await Promise.allSettled(candidates.map(async (param) => {
    try {
      const test = new URL(u.href);
      test.searchParams.set(param, `https://${REDIRECT_CANARY_HOST}/`);
      const res = await fetchWithTimeout(test.href, { method: 'GET', timeout: 7000, redirect: 'manual' });
      const loc = res.headers.get('location') || '';
      if (loc && /^(https?:)?\/\//i.test(loc)) {
        try {
          if (new URL(loc, test.href).hostname === REDIRECT_CANARY_HOST) {
            out.push(finding('high', `Open redirect via "${param}" parameter`,
              'A redirect parameter forwards the browser to an arbitrary external host without validation, enabling phishing and OAuth token theft.',
              'Allowlist redirect destinations (relative paths or a fixed set of hosts); never redirect to a raw user-supplied URL.',
              `${param}=https://${REDIRECT_CANARY_HOST}/ → ${loc}`, null, OWASP.A01));
          }
        } catch { /* unparsable Location */ }
      }
    } catch { /* ignore */ }
  }));
  // De-duplicate to a single finding if several params behave the same way.
  return out.slice(0, 1);
}

// ---- Probe: dangerous HTTP methods (A05) ---------------------------------
async function probeHttpMethods(url) {
  try {
    const res = await fetchWithTimeout(url, { method: 'OPTIONS', timeout: 7000, redirect: 'manual' });
    const allow = (res.headers.get('allow') || res.headers.get('access-control-allow-methods') || '').toUpperCase();
    if (!allow) return [];
    const risky = ['PUT', 'DELETE', 'PATCH', 'CONNECT', 'TRACK'].filter((m) => new RegExp(`\\b${m}\\b`).test(allow));
    if (risky.length) {
      return [finding('medium', `Potentially unsafe HTTP methods advertised: ${risky.join(', ')}`,
        'The server advertises state-changing or diagnostic HTTP methods. If they are not authenticated and intended, they can allow content tampering or information disclosure.',
        'Disable HTTP methods the application does not need; restrict write methods to authenticated, authorized callers.',
        `Allow: ${allow}`, null, OWASP.A05)];
    }
  } catch { /* ignore */ }
  return [];
}

// ---- Probe: exposed dev / debug / API-doc endpoints (A05/A06) ------------
const DEV_ENDPOINTS = [
  { path: '/actuator/env', sev: 'high', title: 'Spring Boot Actuator /env exposed', owasp: OWASP.A05, sig: (b) => /"propertySources"|activeProfiles/i.test(b) },
  { path: '/actuator/health', sev: 'low', title: 'Spring Boot Actuator exposed', owasp: OWASP.A05, sig: (b) => /"status"\s*:\s*"(UP|DOWN)"/i.test(b) },
  { path: '/api-docs', sev: 'low', title: 'OpenAPI/Swagger spec exposed', owasp: OWASP.A05, sig: (b) => /"openapi"|"swagger"/i.test(b) },
  { path: '/v2/api-docs', sev: 'low', title: 'OpenAPI/Swagger spec exposed', owasp: OWASP.A05, sig: (b) => /"openapi"|"swagger"/i.test(b) },
  { path: '/swagger-ui.html', sev: 'low', title: 'Swagger UI exposed', owasp: OWASP.A05, sig: (b) => /swagger-ui|Swagger UI/i.test(b) },
  { path: '/.well-known/openid-configuration', sev: 'info', title: 'OpenID configuration exposed', owasp: OWASP.A05, sig: (b) => /authorization_endpoint/i.test(b) }
];

async function probeDevEndpoints(origin) {
  const out = [];
  await Promise.allSettled(DEV_ENDPOINTS.map(async (e) => {
    try {
      const res = await fetchWithTimeout(origin + e.path, { method: 'GET', timeout: 6000, redirect: 'manual' });
      if (res.status !== 200) return;
      const body = (await res.text().catch(() => '')).slice(0, 4000);
      if (e.sig(body)) {
        out.push(finding(e.sev, e.title,
          `${origin + e.path} is publicly reachable and exposes framework/API internals that aid an attacker in reconnaissance.`,
          'Restrict management, debug, and API-doc endpoints to internal networks or authenticated administrators in production.',
          origin + e.path, null, e.owasp));
      }
    } catch { /* ignore */ }
  }));
  return out;
}

// ---- GraphQL introspection (A05) -----------------------------------------
async function probeGraphql(origin) {
  const query = '{"query":"{__schema{queryType{name}}}"}';
  for (const path of ['/graphql', '/api/graphql', '/v1/graphql']) {
    try {
      const res = await fetchWithTimeout(origin + path, {
        method: 'POST', timeout: 6000, redirect: 'manual',
        headers: { 'Content-Type': 'application/json' }, body: query
      });
      if (res.status !== 200) continue;
      const body = (await res.text().catch(() => '')).slice(0, 4000);
      if (/"__schema"|"queryType"/.test(body)) {
        return [finding('medium', 'GraphQL introspection enabled',
          `${origin + path} answers introspection queries, revealing the full API schema (types, fields, mutations) to attackers.`,
          'Disable introspection in production or require authentication for the GraphQL endpoint.',
          origin + path, null, OWASP.A05)];
      }
    } catch { /* ignore */ }
  }
  return [];
}
