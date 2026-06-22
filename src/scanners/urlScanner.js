// Live-URL security scanner. Uses Node's native fetch and tls module only.
import tls from 'node:tls';
import { URL } from 'node:url';

const UA = 'SentryScan/1.0 (+security-audit)';
const TIMEOUT_MS = 12000;

function finding(severity, title, description, remediation, evidence) {
  return { severity, title, description, remediation, evidence: evidence || null };
}

async function fetchWithTimeout(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), opts.timeout || TIMEOUT_MS);
  try {
    return await fetch(url, {
      ...opts,
      signal: ctrl.signal,
      redirect: opts.redirect || 'manual',
      headers: { 'User-Agent': UA, ...(opts.headers || {}) }
    });
  } finally {
    clearTimeout(t);
  }
}

function normalizeUrl(input) {
  let raw = String(input || '').trim();
  if (!raw) throw new Error('No URL provided.');
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  const u = new URL(raw);
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http and https URLs are supported.');
  // Block obvious SSRF targets against the host running the scanner.
  const host = u.hostname.toLowerCase();
  const blocked = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '169.254.169.254'];
  if (blocked.includes(host) || /^(?:10|127)\./.test(host) || /^192\.168\./.test(host) ||
      /^172\.(1[6-9]|2[0-9]|3[01])\./.test(host)) {
    throw new Error('Scanning of localhost / private network addresses is not allowed.');
  }
  return u;
}

// --- TLS certificate inspection -------------------------------------------
function inspectTls(hostname, port = 443) {
  return new Promise((resolve) => {
    const findings = [];
    let settled = false;
    const done = (cert, protocol) => {
      if (settled) return;
      settled = true;
      resolve({ findings, cert, protocol });
    };
    try {
      const socket = tls.connect(
        { host: hostname, port, servername: hostname, timeout: TIMEOUT_MS, rejectUnauthorized: false },
        () => {
          const cert = socket.getPeerCertificate(false);
          const protocol = socket.getProtocol();
          const authorized = socket.authorized;
          const authError = socket.authorizationError;

          if (!authorized) {
            findings.push(finding('high', 'TLS certificate not trusted',
              `The certificate chain could not be validated (${authError || 'unknown error'}).`,
              'Install a valid certificate from a trusted CA (e.g. Let’s Encrypt) and serve the full chain.',
              String(authError || '')));
          }
          if (cert && cert.valid_to) {
            const expiry = new Date(cert.valid_to);
            const days = Math.round((expiry - Date.now()) / 86400000);
            if (days < 0) {
              findings.push(finding('critical', 'TLS certificate expired',
                `The certificate expired on ${expiry.toUTCString()}.`,
                'Renew the certificate immediately; browsers will block the site.', cert.valid_to));
            } else if (days < 15) {
              findings.push(finding('medium', 'TLS certificate expiring soon',
                `The certificate expires in ${days} day(s) (${expiry.toUTCString()}).`,
                'Renew and automate certificate renewal to avoid downtime.', cert.valid_to));
            }
          }
          if (protocol && /TLSv1(\.0)?$|TLSv1\.1/.test(protocol)) {
            findings.push(finding('medium', `Weak TLS protocol (${protocol})`,
              'The server negotiated a deprecated TLS version.',
              'Disable TLS 1.0/1.1 and require TLS 1.2 or higher.', protocol));
          }
          socket.end();
          done(cert, protocol);
        }
      );
      socket.on('error', (e) => {
        findings.push(finding('high', 'TLS handshake failed',
          `Could not establish a secure connection: ${e.message}.`,
          'Verify HTTPS is configured correctly on the server.', e.message));
        done(null, null);
      });
      socket.on('timeout', () => { socket.destroy(); done(null, null); });
    } catch (e) {
      done(null, null);
    }
  });
}

// --- Security header checks -----------------------------------------------
function checkHeaders(headers, isHttps) {
  const findings = [];
  const get = (n) => headers.get(n);

  if (isHttps && !get('strict-transport-security')) {
    findings.push(finding('high', 'Missing HSTS header',
      'Strict-Transport-Security is not set, so browsers may connect over plain HTTP.',
      'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'));
  }
  if (!get('content-security-policy')) {
    findings.push(finding('high', 'Missing Content-Security-Policy',
      'No CSP header was found. CSP is the strongest defense against XSS and data injection.',
      "Define a restrictive policy, e.g. Content-Security-Policy: default-src 'self'; object-src 'none'"));
  }
  if (!get('x-content-type-options')) {
    findings.push(finding('medium', 'Missing X-Content-Type-Options',
      'Browsers may MIME-sniff responses, enabling some content-injection attacks.',
      'Add: X-Content-Type-Options: nosniff'));
  }
  const xfo = get('x-frame-options');
  const csp = get('content-security-policy') || '';
  if (!xfo && !/frame-ancestors/i.test(csp)) {
    findings.push(finding('medium', 'Clickjacking protection missing',
      'Neither X-Frame-Options nor CSP frame-ancestors is set; the page can be framed by attackers.',
      "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."));
  }
  if (!get('referrer-policy')) {
    findings.push(finding('low', 'Missing Referrer-Policy',
      'Full referrer URLs may leak to third parties.',
      'Add: Referrer-Policy: strict-origin-when-cross-origin'));
  }
  if (!get('permissions-policy')) {
    findings.push(finding('low', 'Missing Permissions-Policy',
      'Powerful browser features (camera, geolocation, etc.) are not restricted.',
      'Add a Permissions-Policy header disabling features you do not use.'));
  }

  // Information disclosure
  const server = get('server');
  if (server && /\d/.test(server)) {
    findings.push(finding('low', 'Server version disclosed',
      `The Server header reveals software version: "${server}".`,
      'Suppress or genericize the Server header to slow down targeted attacks.', server));
  }
  const powered = get('x-powered-by');
  if (powered) {
    findings.push(finding('low', 'X-Powered-By header disclosed',
      `Technology stack disclosed: "${powered}".`,
      'Remove the X-Powered-By header (e.g. app.disable("x-powered-by") in Express).', powered));
  }

  // CORS
  const acao = get('access-control-allow-origin');
  if (acao === '*' && get('access-control-allow-credentials') === 'true') {
    findings.push(finding('high', 'Insecure CORS configuration',
      'Access-Control-Allow-Origin is "*" together with Allow-Credentials: true, which browsers forbid and indicates misconfiguration exposing credentialed data.',
      'Echo a specific allowed origin instead of "*" when credentials are allowed.', acao));
  } else if (acao === '*') {
    findings.push(finding('low', 'Wildcard CORS policy',
      'Access-Control-Allow-Origin is "*"; any site can read responses from this endpoint.',
      'Restrict CORS to trusted origins for any non-public data.', acao));
  }

  // Cookies
  const setCookie = headers.getSetCookie ? headers.getSetCookie() : (get('set-cookie') ? [get('set-cookie')] : []);
  for (const c of setCookie) {
    const name = (c.split('=')[0] || 'cookie').trim();
    const flags = c.toLowerCase();
    const missing = [];
    if (isHttps && !flags.includes('secure')) missing.push('Secure');
    if (!flags.includes('httponly')) missing.push('HttpOnly');
    if (!flags.includes('samesite')) missing.push('SameSite');
    if (missing.length) {
      findings.push(finding('medium', `Cookie "${name}" missing flags: ${missing.join(', ')}`,
        'Cookies without these flags are exposed to theft via XSS, interception, or CSRF.',
        `Set the ${missing.join(', ')} attribute(s) on this cookie.`, c.slice(0, 120)));
    }
  }
  return findings;
}

// --- Exposed sensitive paths ----------------------------------------------
const SENSITIVE_PATHS = [
  { path: '/.env', severity: 'critical', title: 'Exposed .env file' },
  { path: '/.git/config', severity: 'critical', title: 'Exposed .git repository' },
  { path: '/.git/HEAD', severity: 'critical', title: 'Exposed .git/HEAD' },
  { path: '/config.php', severity: 'high', title: 'Exposed config.php' },
  { path: '/wp-config.php.bak', severity: 'critical', title: 'Exposed WordPress config backup' },
  { path: '/.htaccess', severity: 'medium', title: 'Readable .htaccess' },
  { path: '/phpinfo.php', severity: 'high', title: 'Exposed phpinfo()' },
  { path: '/.DS_Store', severity: 'low', title: 'Exposed .DS_Store' },
  { path: '/backup.zip', severity: 'high', title: 'Exposed backup.zip' },
  { path: '/.svn/entries', severity: 'high', title: 'Exposed .svn metadata' },
  { path: '/server-status', severity: 'medium', title: 'Exposed Apache server-status' }
];

async function checkExposedPaths(origin) {
  const findings = [];
  const looksReal = (path, text, ctype) => {
    if (path.includes('.env')) return /[A-Z0-9_]+=/.test(text);
    if (path.includes('.git/config')) return /\[core\]|repositoryformatversion/i.test(text);
    if (path.includes('.git/HEAD')) return /^ref:\s/m.test(text);
    if (path.includes('phpinfo')) return /phpinfo\(\)|PHP Version/i.test(text);
    if (path.includes('.DS_Store')) return /Bud1|\x00\x00\x00/.test(text);
    if (path.includes('.htaccess')) return /RewriteEngine|Order |Deny |Require /i.test(text);
    if (path.includes('server-status')) return /Apache Server Status/i.test(text);
    if (path.endsWith('.zip')) return /application\/zip|application\/octet-stream/i.test(ctype || '');
    if (path.includes('config.php')) return ctype && !/text\/html/i.test(ctype) && text.length > 0;
    if (path.includes('.svn')) return /dir|file/i.test(text);
    return false;
  };
  const tasks = SENSITIVE_PATHS.map(async (p) => {
    try {
      const res = await fetchWithTimeout(origin + p.path, { redirect: 'manual', timeout: 8000 });
      if (res.status !== 200) return;
      const ctype = res.headers.get('content-type') || '';
      const body = await res.text().catch(() => '');
      const sample = body.slice(0, 4000);
      // A custom 200 error page would not match the content signature.
      if (looksReal(p.path, sample, ctype)) {
        findings.push(finding(p.severity, p.title,
          `${origin + p.path} is publicly accessible and returns sensitive content.`,
          'Block access to this path at the web-server level or remove the file from the web root.',
          (origin + p.path)));
      }
    } catch { /* unreachable path - ignore */ }
  });
  await Promise.allSettled(tasks);
  return findings;
}

// --- Mixed content (HTML body) --------------------------------------------
function checkMixedContent(html, isHttps) {
  const findings = [];
  if (!isHttps || !html) return findings;
  const matches = html.match(/(?:src|href)\s*=\s*["']http:\/\/(?!localhost)[^"']+/gi) || [];
  if (matches.length) {
    const sample = [...new Set(matches.map(m => m.replace(/^[^h]*/, '')))].slice(0, 5);
    findings.push(finding('medium', `Mixed content: ${matches.length} insecure resource(s)`,
      'The HTTPS page loads resources over plain HTTP, which browsers block or downgrade security for.',
      'Serve all scripts, styles, images, and links over HTTPS.', sample.join('\n')));
  }
  // Inline secrets in the served HTML/JS
  if (/AIza[0-9A-Za-z\-_]{35}/.test(html)) {
    findings.push(finding('medium', 'API key exposed in page source',
      'A Google API key pattern was found directly in the served HTML/JS.',
      'Restrict the key and avoid embedding privileged keys in client code.'));
  }
  return findings;
}

export async function scanUrl(input) {
  const u = normalizeUrl(input);
  const origin = u.origin;
  const isHttps = u.protocol === 'https:';
  const findings = [];
  const meta = { target: u.href, finalUrl: u.href, statusChain: [] };

  // 1) HTTP -> HTTPS redirect behaviour
  try {
    const httpRes = await fetchWithTimeout('http://' + u.host + u.pathname, { redirect: 'manual', timeout: 8000 });
    const loc = httpRes.headers.get('location') || '';
    if (httpRes.status >= 300 && httpRes.status < 400 && /^https:/i.test(loc)) {
      // good
    } else if (httpRes.status === 200) {
      // HTTPS works (we reached the https URL), but http:// is also served
      // without redirecting — the initial plain-HTTP request is MITM-exposed.
      findings.push(finding(isHttps ? 'medium' : 'high', 'No HTTP→HTTPS redirect',
        'The plain-HTTP endpoint returns content directly instead of redirecting to HTTPS, so a user’s first request can be intercepted (SSL stripping).',
        'Force an HTTP→HTTPS 301 redirect for all traffic and enable HSTS.'));
    }
  } catch { /* http may be closed entirely, which is fine */ }

  // 2) Main request (follow redirects to landing page)
  let res, html = '';
  try {
    res = await fetchWithTimeout(u.href, { redirect: 'follow', timeout: TIMEOUT_MS });
    meta.finalUrl = res.url;
    meta.status = res.status;
    const ctype = res.headers.get('content-type') || '';
    if (/text\/html|application\/xhtml/i.test(ctype)) {
      html = (await res.text().catch(() => '')).slice(0, 500000);
    }
  } catch (e) {
    throw new Error(`Could not reach ${u.href}: ${e.message}`);
  }

  // 3) Header analysis
  findings.push(...checkHeaders(res.headers, new URL(meta.finalUrl).protocol === 'https:'));

  // 4) Mixed content + inline secrets
  findings.push(...checkMixedContent(html, new URL(meta.finalUrl).protocol === 'https:'));

  // 5) TLS + exposed paths in parallel
  const [tlsResult, pathFindings] = await Promise.all([
    isHttps ? inspectTls(u.hostname, u.port ? Number(u.port) : 443) : Promise.resolve({ findings: [], cert: null, protocol: null }),
    checkExposedPaths(origin)
  ]);
  findings.push(...tlsResult.findings);
  findings.push(...pathFindings);

  if (tlsResult.cert && tlsResult.cert.subject) {
    meta.tls = {
      issuer: tlsResult.cert.issuer && tlsResult.cert.issuer.O,
      validTo: tlsResult.cert.valid_to,
      protocol: tlsResult.protocol
    };
  }

  return { type: 'url', meta, findings };
}
