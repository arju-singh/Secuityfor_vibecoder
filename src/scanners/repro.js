// Build copy-paste reproduction commands for findings. These are STRINGS for a
// human to run under their own authorization — nothing here sends any request.
// Credential header values are redacted so exported reports never leak tokens.

const SENSITIVE = /^(authorization|cookie|x-api-key|x-auth-token|x-access-token|token|api-key)$/i;

function shq(s) { return `'` + String(s).replace(/'/g, `'\\''`) + `'`; }

function headerArgs(headers) {
  const out = [];
  for (const [k, v] of Object.entries(headers || {})) {
    const val = SENSITIVE.test(k) ? '<your-credential>' : v;
    out.push('-H', shq(`${k}: ${val}`));
  }
  return out;
}

// A curl command reproducing one request.
export function curl(method, url, { headers, body } = {}) {
  const m = String(method || 'GET').toUpperCase();
  const parts = ['curl', '-i'];
  if (m !== 'GET') parts.push('-X', m);
  parts.push(...headerArgs(headers));
  if (body != null) parts.push('-H', shq('Content-Type: application/json'), '--data', shq(body));
  parts.push(shq(url));
  return parts.join(' ');
}

// Hand-off to sqlmap for an authorized SQL-injection confirmation/exploitation.
export function sqlmapHandoff(url, param) {
  return `sqlmap -u ${shq(url)}${param ? ` -p ${param}` : ''} --batch    # run ONLY against systems you are authorized to test`;
}
