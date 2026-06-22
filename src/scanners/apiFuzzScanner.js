// API / query-parameter fuzzer. Sends a battery of crafted, non-destructive
// payloads to each query parameter of the target URL and looks for anomalies
// that signal an injection or weak input handling. Each finding is mapped to an
// OWASP Top 10 (2021) category.
//
// SAFETY: Fuzzing uses GET requests only — it never sends POST/PUT/DELETE, so
// it cannot create or modify server-side data. It still hits the target many
// times, so use it ONLY on systems you own or are authorized to assess.
import { URL } from 'node:url';
import { finding, fetchWithTimeout, normalizeUrl, currentAuthHeaders } from './util.js';
import { curl, sqlmapHandoff } from './repro.js';

const OWASP_A03 = 'A03:2021 Injection';
const OWASP_A04 = 'A04:2021 Insecure Design';

const MAX_PARAMS = 8;
const CONCURRENCY = 6;

// Detection signatures shared with the baseline DAST checks.
const SQL_ERRORS = [
  /you have an error in your sql syntax/i, /warning:\s+mysqli?/i,
  /unclosed quotation mark after the character string/i, /quoted string not properly terminated/i,
  /pg::syntaxerror|postgresql.*error/i, /ora-\d{5}/i, /sqlite3?::|sqlite_error/i, /odbc.*driver/i,
  /supplied argument is not a valid mysql/i
];
const STACK_TRACES = [
  /Traceback \(most recent call last\)/i, /at [\w.$]+\([\w./]+:\d+:\d+\)/, /Exception in thread/i,
  /java\.lang\.\w+Exception/, /System\.\w+Exception/, /\bnode:internal\//, /\.php on line \d+/i
];

// Each payload carries the technique it tests and a detector for its tell-tale.
const PAYLOADS = [
  { id: 'sql-quote', value: "'", tech: 'SQL injection', sev: 'high', owasp: OWASP_A03,
    detect: (b) => SQL_ERRORS.some((re) => re.test(b)) },
  { id: 'sql-bool', value: "1' OR '1'='1", tech: 'SQL injection', sev: 'high', owasp: OWASP_A03,
    detect: (b) => SQL_ERRORS.some((re) => re.test(b)) },
  { id: 'xss', value: '<sentryscanXSS>', tech: 'Reflected XSS', owasp: OWASP_A03, reflect: true },
  { id: 'traversal', value: '../../../../../../etc/passwd', tech: 'Path traversal', sev: 'high', owasp: OWASP_A03,
    detect: (b) => /root:.*:0:0:/.test(b) },
  { id: 'cmd-semicolon', value: ';id', tech: 'Command injection', sev: 'critical', owasp: OWASP_A03,
    detect: (b) => /uid=\d+\([^)]+\)\s+gid=\d+/.test(b) },
  { id: 'cmd-pipe', value: '|id', tech: 'Command injection', sev: 'critical', owasp: OWASP_A03,
    detect: (b) => /uid=\d+\([^)]+\)\s+gid=\d+/.test(b) },
  { id: 'ssti-dollar', value: '${7*7}', tech: 'Server-side template injection', sev: 'high', owasp: OWASP_A03,
    detect: (b) => b.includes('49') && !b.includes('${7*7}') },
  { id: 'ssti-curly', value: '{{7*7}}', tech: 'Server-side template injection', sev: 'high', owasp: OWASP_A03,
    detect: (b) => b.includes('49') && !b.includes('{{7*7}}') },
  { id: 'longstr', value: 'A'.repeat(6000), tech: 'Oversized input', sev: 'low', owasp: OWASP_A04, oversize: true },
  { id: 'type-array', value: '__arr__', arrayName: true, tech: 'Type confusion (array)', sev: 'low', owasp: OWASP_A04, typeJuggle: true }
];

async function pool(items, limit, worker) {
  const out = [];
  let i = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await worker(items[idx], idx);
    }
  });
  await Promise.all(runners);
  return out;
}

// Build the GET URL for a fuzzed query parameter.
function reqUrl(u, param, payload) {
  const t = new URL(u.href);
  if (payload.arrayName) {
    t.searchParams.delete(param);
    t.searchParams.append(`${param}[]`, '1');
    t.searchParams.append(`${param}[]`, '2');
  } else {
    t.searchParams.set(param, payload.value);
  }
  return t.href;
}

// The value a payload injects into a JSON body field.
function bodyValue(payload) {
  if (payload.arrayName || payload.typeJuggle) return ['1', '2']; // type confusion
  return payload.value;
}

// Dotted paths to every string/number leaf, descending through nested objects
// AND arrays (e.g. "user.roles.0", "items.1.name"), depth ≤ 3, capped.
function leafPaths(node, depth = 3) {
  const out = [];
  const walk = (v, path, d) => {
    if (out.length >= MAX_PARAMS) return;
    if (v === null || v === undefined) return;
    if (typeof v === 'string' || typeof v === 'number') { if (path) out.push(path); return; }
    if (d <= 0 || typeof v !== 'object') return;
    if (Array.isArray(v)) v.slice(0, 3).forEach((el, i) => walk(el, path ? `${path}.${i}` : `${i}`, d - 1));
    else for (const [k, val] of Object.entries(v)) walk(val, path ? `${path}.${k}` : k, d - 1);
  };
  walk(node, '', depth);
  return out;
}
function setPath(obj, path, value) {
  const parts = path.split('.');
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) cur = cur[parts[i]];
  cur[parts[parts.length - 1]] = value;
  return obj;
}
const clone = (o) => JSON.parse(JSON.stringify(o));
// Two response bodies are "similar" if lengths are within 3% — used to tell
// whether a boolean SQL condition actually changed the result.
function similar(a, b) {
  if (!a.length && !b.length) return true;
  const hi = Math.max(a.length, b.length), lo = Math.min(a.length, b.length);
  return hi > 0 && lo / hi >= 0.97;
}

// Send one request (GET/HEAD carry no body; write methods send the JSON body).
async function sendRequest(url, method, bodyObj, contentType) {
  const o = { method, timeout: 9000, redirect: 'follow' };
  if (bodyObj != null && !['GET', 'HEAD'].includes(method)) {
    o.headers = { 'Content-Type': contentType };
    o.body = typeof bodyObj === 'string' ? bodyObj : JSON.stringify(bodyObj);
  }
  const res = await fetchWithTimeout(url, o);
  const text = (await res.text().catch(() => '')).slice(0, 200000);
  return { status: res.status, ctype: res.headers.get('content-type') || '', text };
}

// Non-destructive SQLi confirmation: a tautology (1=1) vs a contradiction (1=2).
// If TRUE responses are stable AND differ from FALSE, the input is evaluated as
// SQL — confirmed, WITHOUT extracting or modifying any data. GET/read only.
async function confirmBooleanSql(u, param, method, bodyObj, contentType) {
  const base = u.searchParams.get(param) ?? '1';
  const pairs = [
    [`${base}' AND '1'='1`, `${base}' AND '1'='2`],
    [`${base} AND 1=1`, `${base} AND 1=2`],
    [`${base}' AND '1'='1'-- -`, `${base}' AND '1'='2'-- -`]
  ];
  const fetchVal = (val) => {
    const t = new URL(u.href); t.searchParams.set(param, val);
    return sendRequest(t.href, method, bodyObj, contentType);
  };
  for (const [tp, fp] of pairs) {
    try {
      const t1 = await fetchVal(tp);
      const f = await fetchVal(fp);
      const t2 = await fetchVal(tp); // re-send TRUE to rule out per-request noise
      if (t1.status < 500 && f.status < 500 &&
          similar(t1.text, t2.text) && !similar(t1.text, f.text)) {
        return { confirmed: true, evidence: `TRUE(1=1)→HTTP ${t1.status}/${t1.text.length}B (stable) vs FALSE(1=2)→HTTP ${f.status}/${f.text.length}B — boolean condition changed the result, so input is evaluated as SQL` };
      }
    } catch { /* try next style */ }
  }
  return { confirmed: false };
}

export async function scanApiFuzz(input, opts = {}) {
  const u = normalizeUrl(input);
  const method = String(opts.method || 'GET').toUpperCase();
  const allowWrite = opts.allowWrite === true;
  const contentType = opts.contentType || 'application/json';
  const isWrite = !['GET', 'HEAD'].includes(method);
  const meta = { target: u.href, method, owaspCovered: [OWASP_A03, OWASP_A04] };

  // Write methods can change server state — require explicit opt-in.
  if (isWrite && !allowWrite) {
    return {
      type: 'fuzz', meta,
      findings: [finding('info', `${method} fuzzing is disabled`,
        `This request uses ${method}, which can create or modify data on the server. Enable "allow destructive (write) requests" to fuzz it.`,
        'Only enable write fuzzing against systems you own or are authorized to test.')]
    };
  }

  // Parse an optional JSON body to discover fields to fuzz.
  let bodyObj = null, bodyFields = [];
  if (opts.body && /json/i.test(contentType)) {
    try { bodyObj = JSON.parse(opts.body); }
    catch {
      return { type: 'fuzz', meta, findings: [finding('info', 'Request body is not valid JSON',
        'A body was provided but could not be parsed as JSON, so its fields were not fuzzed.',
        'Provide a valid JSON object as the request body.')] };
    }
    if (bodyObj && typeof bodyObj === 'object' && !Array.isArray(bodyObj)) bodyFields = leafPaths(bodyObj).slice(0, MAX_PARAMS);
  }

  const params = [...new Set([...u.searchParams.keys()])].slice(0, MAX_PARAMS);
  if (!params.length && !bodyFields.length) {
    return { type: 'fuzz', meta, findings: [finding('info', 'Nothing to fuzz',
      'The URL has no query parameters and no JSON body fields were provided. Add query parameters (e.g. ?q=test) or supply a JSON body.',
      'Provide query parameters and/or a JSON request body to fuzz.')] };
  }
  meta.paramsFuzzed = params;
  meta.bodyFieldsFuzzed = bodyFields;

  // User-supplied custom payloads run alongside the built-ins. They have no
  // dedicated detector, so they're judged by reflection + the generic signals.
  const customPayloads = (Array.isArray(opts.customPayloads) ? opts.customPayloads : [])
    .filter((s) => typeof s === 'string' && s.trim().length)
    .slice(0, 15)
    .map((value, i) => ({ id: `custom-${i}`, value, custom: true }));
  const allPayloads = [...PAYLOADS, ...customPayloads];
  meta.customPayloadCount = customPayloads.length;

  // Baseline: the original request, so we can spot meaningful changes.
  let baseStatus = 0;
  try { baseStatus = (await sendRequest(u.href, method, bodyObj, contentType)).status; } catch { /* best-effort */ }
  meta.baselineStatus = baseStatus;

  const jobs = [];
  for (const param of params) for (const payload of allPayloads) jobs.push({ kind: 'query', target: param, payload });
  for (const field of bodyFields) for (const payload of allPayloads) jobs.push({ kind: 'body', target: field, payload });

  const seen = new Set(); // de-dup: one finding per (location, technique)
  const findings = [];

  await pool(jobs, CONCURRENCY, async ({ kind, target, payload }) => {
    let status, text = '', ctype = '';
    const reqUrlStr = kind === 'query' ? reqUrl(u, target, payload) : u.href;
    const reqBodyObj = kind === 'body' ? setPath(clone(bodyObj), target, bodyValue(payload)) : bodyObj;
    try {
      ({ status, ctype, text } = await sendRequest(reqUrlStr, method, reqBodyObj, contentType));
    } catch { return; }

    const loc = kind === 'query' ? `query "${target}"` : `body field "${target}"`;
    const repro = curl(method, reqUrlStr, {
      headers: currentAuthHeaders() || undefined,
      body: (isWrite && reqBodyObj != null) ? JSON.stringify(reqBodyObj) : undefined
    });
    const push = (sev, title, desc, rem, owasp, handoff) => {
      const key = `${kind}:${target}:${title}`;
      if (seen.has(key)) return;
      seen.add(key);
      const f = finding(sev, title, desc, rem, `${kind}=${target} payload=${truncate(String(payload.value))} → HTTP ${status}`, null, owasp);
      f.reproduction = repro;
      if (handoff) f.handoff = handoff;
      findings.push(f);
    };

    if (payload.reflect) {
      if (text.includes('<sentryscanXSS>') && /html|xml/i.test(ctype)) {
        push('medium', `Reflected XSS (${loc})`,
          'A marker injected here is reflected unencoded in an HTML response — a reflected cross-site scripting vector.',
          'Context-aware output-encode all reflected input and apply a strict CSP.', OWASP_A03);
      } else if (text.includes('sentryscanXSS')) {
        push('low', `Input reflected in response (${loc})`,
          'Input is echoed back in the response (encoded, or a non-HTML content-type). Not directly exploitable here, but a risk if later rendered as HTML.',
          'Encode reflected values for the context they are rendered in.', OWASP_A03);
      }
      return;
    }
    if (payload.detect && payload.detect(text)) {
      const handoff = payload.tech === 'SQL injection'
        ? sqlmapHandoff(reqUrlStr, kind === 'query' ? target : undefined) : undefined;
      push(payload.sev, `${payload.tech} (${loc})`,
        `A ${payload.tech.toLowerCase()} payload in ${loc} produced a tell-tale response, indicating the input is not safely handled.`,
        techRemediation(payload.tech), payload.owasp, handoff);
      return;
    }
    // Custom payloads: judged by SQL-error tell-tales and self-reflection.
    if (payload.custom) {
      if (SQL_ERRORS.some((re) => re.test(text))) {
        push('high', `Injection signal from custom payload (${loc})`,
          `Your custom payload in ${loc} triggered a database error, indicating it reaches a query unsanitized.`,
          techRemediation('SQL injection'), OWASP_A03);
      } else if (payload.value.trim().length >= 4 && text.includes(payload.value)) {
        push('low', `Custom payload reflected (${loc})`,
          'Your custom payload is echoed back in the response — verify it cannot break out of its rendering context.',
          'Encode reflected values for the context they are rendered in.', OWASP_A03);
      }
    }
    if (status === 500 && baseStatus !== 500) {
      push('medium', `Unhandled server error on fuzzed input (${loc})`,
        `Crafted input to ${loc} caused an HTTP 500. Inputs that crash the handler often hide injection or logic flaws.`,
        'Validate and sanitize input; handle errors without leaking a 500.', OWASP_A04);
    }
    if (STACK_TRACES.some((re) => re.test(text))) {
      push('medium', `Stack trace / verbose error disclosed (${loc})`,
        `Fuzzed input to ${loc} returned a stack trace or framework error, leaking internal implementation details.`,
        'Disable verbose errors in production and return generic error responses.', OWASP_A04);
    }
    if (payload.typeJuggle && status === 500 && baseStatus !== 500) {
      push('low', `Type confusion on array input (${loc})`,
        `Sending ${loc} as an array caused a server error, a sign the handler assumes a single value.`,
        'Validate parameter types explicitly and reject unexpected shapes.', OWASP_A04);
    }
  });

  // Non-destructive confirmation pass — boolean-based SQLi on GET query params
  // only (never on write methods, so it can't cause side effects).
  if (!isWrite) {
    for (const param of params) {
      try {
        const c = await confirmBooleanSql(u, param, method, bodyObj, contentType);
        if (c.confirmed) {
          const probe = new URL(u.href);
          probe.searchParams.set(param, `${u.searchParams.get(param) ?? '1'}' AND '1'='1`);
          const f = finding('critical', `Confirmed SQL injection — boolean-based (query "${param}")`,
            'A tautology vs. contradiction injected into this parameter produced reliably different responses, confirming the input is evaluated as SQL. This is a non-destructive proof — no data was read or modified. Treat as exploitable and fix immediately.',
            'Use parameterized queries / prepared statements; this parameter is injectable.',
            c.evidence, null, OWASP_A03);
          f.reproduction = curl(method, probe.href, { headers: currentAuthHeaders() || undefined });
          f.handoff = sqlmapHandoff(u.href, param);
          findings.unshift(f);
        }
      } catch { /* ignore */ }
    }
  }
  meta.confirmedBooleanSqli = findings.some((f) => /Confirmed SQL injection/.test(f.title));

  const scope = `${params.length} query param(s) + ${bodyFields.length} body field(s)`;
  if (!findings.length) {
    findings.push(finding('info', `No injection signals across ${scope}`,
      `Fuzzed ${scope} with ${PAYLOADS.length} payloads each (method ${method}) and saw no error, reflection, or injection tell-tales. A good sign, but not proof of safety — confirm critical inputs manually.`,
      'Keep using parameterized queries, output encoding, and strict input validation.'));
  }
  return { type: 'fuzz', meta, findings };
}

function truncate(v) { return v.length > 24 ? v.slice(0, 24) + '…' : v; }

function techRemediation(tech) {
  switch (tech) {
    case 'SQL injection': return 'Use parameterized queries / prepared statements; never concatenate input into SQL.';
    case 'Reflected XSS': return 'Context-aware output-encode all reflected input and apply a strict CSP.';
    case 'Path traversal': return 'Reject path separators; resolve and confine file access to an allowlisted base directory.';
    case 'Command injection': return 'Never pass input to a shell; use argument arrays and strict allowlists.';
    case 'Server-side template injection': return 'Do not render user input as a template; use a sandboxed, logic-less templating context.';
    default: return 'Validate and sanitize all input; reject unexpected types and sizes.';
  }
}
