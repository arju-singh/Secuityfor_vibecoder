'use strict';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS = {
  critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)',
  low: 'var(--low)', info: 'var(--info)'
};
const CAT_LABELS = { ui: 'UI', security: 'Security', vuln: 'Vulnerabilities', render: 'Render', api: 'API', code: 'Code', fuzz: 'Fuzzing', access: 'Access control', spec: 'API surface', perf: 'Performance', a11y: 'Accessibility', seo: 'SEO', quality: 'Code quality', frontend: 'Frontend', config: 'Config & DevOps', testing: 'Testing', hygiene: 'Project hygiene', seccode: 'Code security', deps: 'Dependencies' };
const CAT_ICONS = { ui: '🧩', security: '🛡️', vuln: '🎯', render: '🖥️', api: '🔌', code: '📦', fuzz: '🧬', access: '🔓', spec: '📜', perf: '⚡', a11y: '♿', seo: '🔎', quality: '🧹', frontend: '🎨', config: '⚙️', testing: '🧪', hygiene: '📋', seccode: '🔐', deps: '📦' };

// Parse a "Name: value" textarea into a headers object for authenticated scans.
function parseAuthHeaders(id) {
  const el = document.getElementById(id);
  if (!el || !el.value.trim()) return undefined;
  const headers = {};
  el.value.split(/\r?\n/).forEach((line) => {
    const i = line.indexOf(':');
    if (i === -1) return;
    const name = line.slice(0, i).trim();
    const value = line.slice(i + 1).trim();
    if (name && value) headers[name] = value;
  });
  return Object.keys(headers).length ? headers : undefined;
}

let allFindings = [];
let categories = [];
let activeSev = 'all';
let activeCat = 'all';
let selectedFiles = [];
let currentReport = null;

// --- Tabs ------------------------------------------------------------------
document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('panel-' + tab.dataset.tab).classList.add('active');
  });
});

// --- Website test ----------------------------------------------------------
document.getElementById('website-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = document.getElementById('website-input').value.trim();
  if (!url) return;
  const render = document.getElementById('render-toggle').checked;
  const audits = document.getElementById('audits-toggle').checked;
  const authHeaders = parseAuthHeaders('website-auth');
  await runScan('Testing ' + url + ' (UI · security' + (render ? ' · render' : '') + (audits ? ' · audits' : '') + (authHeaders ? ' · authenticated' : '') + ') …', () =>
    fetch('/api/test/website', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, render, audits, headers: authHeaders })
    })
  );
});

// --- API test --------------------------------------------------------------
document.getElementById('api-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = document.getElementById('api-input').value.trim();
  if (!url) return;
  const fuzz = document.getElementById('fuzz-toggle').checked;
  const authHeaders = parseAuthHeaders('api-auth');
  const method = document.getElementById('fuzz-method').value;
  const fuzzBody = document.getElementById('fuzz-body').value.trim() || undefined;
  const allowWrite = document.getElementById('fuzz-allow-write').checked;
  const customPayloads = document.getElementById('fuzz-payloads').value
    .split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const enumerate = document.getElementById('enumerate-toggle').checked;
  const rateLimit = document.getElementById('ratelimit-toggle').checked;
  await runScan('Testing API endpoint ' + url + (fuzz ? ' (with parameter fuzzing)' : '') + ' …', () =>
    fetch('/api/test/api', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, fuzz, headers: authHeaders, method, body: fuzzBody, allowWrite, customPayloads, enumerate, rateLimit })
    })
  );
});

// --- File selection --------------------------------------------------------
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('file-input');
const codeBtn = document.getElementById('code-btn');

document.getElementById('browse-btn').addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => addFiles(fileInput.files));
['dragenter', 'dragover'].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add('dragover'); }));
['dragleave', 'drop'].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove('dragover'); }));
dropzone.addEventListener('drop', (e) => addFiles(e.dataTransfer.files));

function addFiles(fileList) {
  selectedFiles = Array.from(fileList);
  const list = document.getElementById('file-list');
  list.innerHTML = '';
  selectedFiles.forEach((f) => {
    const li = document.createElement('li');
    li.textContent = f.name + '  ·  ' + formatBytes(f.size);
    list.appendChild(li);
  });
  codeBtn.disabled = selectedFiles.length === 0;
}

codeBtn.addEventListener('click', async () => {
  if (!selectedFiles.length) return;
  const fd = new FormData();
  selectedFiles.forEach((f) => fd.append('files', f, f.name));
  await runScan('Analyzing ' + selectedFiles.length + ' file(s) and checking dependencies …', () =>
    fetch('/api/scan/files', { method: 'POST', body: fd }));
});

// --- Runner ----------------------------------------------------------------
async function runScan(loadingText, requestFn) {
  show('loading'); hide('results'); hide('error');
  document.getElementById('loading-text').textContent = loadingText;
  try {
    const res = await requestFn();
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Test failed.');
    renderResults(data);
    saveToHistory(data);
  } catch (err) {
    showError(err.message);
  } finally {
    hide('loading');
  }
}

// --- Rendering -------------------------------------------------------------
function renderResults(data) {
  currentReport = data;
  allFindings = data.findings;
  categories = data.categories || [];
  activeSev = 'all';
  activeCat = 'all';

  const arc = document.getElementById('gauge-arc');
  arc.style.strokeDashoffset = 327 * (1 - data.score / 100);
  arc.style.stroke = data.score >= 80 ? 'var(--accent-2)' : data.score >= 50 ? 'var(--medium)' : 'var(--critical)';
  document.getElementById('score-grade').textContent = data.grade;
  document.getElementById('score-num').textContent = data.score + '/100';

  document.getElementById('result-title').textContent = titleFor(data);
  document.getElementById('result-sub').textContent = subtitleFor(data);

  renderCategorySummary();
  renderFilters(data);
  renderFindings();

  document.getElementById('results').dataset.printed = titleFor(data) + ' · ' + new Date().toLocaleString();
  show('results');
  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function titleFor(data) {
  if (data.type === 'code') return 'Source code analysis';
  return data.meta.finalUrl || data.meta.target || 'Results';
}
function subtitleFor(data) {
  const parts = [data.total + ' finding(s)'];
  if (data.meta && data.meta.authenticated) parts.push('🔐 authenticated');
  if (data.meta && data.meta.fuzzed) parts.push('🧬 fuzzed');
  for (const c of categories) {
    if (c.status === 'error') parts.push(`${CAT_LABELS[c.category]}: unavailable`);
  }
  return parts.join('  ·  ');
}

function renderCategorySummary() {
  const wrap = document.getElementById('cat-summary');
  wrap.innerHTML = '';
  categories.forEach((c) => {
    const card = document.createElement('div');
    card.className = 'cat-card' + (c.status === 'error' ? ' cat-error' : '');
    const worst = worstSeverity(c.counts);
    const dot = c.status === 'error' ? 'var(--muted)' : (worst ? SEV_COLORS[worst] : 'var(--accent-2)');
    let detail;
    if (c.status === 'error') detail = 'unavailable';
    else if (c.total === 0) detail = 'clean';
    else detail = c.total + ' issue(s)';
    card.innerHTML = `<span class="cat-dot" style="background:${dot}"></span>
      <span class="cat-name">${CAT_ICONS[c.category] || ''} ${c.label}</span>
      <span class="cat-detail">${detail}</span>`;
    if (c.status === 'error' && c.error) card.title = c.error;
    // Cards with findings act as a shortcut to that category's filter.
    if (c.status === 'ok' && c.total > 0) {
      card.classList.add('clickable');
      card.title = `Show ${c.total} ${c.label} issue(s)`;
      card.addEventListener('click', () => {
        activeCat = c.category;
        activeSev = 'all';
        setActiveChip('cat', c.category);
        setActiveChip('sev', 'all');
        renderFindings();
        document.querySelector('.filter-bar').scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    }
    wrap.appendChild(card);
  });
}

function renderFilters(data) {
  const filters = document.getElementById('filters');
  filters.innerHTML = '';
  filters.appendChild(sevChip('all', `All (${data.total})`));
  SEVERITIES.forEach((sev) => {
    const n = data.counts[sev] || 0;
    if (n) filters.appendChild(sevChip(sev, `${sev} (${n})`));
  });
  if (categories.length > 1) {
    const sep = document.createElement('span');
    sep.className = 'filter-sep';
    filters.appendChild(sep);
    filters.appendChild(catChip('all', 'all areas'));
    categories.forEach((c) => {
      if (c.total > 0) filters.appendChild(catChip(c.category, `${CAT_ICONS[c.category] || ''} ${CAT_LABELS[c.category]}`));
    });
  }
}

// Reflect the active selection for a chip row (by data-value).
function setActiveChip(kind, value) {
  document.querySelectorAll(`.chip[data-kind="${kind}"]`)
    .forEach((x) => x.classList.toggle('active', x.dataset.value === value));
}

function sevChip(value, label) {
  const c = document.createElement('button');
  c.className = 'chip' + (value === activeSev ? ' active' : '');
  c.textContent = label;
  c.dataset.kind = 'sev';
  c.dataset.value = value;
  c.addEventListener('click', () => {
    // Picking a severity resets the category filter so the result always
    // matches the chip's count (the two rows don't silently AND to empty).
    activeSev = value;
    activeCat = 'all';
    setActiveChip('sev', value);
    setActiveChip('cat', 'all');
    renderFindings();
  });
  return c;
}
function catChip(value, label) {
  const c = document.createElement('button');
  c.className = 'chip cat-chip' + (value === activeCat ? ' active' : '');
  c.textContent = label;
  c.dataset.kind = 'cat';
  c.dataset.value = value;
  c.addEventListener('click', () => {
    // Picking a category resets the severity filter, so clicking a category
    // always shows all of that category's issues (the reported bug).
    activeCat = value;
    activeSev = 'all';
    setActiveChip('cat', value);
    setActiveChip('sev', 'all');
    renderFindings();
  });
  return c;
}

function renderFindings() {
  const container = document.getElementById('findings');
  container.innerHTML = '';
  let items = allFindings;
  if (activeSev !== 'all') items = items.filter((f) => f.severity === activeSev);
  if (activeCat !== 'all') items = items.filter((f) => f.category === activeCat);

  if (!items.length) {
    const div = document.createElement('div');
    div.className = 'clean-state';
    div.textContent = allFindings.length ? 'No findings match this filter.' : '✓ No issues detected.';
    container.appendChild(div);
    return;
  }

  items.forEach((f) => {
    const el = document.createElement('div');
    el.className = 'finding ' + f.severity;
    el.innerHTML = `
      <div class="f-head">
        <span class="f-sev ${f.severity}">${f.severity}</span>
        <span class="f-cat">${CAT_ICONS[f.category] || ''} ${CAT_LABELS[f.category] || f.category}</span>
        ${f.owasp ? `<span class="f-owasp"></span>` : ''}
        <span class="f-title"></span>
        ${f.location ? `<span class="f-loc"></span>` : ''}
      </div>
      <p class="f-desc"></p>
      ${f.evidence ? `<div class="f-evidence"></div>` : ''}
      ${f.remediation ? `<p class="f-fix"><strong>Fix:</strong> <span class="f-fix-text"></span></p>` : ''}
      ${f.reproduction ? `<div class="f-repro"><div class="f-repro-head"><span>↻ Reproduce (curl)</span><button type="button" class="copy-btn">Copy</button></div><pre class="f-repro-code"></pre></div>` : ''}
      ${f.handoff ? `<div class="f-handoff"><strong>Authorized hand-off:</strong> <code class="f-handoff-code"></code></div>` : ''}
    `;
    el.querySelector('.f-title').textContent = f.title;
    if (f.owasp) el.querySelector('.f-owasp').textContent = f.owasp;
    if (f.location) el.querySelector('.f-loc').textContent = f.location;
    el.querySelector('.f-desc').textContent = f.description;
    if (f.evidence) el.querySelector('.f-evidence').textContent = f.evidence;
    if (f.remediation) el.querySelector('.f-fix-text').textContent = f.remediation;
    if (f.reproduction) {
      el.querySelector('.f-repro-code').textContent = f.reproduction;
      el.querySelector('.copy-btn').addEventListener('click', (e) => {
        try {
          if (navigator.clipboard) navigator.clipboard.writeText(f.reproduction).catch(() => {});
        } catch { /* clipboard blocked */ }
        e.target.textContent = 'Copied';
        setTimeout(() => { e.target.textContent = 'Copy'; }, 1200);
      });
    }
    if (f.handoff) el.querySelector('.f-handoff-code').textContent = f.handoff;
    container.appendChild(el);
  });
}

// --- Helpers ---------------------------------------------------------------
function worstSeverity(counts) {
  for (const s of SEVERITIES) if (counts && counts[s]) return s;
  return null;
}
function show(id) { document.getElementById(id).classList.remove('hidden'); }
function hide(id) { document.getElementById(id).classList.add('hidden'); }
function showError(msg) {
  const box = document.getElementById('error');
  box.textContent = '⚠ ' + msg;
  show('error');
}
function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}

// ===========================================================================
// Practice-site presets + Learn/roadmap content
// ===========================================================================

// Public, owner-sanctioned practice targets. `run:true` auto-launches the test.
const WEBSITE_PRESETS = [
  { label: 'SauceDemo (e-commerce UI)', url: 'https://www.saucedemo.com/' },
  { label: 'the-internet (UI edge cases)', url: 'https://the-internet.herokuapp.com/' },
  { label: 'UltimateQA automation', url: 'https://ultimateqa.com/automation' },
  { label: 'DemoQA (widgets)', url: 'https://demoqa.com/' },
  { label: 'ParaBank (banking)', url: 'https://parabank.parasoft.com/parabank/index.htm' },
  { label: 'ACME demo (Applitools)', url: 'https://demo.applitools.com/' },
  { label: 'Swagger PetStore', url: 'https://petstore.swagger.io/' },
  { label: 'OWASP Juice Shop demo', url: 'https://demo.owasp-juice.shop/' }
];
const API_PRESETS = [
  { label: 'JSONPlaceholder', url: 'https://jsonplaceholder.typicode.com/posts/1' },
  { label: 'Restful-Booker', url: 'https://restful-booker.herokuapp.com/booking' },
  { label: 'httpbin /get', url: 'https://httpbin.org/get' },
  { label: 'PetStore /pet/1', url: 'https://petstore.swagger.io/v2/pet/1' },
  { label: 'GitHub API', url: 'https://api.github.com/users/octocat' }
];

const METHODOLOGY = [
  ['Scope & authorize', 'Confirm written authorization and the exact in-scope hosts, apps, and accounts before touching anything.'],
  ['Recon & mapping', 'Enumerate subdomains, technologies, endpoints, and the attack surface (the "Test a website" tab fingerprints stacks, libraries, and exposed files).'],
  ['Vulnerability analysis', 'Probe for the OWASP Top 10 — injection, broken access control, misconfiguration, exposed secrets (SentryScan automates the non-destructive baseline).'],
  ['Exploitation', 'Safely confirm impact of high-signal findings (open redirect, SQLi, XSS) manually — never on production without sign-off.'],
  ['Post-exploitation & impact', 'Assess what an attacker could reach: data, privilege escalation, lateral movement.'],
  ['Report & remediate', 'Document each finding with evidence, severity, and a concrete fix; re-test after remediation.']
];

const BIZLOGIC = [
  ['Map the intended workflow', 'Walk the feature as a normal user first (e.g. cart → checkout → pay → ship). Write down every step, the order it must happen in, and every value the client sends (prices, quantities, IDs, roles, status fields). You can\'t abuse a flow you haven\'t mapped.'],
  ['Skip / reorder steps', 'Try to reach a later step without completing earlier ones — request the "order confirmed" endpoint before paying, or jump straight to a download/receipt URL. If the server trusts the sequence instead of re-checking state, it breaks.'],
  ['Tamper with client-trusted values', 'Intercept requests (Burp/DevTools) and change values the server should never trust: price, total, quantity (try negative or 0), discount, currency, userId, role=admin, isPaid=true. Resubmit and see if the server recomputes or blindly accepts them.'],
  ['Replay & reuse', 'Replay one-time actions: use a coupon/gift card twice, reuse a password-reset or email-verification token, resubmit a "transfer funds" request. Anything meant to work once should fail the second time.'],
  ['Race the state change', 'Fire the same single-use action many times at once (redeem credit, withdraw, claim a seat). If two requests both succeed before the balance/stock updates, that\'s a race condition (SentryScan\'s experimental probe flags a hint; confirm here).'],
  ['Cross-account / authorization (IDOR)', 'With two accounts, take an object ID from account A and access/modify it as account B. Check every object reference — order IDs, file IDs, invoice numbers, user IDs in URLs and bodies.'],
  ['Abuse limits & quantities', 'Push boundaries the business assumes: negative quantities to get a refund, huge values to overflow, more items than stock, exceeding a per-user limit by parallel requests, or bypassing a spending cap.'],
  ['Manipulate the trust flow', 'Change "who decides" — flip a hidden field that sets approval status, change a redirect/callback after payment, or alter a step that the server assumes only its own UI can trigger.'],
  ['Document impact & fix', 'For each finding, record the exact requests, why it violates intended behaviour, and the business impact (money, data, privilege). Fix = enforce state & authorization server-side, recompute trusted values, make one-time actions atomic/idempotent.']
];

const OWASP_ROWS = [
  ['A01', 'Broken Access Control', 'Directory listing, missing CSRF tokens, open redirect, exposed admin/.git paths', true],
  ['A02', 'Cryptographic Failures', 'No HTTPS, weak/expired TLS, weak HSTS, secrets & keys in page source', true],
  ['A03', 'Injection', 'Reflected-input (XSS) canary + SQL-error signature probes on URL parameters', true],
  ['A04', 'Insecure Design', 'Architectural — review threat models & business logic manually', false],
  ['A05', 'Security Misconfiguration', 'CSP weaknesses, TRACE/XST, CORS reflection, unsafe HTTP methods, exposed Actuator/Swagger/GraphQL, source maps', true],
  ['A06', 'Vulnerable & Outdated Components', 'Outdated jQuery/AngularJS/Bootstrap, version disclosure, OSV dependency lookups (code scan)', true],
  ['A07', 'Identification & Auth Failures', 'Insecure cookie flags, password fields over HTTP, autocomplete on credentials', true],
  ['A08', 'Software & Data Integrity', 'Third-party scripts/styles loaded without Subresource Integrity (SRI)', true],
  ['A09', 'Logging & Monitoring Failures', 'Missing security.txt disclosure contact (RFC 9116)', true],
  ['A10', 'Server-Side Request Forgery', 'Server-side — review URL-fetching features manually', false]
];

const ROADMAP = [
  ['1 · Foundations', 'Computer-science & networking basics, Linux, HTTP, TLS, how the web actually works.'],
  ['2 · Security 101', 'Core security concepts, the CIA triad, common attacks, defensive fundamentals.'],
  ['3 · Web app security', 'OWASP Top 10, Burp Suite, manual testing, the methodology above — practise on the legal targets.'],
  ['4 · Offensive (pentest)', 'Jr. Penetration Tester → Web App Pentesting → Red Teaming. Learn to find & prove vulnerabilities.'],
  ['5 · Defensive (blue team)', 'SOC analyst skills, log analysis, SIEM, detection & incident response.'],
  ['6 · Security engineering', 'DevSecOps, cloud security (AWS/Azure), secure design, automation & hardening pipelines.'],
  ['7 · AI security', 'Emerging surface: prompt injection, model/data poisoning, RAG & LLM supply-chain risks.']
];

const PRACTICE_LINKS = [
  ['SauceDemo', 'E-commerce UI automation', 'https://www.saucedemo.com/'],
  ['the-internet', 'UI edge cases (auth, iframes, uploads)', 'https://the-internet.herokuapp.com/'],
  ['OWASP Juice Shop', 'Deliberately insecure web app', 'https://owasp.org/www-project-juice-shop/'],
  ['JSONPlaceholder', 'Fake REST API for testing', 'https://jsonplaceholder.typicode.com/'],
  ['Restful-Booker', 'CRUD API with auth & bugs', 'https://restful-booker.herokuapp.com/'],
  ['PetStore (Swagger)', 'OpenAPI REST sandbox', 'https://petstore.swagger.io/'],
  ['DemoQA', 'Widgets, drag/drop, forms', 'https://demoqa.com/'],
  ['ParaBank', 'Banking app — UI + SOAP/REST', 'https://parabank.parasoft.com/']
];

const LEARNING_LINKS = [
  ['OWASP Top 10', 'The canonical web-risk reference', 'https://owasp.org/www-project-top-ten/'],
  ['OWASP WSTG', 'Web Security Testing Guide', 'https://owasp.org/www-project-web-security-testing-guide/'],
  ['OWASP Cheat Sheets', 'Concrete defensive guidance', 'https://cheatsheetseries.owasp.org/'],
  ['PortSwigger Web Academy', 'Free, hands-on web-security labs', 'https://portswigger.net/web-security'],
  ['TryHackMe', 'Guided rooms & career paths', 'https://tryhackme.com/'],
  ['Hack The Box', 'Realistic pentest machines', 'https://www.hackthebox.com/'],
  ['OWASP AI Top 10 (LLM)', 'Security risks for LLM apps', 'https://owasp.org/www-project-top-10-for-large-language-model-applications/'],
  ['OSV.dev', 'Open vulnerability database', 'https://osv.dev/']
];

function buildPresetChips(container, presets, tabName) {
  presets.forEach((p) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'preset-chip';
    b.textContent = p.label;
    b.title = p.url;
    b.addEventListener('click', () => {
      const input = document.getElementById(container.dataset.target);
      input.value = p.url;
      // Submit the matching form so the test launches immediately.
      const form = document.getElementById(tabName + '-form');
      if (form) form.requestSubmit();
    });
    container.appendChild(b);
  });
}

function buildLearnContent() {
  const ol = document.getElementById('method-list');
  METHODOLOGY.forEach(([t, d]) => {
    const li = document.createElement('li');
    li.innerHTML = `<strong></strong> <span></span>`;
    li.querySelector('strong').textContent = t + ' —';
    li.querySelector('span').textContent = d;
    ol.appendChild(li);
  });

  const bl = document.getElementById('bizlogic-list');
  BIZLOGIC.forEach(([t, d]) => {
    const li = document.createElement('li');
    li.innerHTML = '<strong></strong> <span></span>';
    li.querySelector('strong').textContent = t + ' —';
    li.querySelector('span').textContent = d;
    bl.appendChild(li);
  });

  const tbl = document.getElementById('owasp-table');
  OWASP_ROWS.forEach(([id, name, covers, automated]) => {
    const row = document.createElement('div');
    row.className = 'owasp-row';
    row.innerHTML = `<span class="owasp-id"></span>
      <div class="owasp-body"><span class="owasp-name"></span><span class="owasp-covers"></span></div>
      <span class="owasp-badge ${automated ? 'auto' : 'manual'}">${automated ? '✓ automated' : 'manual'}</span>`;
    row.querySelector('.owasp-id').textContent = id;
    row.querySelector('.owasp-name').textContent = name;
    row.querySelector('.owasp-covers').textContent = covers;
    tbl.appendChild(row);
  });

  const rm = document.getElementById('roadmap');
  ROADMAP.forEach(([stage, desc]) => {
    const step = document.createElement('div');
    step.className = 'roadmap-step';
    step.innerHTML = `<span class="roadmap-stage"></span><span class="roadmap-desc"></span>`;
    step.querySelector('.roadmap-stage').textContent = stage;
    step.querySelector('.roadmap-desc').textContent = desc;
    rm.appendChild(step);
  });

  fillResourceGrid('practice-grid', PRACTICE_LINKS);
  fillResourceGrid('learning-grid', LEARNING_LINKS);
}

function fillResourceGrid(id, links) {
  const grid = document.getElementById(id);
  links.forEach(([name, desc, url]) => {
    const a = document.createElement('a');
    a.className = 'resource-card';
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.innerHTML = `<span class="resource-name"></span><span class="resource-desc"></span>`;
    a.querySelector('.resource-name').textContent = name;
    a.querySelector('.resource-desc').textContent = desc;
    grid.appendChild(a);
  });
}

// ===========================================================================
// Saved authentication profiles (stored locally in the browser)
// ===========================================================================
const PROFILE_KEY = 'sentryscan_auth_profiles';
function getProfiles() { try { return JSON.parse(localStorage.getItem(PROFILE_KEY)) || {}; } catch { return {}; } }
function setProfiles(p) { try { localStorage.setItem(PROFILE_KEY, JSON.stringify(p)); } catch { /* storage full/blocked */ } }

function refreshProfileSelects() {
  const names = Object.keys(getProfiles()).sort();
  document.querySelectorAll('.profile-select').forEach((sel) => {
    const current = sel.value;
    sel.innerHTML = '<option value="">— saved profiles —</option>' +
      names.map((n) => `<option>${escapeHtml(n)}</option>`).join('');
    if (names.includes(current)) sel.value = current;
  });
}
function escapeHtml(s) { return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

function initProfiles() {
  document.querySelectorAll('.profile-row').forEach((row) => {
    const textarea = document.getElementById(row.dataset.target);
    const select = row.querySelector('.profile-select');
    const nameInput = row.querySelector('.profile-name');
    row.querySelector('.profile-apply').addEventListener('click', () => {
      const p = getProfiles();
      if (select.value && p[select.value] != null) textarea.value = p[select.value];
    });
    row.querySelector('.profile-save').addEventListener('click', () => {
      const name = (nameInput.value || select.value).trim();
      if (!name) { nameInput.focus(); return; }
      const p = getProfiles();
      p[name] = textarea.value;
      setProfiles(p);
      nameInput.value = '';
      refreshProfileSelects();
      document.querySelectorAll('.profile-select').forEach((s) => { s.value = name; });
    });
    row.querySelector('.profile-del').addEventListener('click', () => {
      const name = select.value;
      if (!name) return;
      const p = getProfiles();
      delete p[name];
      setProfiles(p);
      refreshProfileSelects();
    });
  });
  refreshProfileSelects();
}

// ===========================================================================
// Export (JSON / PDF) + scan history
// ===========================================================================
function gradeColor(score) {
  return score >= 80 ? 'var(--accent-2)' : score >= 50 ? 'var(--medium)' : 'var(--critical)';
}

document.getElementById('export-json').addEventListener('click', () => {
  if (!currentReport) return;
  const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `sentryscan-${currentReport.type || 'report'}-${Date.now()}.json`;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(a.href);
});
// Browser print-to-PDF — the print stylesheet formats a clean report.
document.getElementById('export-pdf').addEventListener('click', () => window.print());

const HISTORY_KEY = 'sentryscan_history';
const HISTORY_MAX = 20;
function getHistory() { try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; } catch { return []; } }
// Persist, trimming oldest entries if we hit the storage quota.
function persistHistory(arr) {
  let a = arr.slice(0, HISTORY_MAX);
  while (a.length) {
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(a)); return; }
    catch { a = a.slice(0, a.length - 1); }
  }
  try { localStorage.removeItem(HISTORY_KEY); } catch { /* ignore */ }
}
function saveToHistory(data) {
  const entry = {
    id: 'h' + Date.now() + Math.random().toString(36).slice(2, 6),
    ts: Date.now(), type: data.type, target: titleFor(data),
    score: data.score, grade: data.grade, total: data.total, data
  };
  const h = getHistory();
  h.unshift(entry);
  persistHistory(h);
  renderHistory();
}
function renderHistory() {
  const list = document.getElementById('history-list');
  const h = getHistory();
  list.innerHTML = '';
  if (!h.length) { list.innerHTML = '<p class="hint">No scans yet — run one and it will appear here.</p>'; return; }
  h.forEach((e) => {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'history-item';
    item.innerHTML = `<span class="hi-grade"></span>
      <span class="hi-main"><span class="hi-target"></span><span class="hi-meta"></span></span>
      <span class="hi-score"></span>`;
    const g = item.querySelector('.hi-grade');
    g.textContent = e.grade; g.style.background = gradeColor(e.score);
    item.querySelector('.hi-target').textContent = e.target;
    item.querySelector('.hi-meta').textContent =
      `${CAT_LABELS[e.type] || e.type} · ${e.total} finding(s) · ${new Date(e.ts).toLocaleString()}`;
    item.querySelector('.hi-score').textContent = `${e.score}/100`;
    item.addEventListener('click', () => {
      renderResults(e.data);
      document.querySelector('.tab[data-tab="website"]').click();
      document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    list.appendChild(item);
  });
}
document.getElementById('clear-history').addEventListener('click', () => {
  if (!getHistory().length || confirm('Clear all saved scan history?')) {
    try { localStorage.removeItem(HISTORY_KEY); } catch { /* ignore */ }
    renderHistory();
  }
});
// Refresh the history list whenever its tab is opened.
document.querySelector('.tab[data-tab="history"]').addEventListener('click', renderHistory);

// Populate everything once the DOM is ready.
document.querySelectorAll('.preset-chips').forEach((c) => {
  const tabName = c.dataset.target === 'api-input' ? 'api' : 'website';
  buildPresetChips(c, c.dataset.target === 'api-input' ? API_PRESETS : WEBSITE_PRESETS, tabName);
});
buildLearnContent();
initProfiles();
renderHistory();
