'use strict';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS = {
  critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)',
  low: 'var(--low)', info: 'var(--info)'
};
const CAT_LABELS = { ui: 'UI', security: 'Security', vuln: 'Vulnerabilities', render: 'Render', api: 'API', code: 'Code', fuzz: 'Fuzzing', access: 'Access control', spec: 'API surface', vapt: 'Active pen-test', perf: 'Performance', a11y: 'Accessibility', seo: 'SEO', quality: 'Code quality', frontend: 'Frontend', config: 'Config & DevOps', testing: 'Testing', hygiene: 'Project hygiene', seccode: 'Code security', deps: 'Dependencies' };
const CAT_ICONS = { ui: '🧩', security: '🛡️', vuln: '🎯', render: '🖥️', api: '🔌', code: '📦', fuzz: '🧬', access: '🔓', spec: '📜', vapt: '🎯', perf: '⚡', a11y: '♿', seo: '🔎', quality: '🧹', frontend: '🎨', config: '⚙️', testing: '🧪', hygiene: '📋', seccode: '🔐', deps: '📦' };

// Severity definitions — shown as a tooltip on each badge and in the Learn tab.
// These mirror how the report reasons about exploitability, not just impact.
const SEVERITY_DEFS = {
  critical: 'Directly exploitable by an unauthenticated remote attacker with no meaningful preconditions, and leads to compromise of data or the system.',
  high: 'Exploitable by an unauthenticated remote attacker against a default deployment, with no meaningful preconditions.',
  medium: 'Exploitable behind authentication, or needs 1–2 realistic preconditions like a specific role or user interaction.',
  low: 'Needs 3+ preconditions, local-only access, or lacks a concrete demonstrated attack path.',
  info: 'Informational — no direct attack path; recorded for defense-in-depth and reconnaissance awareness.'
};
const CONFIDENCE_LABELS = { high: 'High confidence', medium: 'Medium confidence', low: 'Low confidence' };
const CONFIDENCE_TITLE = 'How sure this is a real issue and not a false positive.';

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
  const vapt = document.getElementById('vapt-toggle').checked;
  const effort = document.getElementById('website-effort').value;
  const authHeaders = parseAuthHeaders('website-auth');
  await runScan('Testing ' + url + ' (UI · security' + (render ? ' · render' : '') + (audits ? ' · audits' : '') + (vapt ? ' · pen-test' : '') + ' · ' + effort + (authHeaders ? ' · authenticated' : '') + ') …', () =>
    fetch('/api/test/website', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, render, audits, vapt, effort, project: getActiveProject(), headers: authHeaders })
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
  const vapt = document.getElementById('api-vapt-toggle').checked;
  await runScan('Testing API endpoint ' + url + (fuzz ? ' (with parameter fuzzing)' : '') + (vapt ? ' (with pen-test)' : '') + ' …', () =>
    fetch('/api/test/api', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, fuzz, headers: authHeaders, method, body: fuzzBody, allowWrite, customPayloads, enumerate, rateLimit, vapt, project: getActiveProject() })
    })
  );
});

// --- Full VAPT assessment --------------------------------------------------
document.getElementById('vapt-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = document.getElementById('vapt-input').value.trim();
  if (!url) return;
  const effort = document.getElementById('vapt-effort').value;
  const allowWrite = document.getElementById('vapt-allow-write').checked;
  const authHeaders = parseAuthHeaders('vapt-auth');
  await runScan('Running full VAPT assessment on ' + url + ' (recon · security · OWASP · pen-test · access · API · fuzzing · render' + (allowWrite ? ' · active probes' : '') + (authHeaders ? ' · authenticated' : '') + ') — this runs many suites and can take a minute …', () =>
    fetch('/api/test/vapt', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, effort, allowWrite, project: getActiveProject(), headers: authHeaders })
    })
  );
});

// --- File selection --------------------------------------------------------
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('file-input');
const codeBtn = document.getElementById('code-btn');
const codeConsent = document.getElementById('code-consent');

// The user must confirm the privacy/consent checkbox before any code is sent for
// scanning (upload, paste, or GitHub). Missing element → treat as consented so a
// future layout change can't silently block scanning.
function consentOk() { return !codeConsent || codeConsent.checked; }
// Re-evaluate the upload/paste button states when consent toggles.
if (codeConsent) codeConsent.addEventListener('change', refreshCodeButtons);
function refreshCodeButtons() {
  codeBtn.disabled = !(selectedFiles.length && consentOk());
  const pb = document.getElementById('paste-btn');
  const pi = document.getElementById('paste-input');
  if (pb && pi) pb.disabled = !(pi.value.trim() && consentOk());
}

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
  codeBtn.disabled = !(selectedFiles.length && consentOk());
}

// Read the shared code-scan options (effort + optional path scope).
function codeOpts() {
  return {
    effort: (document.getElementById('code-effort') || {}).value || 'extended',
    paths: ((document.getElementById('code-paths') || {}).value || '')
      .split(/\r?\n/).map((s) => s.trim()).filter(Boolean)
  };
}

codeBtn.addEventListener('click', async () => {
  if (!selectedFiles.length) return;
  if (!consentOk()) { showError('Please confirm the consent checkbox above before scanning your code.'); return; }
  const { effort, paths } = codeOpts();
  const fd = new FormData();
  selectedFiles.forEach((f) => fd.append('files', f, f.name));
  fd.append('effort', effort);
  fd.append('project', getActiveProject());
  if (paths.length) fd.append('paths', paths.join('\n'));
  await runScan('Analyzing ' + selectedFiles.length + ' file(s) and checking dependencies (' + effort + (paths.length ? ' · scoped' : '') + ') …', () =>
    fetch('/api/scan/files', { method: 'POST', body: fd }));
});

// --- GitHub repo scan ------------------------------------------------------
const ghForm = document.getElementById('gh-form');
if (ghForm) {
  ghForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('gh-input').value.trim();
    if (!url) return;
    if (!consentOk()) { showError('Please confirm the consent checkbox above before scanning a repository.'); return; }
    const { effort, paths } = codeOpts();
    await runScan('Fetching & scanning ' + url + ' (' + effort + (paths.length ? ' · scoped' : '') + ') …', () =>
      fetch('/api/scan/github', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, effort, paths, project: getActiveProject() })
      }));
  });
}

// --- Paste code ------------------------------------------------------------
// Pasted code is sent as a single in-memory file to the same /api/scan/files
// endpoint — it is analyzed as TEXT only and never executed.
const pasteInput = document.getElementById('paste-input');
const pasteBtn = document.getElementById('paste-btn');
const pasteLang = document.getElementById('paste-lang');
if (pasteInput && pasteBtn) {
  pasteInput.addEventListener('input', () => { pasteBtn.disabled = !(pasteInput.value.trim() && consentOk()); });
  pasteBtn.addEventListener('click', async () => {
    const code = pasteInput.value;
    if (!code.trim()) return;
    if (!consentOk()) { showError('Please confirm the consent checkbox above before scanning your code.'); return; }
    const ext = (pasteLang && pasteLang.value) || 'txt';
    const blob = new Blob([code], { type: 'text/plain' });
    const fd = new FormData();
    fd.append('files', blob, 'pasted.' + ext);
    fd.append('effort', codeOpts().effort); // path scope is irrelevant for a single paste
    fd.append('project', getActiveProject());
    await runScan('Analyzing pasted code …', () =>
      fetch('/api/scan/files', { method: 'POST', body: fd }));
  });
}

// --- Runner ----------------------------------------------------------------
function isAuthed() { return document.body.dataset.authed === 'true'; }

// Scanning requires an account. If the visitor isn't signed in, prompt signup
// instead of firing a request that the server would reject with 401.
function requireSignin() {
  if (isAuthed()) return true;
  showError('Create a free account to run scans — your results are saved to your project dashboard.');
  if (window.SentryAuth && window.SentryAuth.open) window.SentryAuth.open();
  return false;
}

async function runScan(loadingText, requestFn) {
  if (!requireSignin()) return;
  show('loading'); hide('results'); hide('error');
  document.getElementById('loading-text').textContent = loadingText;
  try {
    const res = await requestFn();
    const data = await res.json().catch(() => ({ ok: false, error: 'Unexpected server response.' }));
    if (res.status === 401 || res.status === 403) {
      throw new Error(data.error || 'Please sign in to run scans.');
    }
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
  renderSevStrip(data);
  renderIncompleteBanner();
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
    if (c.status === 'error') detail = "couldn't complete";
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

// Honest partial-scan notice: if any suite errored or timed out, say so loudly.
// The score/grade only reflect checks that actually completed, so a silent drop
// would read as a misleadingly clean result.
function renderIncompleteBanner() {
  const existing = document.getElementById('incomplete-banner');
  if (existing) existing.remove();
  const failed = categories.filter((c) => c.status === 'error');
  if (!failed.length) return;

  const banner = document.createElement('div');
  banner.id = 'incomplete-banner';
  banner.className = 'incomplete-banner';
  banner.innerHTML = `
    <div class="ib-head">⚠ Partial scan — ${failed.length} check${failed.length > 1 ? 's' : ''} couldn't complete</div>
    <p class="ib-note">The score and grade below reflect only the checks that finished. Re-run to cover the rest.</p>
    <ul class="ib-list">${failed.map(() => '<li><span class="ib-cat"></span><span class="ib-reason"></span></li>').join('')}</ul>`;

  const rows = banner.querySelectorAll('.ib-list li');
  failed.forEach((c, i) => {
    rows[i].querySelector('.ib-cat').textContent =
      (CAT_ICONS[c.category] || '') + ' ' + (c.label || CAT_LABELS[c.category] || c.category);
    rows[i].querySelector('.ib-reason').textContent =
      "couldn't complete — " + ((c.error || 'no reason reported').trim());
  });

  const anchor = document.querySelector('.filter-bar');
  anchor.parentNode.insertBefore(banner, anchor);
}

// At-a-glance severity breakdown in the scorecard header.
function renderSevStrip(data) {
  const old = document.getElementById('sev-strip');
  if (old) old.remove();
  const strip = document.createElement('div');
  strip.id = 'sev-strip';
  strip.className = 'sev-strip';
  let html = '';
  SEVERITIES.forEach((s) => {
    const n = (data.counts && data.counts[s]) || 0;
    if (n) html += `<span class="sev-pill ${s}"><b>${n}</b> ${s}</span>`;
  });
  strip.innerHTML = html || '<span class="sev-pill info">no issues</span>';
  const sub = document.getElementById('result-sub');
  sub.parentNode.insertBefore(strip, sub.nextSibling);
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

// --- Dismissals ------------------------------------------------------------
// A dismissal is keyed by a stable fingerprint of the finding (category + title
// + location + severity) so the same issue stays dismissed across re-scans and
// re-opened history entries. Reason + timestamp are kept so a future reviewer
// sees the rationale. Persisted in localStorage, matching the history model.
// Namespace dismissals per account so a shared browser never leaks one user's
// dismissals into another's results. Anonymous dismissals live under ":anon".
const DISMISS_KEY_BASE = 'sentryscan_dismissed';
function dismissKey() {
  const email = (window.SentryAuth && window.SentryAuth.user && window.SentryAuth.user.email) || null;
  return email ? `${DISMISS_KEY_BASE}:${email.toLowerCase()}` : `${DISMISS_KEY_BASE}:anon`;
}
let showDismissed = false;

function findingFingerprint(f) {
  const raw = [f.category || '', f.severity || '', f.title || '', f.location || ''].join('');
  // Small, stable DJB2 hash — enough to key localStorage without storing PII.
  let h = 5381;
  for (let i = 0; i < raw.length; i++) h = ((h << 5) + h + raw.charCodeAt(i)) >>> 0;
  return 'f' + h.toString(36);
}
function getDismissed() { try { return JSON.parse(localStorage.getItem(dismissKey())) || {}; } catch { return {}; } }
function setDismissed(map) { try { localStorage.setItem(dismissKey(), JSON.stringify(map)); } catch { /* quota */ } }
function isDismissed(f) { return !!getDismissed()[findingFingerprint(f)]; }
function dismissFinding(f, reason) {
  const fp = findingFingerprint(f);
  const map = getDismissed();
  map[fp] = { reason: reason || '(no reason given)', ts: Date.now(), title: f.title };
  setDismissed(map);
  // Signed-in: persist to the account so it syncs across devices + the dashboard.
  if (isAuthed()) {
    fetch('/api/dismissals', {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint: fp, reason: reason || '', title: f.title || '' })
    }).catch(() => {});
  }
}
function restoreFinding(f) {
  const fp = findingFingerprint(f);
  const map = getDismissed();
  delete map[fp];
  setDismissed(map);
  if (isAuthed()) {
    fetch('/api/dismissals/' + encodeURIComponent(fp), { method: 'DELETE', credentials: 'same-origin' }).catch(() => {});
  }
}
// On sign-in, pull the account's dismissals into local state so they show
// immediately (cross-device sync) in the results view.
async function hydrateDismissals() {
  if (!isAuthed()) return;
  try {
    const d = await fetch('/api/dismissals', { credentials: 'same-origin' }).then((r) => r.json());
    if (!d || !d.dismissals) return;
    const map = getDismissed();
    for (const [fp, rec] of Object.entries(d.dismissals)) {
      map[fp] = { reason: rec.reason, ts: rec.ts ? Date.parse(rec.ts) : Date.now(), title: rec.title };
    }
    setDismissed(map);
  } catch { /* offline / not authed */ }
}

function renderFindings() {
  const container = document.getElementById('findings');
  container.innerHTML = '';
  let items = allFindings;
  if (activeSev !== 'all') items = items.filter((f) => f.severity === activeSev);
  if (activeCat !== 'all') items = items.filter((f) => f.category === activeCat);

  const dismissedItems = items.filter(isDismissed);
  const visibleItems = items.filter((f) => !isDismissed(f));

  // Update the "show dismissed" toggle (only meaningful once something is hidden).
  const dismissBtn = document.getElementById('toggle-dismissed');
  if (dismissBtn) {
    const n = dismissedItems.length;
    dismissBtn.classList.toggle('hidden', n === 0);
    dismissBtn.textContent = `${showDismissed ? '🙈 Hide' : '👁 Show'} dismissed (${n})`;
  }

  const items2 = showDismissed ? [...visibleItems, ...dismissedItems] : visibleItems;

  if (!items2.length) {
    const div = document.createElement('div');
    div.className = 'clean-state';
    div.textContent = allFindings.length
      ? (dismissedItems.length ? 'All matching findings are dismissed.' : 'No findings match this filter.')
      : '✓ No issues detected.';
    container.appendChild(div);
    return;
  }

  items2.forEach((f) => {
    const dismissed = isDismissed(f);
    const el = document.createElement('div');
    el.className = 'finding ' + f.severity + (dismissed ? ' dismissed' : '');
    const conf = f.confidence && CONFIDENCE_LABELS[f.confidence];
    el.innerHTML = `
      <div class="f-head">
        <span class="f-sev ${f.severity}" title="${f.severity.toUpperCase()}: ${SEVERITY_DEFS[f.severity] || ''}">${f.severity}</span>
        ${conf ? `<span class="f-conf ${f.confidence}" title="${CONFIDENCE_TITLE}"></span>` : ''}
        <span class="f-cat">${CAT_ICONS[f.category] || ''} ${CAT_LABELS[f.category] || f.category}</span>
        ${f.owasp ? `<span class="f-owasp"></span>` : ''}
        <span class="f-title"></span>
        ${f.location ? `<span class="f-loc"></span>` : ''}
        <button type="button" class="f-dismiss">${dismissed ? 'Restore' : 'Dismiss'}</button>
      </div>
      <p class="f-desc"></p>
      ${f.impact ? `<p class="f-impact"><strong>Impact:</strong> <span class="f-impact-text"></span></p>` : ''}
      ${f.evidence ? `<div class="f-evidence"></div>` : ''}
      ${f.remediation ? `<p class="f-fix"><strong>Fix:</strong> <span class="f-fix-text"></span></p>` : ''}
      ${f.reproduction ? `<div class="f-repro"><div class="f-repro-head"><span>↻ Reproduce (curl)</span><button type="button" class="copy-btn">Copy</button></div><pre class="f-repro-code"></pre></div>` : ''}
      ${f.handoff ? `<div class="f-handoff"><strong>Authorized hand-off:</strong> <code class="f-handoff-code"></code></div>` : ''}
      ${dismissed ? `<p class="f-dismiss-note"><strong>Dismissed:</strong> <span class="f-dismiss-reason"></span></p>` : ''}
    `;
    el.querySelector('.f-title').textContent = f.title;
    if (conf) el.querySelector('.f-conf').textContent = conf;
    if (f.owasp) el.querySelector('.f-owasp').textContent = f.owasp;
    if (f.location) el.querySelector('.f-loc').textContent = f.location;
    el.querySelector('.f-desc').textContent = f.description;
    if (f.impact) el.querySelector('.f-impact-text').textContent = f.impact;
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
    if (dismissed) {
      const d = getDismissed()[findingFingerprint(f)];
      el.querySelector('.f-dismiss-reason').textContent =
        `${d ? d.reason : ''}${d && d.ts ? ' · ' + new Date(d.ts).toLocaleString() : ''}`;
    }
    el.querySelector('.f-dismiss').addEventListener('click', () => {
      if (dismissed) {
        restoreFinding(f);
      } else {
        const reason = prompt('Why dismiss this finding? (e.g. false positive, accepted risk, out of scope)');
        if (reason === null) return; // cancelled
        dismissFinding(f, reason.trim());
      }
      renderFindings();
    });
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

// Full ethical-hacking domain map. tag: 'auto' (SentryScan scans it),
// 'manual' (do by hand), 'context' (background — out of a web/code scanner's scope).
const KNOWLEDGE = [
  ['1. Ethical Hacking foundations', 'Definition, purpose, hacker types, legal/ethical considerations', 'context'],
  ['2. Networking basics', 'TCP/IP, OSI model, subnetting, DNS, DHCP', 'context'],
  ['3. Operating systems', 'Linux, Windows, macOS, command-line basics', 'context'],
  ['4. Cybersecurity fundamentals', 'Encryption, firewalls, antivirus, IDS/IPS', 'context'],
  ['5. Programming languages', 'Python, JavaScript, Bash, SQL, C/C++/Java/Ruby', 'context'],
  ['6. Scanning & enumeration', 'Service/version fingerprinting, exposed paths & dev endpoints, OpenAPI enumeration, vuln scanning (no raw port scan)', 'auto'],
  ['7. Exploitation', 'CVEs, Metasploit, buffer overflows — SentryScan confirms (boolean SQLi/SSTI/redirect) but never weaponizes', 'manual'],
  ['8. Web application security', 'OWASP Top 10, SQL injection, XSS — the core of SentryScan', 'auto'],
  ['9. Wireless network hacking', 'Wi-Fi, WEP/WPA/WPA2, wireless attacks', 'context'],
  ['10. Social engineering', 'Phishing, spear phishing, SET', 'context'],
  ['11. Sniffing & spoofing', 'MITM, ARP spoofing, DNS spoofing', 'context'],
  ['12. Malware analysis', 'Malware types, sandboxing, signature/behavior detection', 'context'],
  ['13. Incident response & forensics', 'IR process, digital forensics, chain of custody', 'context'],
  ['14. Penetration testing', 'Types, methodology, reporting — see the methodology + reproduction PoCs above', 'manual'],
  ['15. Cryptography', 'Symmetric/asymmetric, hashing, signatures — SentryScan checks TLS/HTTPS, weak transport, exposed keys', 'auto'],
  ['16. Mobile hacking', 'Android/iOS & mobile app security', 'context'],
  ['17. Cloud security', 'AWS/Azure/GCP best practices (cloud-account config needs creds — out of scope)', 'context'],
  ['18. IoT security', 'IoT risks, securing devices', 'context'],
  ['19. Legal & compliance', 'CFAA, GDPR, HIPAA, PCI DSS — always get written authorization before testing', 'context'],
  ['20. Cybersecurity tools', 'Nmap, Wireshark, Burp, Snort, Nessus, Aircrack — SentryScan bundles Trivy, Gitleaks, SonarCloud, Lighthouse, OSV', 'manual'],
  ['21. Careers & certifications', 'CEH, OSCP, CISSP, CompTIA Security+', 'context']
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

// ===========================================================================
// VAPT methodology — the full professional checklist, each item honestly mapped
// to how SentryScan covers it: Automated (in-app), Partial (signal / needs
// confirmation), or Manual (out of a black-box web scanner's reach — do it by
// hand with the noted tool). Rendered statically into the VAPT page.
// ===========================================================================
const VAPT_STATUS = {
  auto: { label: 'Automated', cls: 'auto' },
  partial: { label: 'Partial', cls: 'partial' },
  manual: { label: 'Manual', cls: 'manual' }
};
const VAPT_METHOD = [
  { n: '1. Information Gathering (Recon)', items: [
    ['WHOIS', 'manual', 'whois'], ['DNS records (A/MX/TXT/NS)', 'manual', 'dig'], ['Subdomain enumeration', 'manual', 'Subfinder/Amass'],
    ['Public IP addresses', 'manual'], ['Technology & framework', 'auto'], ['Server / web-server version', 'auto'], ['CMS detection', 'auto'],
    ['JavaScript files', 'auto'], ['API endpoints', 'auto'], ['robots.txt', 'auto'], ['sitemap.xml', 'auto'], ['Git exposure (.git)', 'auto'],
    ['Swagger / OpenAPI docs', 'auto'], ['Hidden directories', 'auto'], ['Backup files', 'auto'], ['Source maps', 'auto'],
    ['Third-party libraries', 'auto'], ['Email / metadata leaks', 'partial'], ['SSL certificate', 'auto'], ['Cloud storage buckets', 'manual'], ['CDN detection', 'partial'] ] },
  { n: '2. Authentication Testing', items: [
    ['Weak / default passwords', 'manual', 'Hydra'], ['Password policy', 'partial'], ['Brute force / rate limit', 'auto'], ['Credential stuffing', 'manual'],
    ['Login bypass', 'partial'], ['MFA bypass', 'manual'], ['Session fixation', 'partial'], ['Session timeout', 'manual'], ['Account lockout', 'partial'],
    ['Password reset flaws', 'manual'], ['OTP / email-verify bypass', 'manual'], ['JWT manipulation (alg:none / exp)', 'auto'], ['OAuth issues', 'manual'],
    ['Token replay / expiry', 'partial'], ['Refresh token abuse', 'manual'] ] },
  { n: '3. Authorization Testing', items: [
    ['Horizontal privilege escalation', 'partial'], ['Vertical privilege escalation', 'partial'], ['IDOR', 'auto'], ['Missing authorization', 'auto'],
    ['Admin page access', 'auto'], ['Hidden endpoints', 'auto'], ['API authorization', 'auto'], ['Resource ownership', 'partial'], ['Role validation', 'manual'] ] },
  { n: '4. Session Management', items: [
    ['Cookie HttpOnly', 'auto'], ['Cookie Secure flag', 'auto'], ['Cookie SameSite', 'auto'], ['Session expiration', 'manual'], ['Session hijacking', 'partial'],
    ['Predictable session IDs', 'partial'], ['Logout functionality', 'manual'], ['Concurrent sessions', 'manual'], ['Session invalidation', 'manual'] ] },
  { n: '5. Injection & Input Validation', items: [
    ['SQL injection (error/boolean/time/blind)', 'auto'], ['NoSQL / Mongo injection', 'partial'], ['Second-order SQLi', 'manual'], ['XSS — reflected', 'auto'],
    ['XSS — stored', 'partial'], ['XSS — DOM', 'partial'], ['Command injection', 'auto'], ['SSTI / template injection', 'auto'], ['Path traversal', 'auto'],
    ['CRLF injection', 'partial'], ['HTTP parameter pollution', 'manual'] ] },
  { n: '6. CSRF', items: [
    ['Missing CSRF token', 'auto'], ['Weak CSRF protection', 'partial'], ['Cookie-only authentication', 'partial'], ['Sensitive POST without token', 'partial'] ] },
  { n: '7. File Upload / Download', items: [
    ['Malicious upload (PHP/JSP/SVG/HTML)', 'manual'], ['Double-extension / MIME bypass', 'manual'], ['Magic-byte validation', 'manual'],
    ['Directory / path traversal', 'auto'], ['Sensitive file exposure', 'auto'], ['Config / log exposure', 'auto'] ] },
  { n: '8. XML / JSON Issues', items: [
    ['XXE', 'manual'], ['XML bomb / injection', 'manual'], ['JSON injection', 'partial'], ['Mass assignment', 'partial'], ['Prototype pollution', 'partial'] ] },
  { n: '9. API Security', items: [
    ['Broken authentication', 'auto'], ['Broken object-level auth (BOLA / IDOR)', 'auto'], ['Rate limiting', 'auto'], ['JWT security', 'auto'],
    ['API key / token leakage', 'auto'], ['GraphQL introspection', 'auto'], ['REST / SOAP checks', 'partial'], ['Excessive data exposure', 'partial'],
    ['Shadow APIs', 'manual'], ['Swagger / doc exposure', 'auto'], ['API business-logic flaws', 'manual'] ] },
  { n: '10. Business Logic & Payment', items: [
    ['Price / amount manipulation', 'manual'], ['Coupon / reward abuse', 'manual'], ['Workflow / step bypass', 'manual'], ['Cart / order manipulation', 'manual'],
    ['Race conditions', 'partial'], ['Duplicate / replay payment', 'manual'], ['Currency modification', 'manual'], ['Webhook / callback validation', 'manual'], ['Refund abuse', 'manual'] ] },
  { n: '11. Cryptography', items: [
    ['Weak hashing (MD5 / SHA1)', 'auto'], ['ECB / weak encryption', 'partial'], ['Hardcoded keys', 'auto'], ['Insecure randomness', 'auto'],
    ['Key storage', 'partial'], ['Sensitive-data encryption', 'partial'] ] },
  { n: '12. Sensitive Data Exposure', items: [
    ['Passwords / secrets in responses', 'auto'], ['JWT / access / refresh tokens', 'auto'], ['Credit cards / PAN', 'partial'], ['Email / phone / PII', 'partial'],
    ['Env variables / config', 'auto'], ['Secrets in logs', 'partial'] ] },
  { n: '13. HTTP Security Headers', items: [
    ['HSTS', 'auto'], ['X-Frame-Options', 'auto'], ['Content-Security-Policy', 'auto'], ['Referrer-Policy', 'auto'], ['Permissions-Policy', 'auto'],
    ['X-Content-Type-Options', 'auto'], ['Cache-Control', 'partial'], ['CORS headers', 'auto'] ] },
  { n: '14. CORS', items: [
    ['Wildcard *', 'auto'], ['Origin reflection', 'auto'], ['Credentials + reflection', 'auto'], ['Subdomain abuse', 'partial'] ] },
  { n: '15. Server & SSL/TLS', items: [
    ['Server / version disclosure', 'auto'], ['Banner grabbing', 'auto'], ['Default pages', 'partial'], ['Directory listing', 'auto'], ['TLS version', 'auto'],
    ['Weak ciphers', 'auto'], ['Expired / invalid certificate', 'auto'], ['Certificate chain', 'auto'], ['Forward secrecy', 'partial'] ] },
  { n: '16. Network Testing', items: [
    ['Open ports', 'manual', 'Nmap'], ['SSH / FTP / SMTP', 'manual', 'Nmap'], ['Redis / Mongo / Elasticsearch', 'manual', 'Nmap'],
    ['Docker / Kubernetes exposure', 'partial'], ['Firewall / VPN', 'manual'] ] },
  { n: '17. Mobile Security', items: [
    ['APK reverse engineering', 'manual', 'MobSF'], ['Certificate pinning', 'manual'], ['Root detection', 'manual'], ['Local DB / SharedPrefs', 'manual'],
    ['Hardcoded secrets', 'manual', 'MobSF'], ['Deep links / exported activities', 'manual'] ] },
  { n: '18. Cloud Security', items: [
    ['S3 / bucket permissions', 'manual'], ['IAM / security groups', 'manual'], ['Cloud metadata SSRF', 'partial'], ['Public buckets', 'manual'],
    ['Cloud keys in code', 'auto'], ['Cloud functions / storage', 'manual'] ] },
  { n: '19. Docker & Kubernetes', items: [
    ['Docker daemon / socket', 'manual'], ['Container escape', 'manual'], ['Exposed dashboard / actuator', 'auto'], ['RBAC / network policies', 'manual'],
    ['Dockerfile misconfig', 'auto'], ['Secrets in images', 'partial'] ] },
  { n: '20. Dependency Security', items: [
    ['npm / pip / maven / composer CVEs', 'auto'], ['Outdated libraries', 'auto'], ['Known CVEs (OSV.dev)', 'auto'], ['License issues', 'partial'], ['Supply-chain / typosquat', 'partial'] ] },
  { n: '21. Logging & Monitoring', items: [
    ['Sensitive data in logs', 'partial'], ['Audit logs', 'manual'], ['Log injection', 'manual'], ['Monitoring / alerting / SIEM', 'manual'] ] },
  { n: '22. Error Handling', items: [
    ['Stack traces', 'auto'], ['Database errors', 'auto'], ['Debug mode', 'auto'], ['Verbose responses', 'auto'], ['Internal IP disclosure', 'auto'] ] },
  { n: '23. Denial of Service', items: [
    ['Rate limiting present', 'auto'], ['Large-payload handling', 'partial'], ['Flooding / Slowloris', 'manual'], ['Resource exhaustion', 'manual'] ] },
  { n: '24. Race Conditions', items: [
    ['Concurrent-request race probe', 'partial'], ['Double spending', 'manual'], ['Duplicate orders', 'manual'], ['Reward / payment duplication', 'manual'] ] },
  { n: '25. Clickjacking', items: [
    ['Iframe embedding allowed', 'auto'], ['Missing X-Frame-Options / frame-ancestors', 'auto'] ] },
  { n: '26. Open Redirect', items: [ ['Redirect parameter manipulation', 'auto'] ] },
  { n: '27. SSRF', items: [
    ['Internal service access', 'partial'], ['Cloud metadata', 'partial'], ['Private IP access', 'partial'], ['DNS rebinding', 'manual'] ] },
  { n: '28. Deserialization', items: [
    ['Java / PHP / Python / Node deserialization', 'manual'], ['Unsafe object deserialization', 'partial'] ] },
  { n: '29. Remote Code Execution', items: [
    ['Command execution', 'partial'], ['Template injection', 'auto'], ['Unsafe eval', 'partial'], ['Unsafe libraries', 'partial'] ] },
  { n: '30. WebSocket Security', items: [
    ['Authentication / authorization', 'manual'], ['Message tampering / replay', 'manual'], ['Rate limiting', 'manual'] ] },
  { n: '31. Secrets Management', items: [
    ['GitHub / repo leaks', 'auto'], ['AWS / GCP / Firebase keys', 'auto'], ['API keys', 'auto'], ['Private keys / certificates', 'auto'], ['Environment variables', 'auto'] ] },
  { n: '32. Source Code Review (White Box)', items: [
    ['Hardcoded passwords', 'auto'], ['Unsafe SQL queries', 'auto'], ['Unsafe functions (eval/exec)', 'auto'], ['Insecure randomness', 'auto'],
    ['Secrets', 'auto'], ['Unsafe file handling', 'auto'], ['Logic flaws', 'partial'], ['Input validation', 'auto'] ] },
  { n: '33. Configuration Review', items: [
    ['Debug mode', 'auto'], ['Environment configs', 'auto'], ['Default credentials', 'partial'], ['Open admin panels', 'auto'], ['Verbose logging', 'partial'] ] },
  { n: '34. Compliance', items: [
    ['OWASP Top 10 mapping', 'auto'], ['OWASP API Top 10', 'partial'], ['SANS Top 25 / CWE', 'partial'], ['CVE mapping', 'auto'], ['PCI DSS', 'manual'], ['ISO 27001', 'manual'] ] },
  { n: '35. Advanced Testing', items: [
    ['JWT algorithm confusion', 'partial'], ['JWT signature bypass', 'partial'], ['Web cache deception', 'auto'], ['Cache poisoning', 'partial'],
    ['HTTP request smuggling', 'manual'], ['HTTP response splitting', 'manual'], ['Host header injection', 'auto'], ['DNS rebinding', 'manual'],
    ['CRLF injection', 'partial'], ['Prototype pollution', 'partial'], ['Insecure deserialization', 'manual'], ['XXE', 'manual'], ['SSRF', 'partial'],
    ['RCE chaining', 'partial'], ['Supply-chain attacks', 'auto'], ['Client-side path traversal', 'manual'], ['Browser cache poisoning', 'partial'],
    ['Unicode normalization', 'manual'], ['HTTP parameter pollution', 'manual'] ] }
];
const VAPT_FRAMEWORKS = ['OWASP Web Security Testing Guide (WSTG)', 'OWASP API Security Top 10', 'OWASP Top 10 (2021)', 'PTES', 'NIST SP 800-115', 'OSSTMM', 'MITRE ATT&CK', 'SANS Top 25', 'CWE', 'CVE', 'PCI DSS', 'ISO 27001'];
// ★ = SentryScan automates part of this capability in-app.
const VAPT_TOOLS = [
  ['Burp Suite', 0], ['OWASP ZAP', 1], ['Nmap', 0], ['Nikto', 1], ['sqlmap', 1], ['ffuf', 0], ['dirsearch', 1], ['Gobuster', 0],
  ['Amass', 0], ['Subfinder', 0], ['Nuclei', 1], ['Metasploit', 0], ['Wireshark', 0], ['Hydra', 0], ['John the Ripper', 0], ['Hashcat', 0],
  ['MobSF', 0], ['Postman / Insomnia', 1], ['Trivy', 1], ['SonarQube', 1], ['GitLeaks / TruffleHog', 1]
];
const VAPT_REPORTING = [
  ['CVSS-style severity', 'Every finding carries a severity + confidence + OWASP category.'],
  ['Risk categorization', 'Critical / High / Medium / Low / Info, rolled into a 0–100 grade.'],
  ['Proof of Concept', 'Copy-paste curl reproduction per finding, plus a sqlmap hand-off for SQLi.'],
  ['Business impact', 'Each finding explains what an attacker could actually do.'],
  ['Remediation', 'Specific, per-finding fix guidance — not generic advice.'],
  ['Executive summary', 'Grade + severity breakdown + trend, exportable as JSON / PDF.'],
  ['Retest', 'Re-run any target; dismissals and the score trend track fixes over time.']
];

function buildVaptContent() {
  const host = document.getElementById('vapt-content');
  if (!host) return;
  let a = 0, p = 0, m = 0, total = 0;
  VAPT_METHOD.forEach((s) => s.items.forEach((it) => { total++; if (it[1] === 'auto') a++; else if (it[1] === 'partial') p++; else m++; }));

  const summary = `<div class="vapt-summary">
    <div class="vapt-sum-lead"><h3 class="vapt-h">Coverage against the professional VAPT checklist</h3>
      <p class="hint" style="margin:0">${total} checklist items mapped honestly. Running an assessment above exercises the <strong>Automated</strong> and (where you enable active probes) the <strong>Partial</strong> items; the <strong>Manual</strong> ones need a human tester with the noted tools — this page tells you exactly which is which.</p></div>
    <div class="vapt-sum-stats">
      <span class="vapt-stat auto"><b>${a}</b> Automated</span>
      <span class="vapt-stat partial"><b>${p}</b> Partial</span>
      <span class="vapt-stat manual"><b>${m}</b> Manual</span>
    </div></div>`;

  const legend = `<div class="vapt-legend">
    <span class="vapt-dot auto"></span> Automated in-app
    <span class="vapt-dot partial"></span> Partial — signal, confirm manually
    <span class="vapt-dot manual"></span> Manual — out of a black-box web scanner's reach</div>`;

  const sections = '<div class="vapt-grid">' + VAPT_METHOD.map((s) => {
    const counts = { auto: 0, partial: 0, manual: 0 };
    s.items.forEach((it) => counts[it[1]]++);
    const items = s.items.map((it) => {
      const st = VAPT_STATUS[it[1]];
      const tool = it[2] ? `<span class="vapt-tool">${anEsc(it[2])}</span>` : '';
      return `<li class="vapt-item"><span class="vapt-dot ${st.cls}" title="${st.label}"></span><span class="vapt-item-t">${anEsc(it[0])}</span>${tool}</li>`;
    }).join('');
    return `<div class="vapt-card">
      <div class="vapt-card-head"><h4 class="vapt-card-title">${anEsc(s.n)}</h4>
        <span class="vapt-card-mini">${counts.auto}<i class="vapt-dot auto"></i> ${counts.partial}<i class="vapt-dot partial"></i> ${counts.manual}<i class="vapt-dot manual"></i></span></div>
      <ul class="vapt-items">${items}</ul></div>`;
  }).join('') + '</div>';

  const frameworks = `<div class="vapt-card vapt-wide"><h4 class="vapt-card-title">Frameworks &amp; methodologies referenced</h4>
    <div class="vapt-chips">${VAPT_FRAMEWORKS.map((f) => `<span class="vapt-chip">${anEsc(f)}</span>`).join('')}</div></div>`;

  const tools = `<div class="vapt-card vapt-wide"><h4 class="vapt-card-title">Tools used in professional VAPT <span class="hint" style="font-weight:400">— ★ = SentryScan automates part of this in-app</span></h4>
    <div class="vapt-chips">${VAPT_TOOLS.map((t) => `<span class="vapt-chip${t[1] ? ' star' : ''}">${t[1] ? '★ ' : ''}${anEsc(t[0])}</span>`).join('')}</div></div>`;

  const reporting = `<div class="vapt-card vapt-wide"><h4 class="vapt-card-title">Reporting (what a good VAPT deliverable includes)</h4>
    <div class="vapt-report">${VAPT_REPORTING.map((r) => `<div class="vapt-report-row"><strong>${anEsc(r[0])}</strong><span>${anEsc(r[1])}</span></div>`).join('')}</div></div>`;

  host.innerHTML = summary + legend + sections + frameworks + tools + reporting;
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

  const kb = document.getElementById('knowledge-base');
  if (kb) KNOWLEDGE.forEach(([name, covers, tag]) => {
    const row = document.createElement('div');
    row.className = 'owasp-row';
    const cls = tag === 'auto' ? 'auto' : (tag === 'manual' ? 'manual' : 'context');
    row.innerHTML = `<div class="owasp-body"><span class="owasp-name"></span><span class="owasp-covers"></span></div>
      <span class="owasp-badge ${cls}"></span>`;
    row.querySelector('.owasp-name').textContent = name;
    row.querySelector('.owasp-covers').textContent = covers;
    row.querySelector('.owasp-badge').textContent = tag;
    kb.appendChild(row);
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

document.getElementById('toggle-dismissed').addEventListener('click', () => {
  showDismissed = !showDismissed;
  renderFindings();
});

// --- CSV / Markdown / webhook export --------------------------------------
// Export the findings currently loaded (dismissed ones are marked, not dropped,
// so an exported report is a faithful record).
const EXPORT_COLUMNS = ['severity', 'confidence', 'category', 'owasp', 'title', 'description', 'impact', 'evidence', 'location', 'remediation', 'reproduction', 'dismissed', 'dismiss_reason'];

function exportRows() {
  return (currentReport?.findings || []).map((f) => {
    const d = getDismissed()[findingFingerprint(f)];
    return {
      severity: f.severity || '', confidence: f.confidence || '', category: CAT_LABELS[f.category] || f.category || '',
      owasp: f.owasp || '', title: f.title || '', description: f.description || '', impact: f.impact || '',
      evidence: f.evidence || '', location: f.location || '', remediation: f.remediation || '',
      reproduction: f.reproduction || '', dismissed: d ? 'yes' : '', dismiss_reason: d ? d.reason : ''
    };
  });
}
function downloadBlob(content, type, ext) {
  const blob = new Blob([content], { type });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `sentryscan-${currentReport?.type || 'report'}-${Date.now()}.${ext}`;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(a.href);
}
function csvCell(v) {
  const s = String(v ?? '');
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
document.getElementById('export-csv').addEventListener('click', () => {
  if (!currentReport) return;
  const rows = exportRows();
  const lines = [EXPORT_COLUMNS.join(',')];
  rows.forEach((r) => lines.push(EXPORT_COLUMNS.map((c) => csvCell(r[c])).join(',')));
  // Prepend a UTF-8 BOM so Excel opens accented characters correctly.
  downloadBlob('﻿' + lines.join('\r\n'), 'text/csv;charset=utf-8', 'csv');
});
document.getElementById('export-md').addEventListener('click', () => {
  if (!currentReport) return;
  downloadBlob(buildMarkdown(currentReport), 'text/markdown;charset=utf-8', 'md');
});
function buildMarkdown(report) {
  const rows = exportRows();
  const out = [];
  out.push(`# SentryScan report — ${titleFor(report)}`);
  out.push('');
  out.push(`- **Grade:** ${report.grade} (${report.score}/100)`);
  out.push(`- **Findings:** ${report.total}`);
  out.push(`- **Generated:** ${new Date().toLocaleString()}`);
  out.push('');
  rows.forEach((r, i) => {
    out.push(`## ${i + 1}. ${r.title} ${r.dismissed ? '_(dismissed)_' : ''}`.trim());
    out.push('');
    out.push(`- **Severity:** ${r.severity.toUpperCase()}${r.confidence ? ` · **Confidence:** ${r.confidence}` : ''}`);
    if (r.category) out.push(`- **Category:** ${r.category}${r.owasp ? ` · ${r.owasp}` : ''}`);
    if (r.location) out.push(`- **Location:** \`${r.location}\``);
    out.push('');
    if (r.description) { out.push(`**Details:** ${r.description}`, ''); }
    if (r.impact) { out.push(`**Impact:** ${r.impact}`, ''); }
    if (r.evidence) { out.push('**Evidence:**', '```', r.evidence, '```', ''); }
    if (r.remediation) { out.push(`**Recommended fix:** ${r.remediation}`, ''); }
    if (r.reproduction) { out.push('**Reproduce:**', '```bash', r.reproduction, '```', ''); }
    if (r.dismissed) out.push(`> Dismissed — ${r.dismiss_reason}`);
    out.push('');
  });
  return out.join('\n');
}

// Webhook: POST the report JSON to a user-supplied URL. Routed through the
// server (browsers can't POST cross-origin to arbitrary hosts) which validates
// the destination through the same SSRF guard used for scan targets.
document.getElementById('export-webhook').addEventListener('click', async () => {
  if (!currentReport) return;
  const url = prompt('Webhook URL — the full report JSON will be POSTed here:');
  if (!url) return;
  const btn = document.getElementById('export-webhook');
  const original = btn.textContent;
  btn.disabled = true; btn.textContent = 'Sending…';
  try {
    const res = await fetch('/api/export/webhook', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url.trim(), report: { ...currentReport, findings: exportRows() } })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    btn.textContent = `✓ Sent (${data.status})`;
  } catch (e) {
    btn.textContent = '✗ Failed';
    showError('Webhook failed: ' + e.message);
  } finally {
    setTimeout(() => { btn.disabled = false; btn.textContent = original; }, 2000);
  }
});

// Jira: create one issue per finding. Connection details are remembered locally
// (never the report data) so you don't re-enter them every export. The API token
// is stored in this browser only and sent to your own server, which forwards it
// to your Jira instance — nowhere else.
const JIRA_CFG_KEY = 'sentryscan_jira';
function getJiraCfg() { try { return JSON.parse(localStorage.getItem(JIRA_CFG_KEY)) || {}; } catch { return {}; } }
function promptJiraCfg() {
  const c = getJiraCfg();
  const baseUrl = prompt('Jira base URL (e.g. https://your-team.atlassian.net):', c.baseUrl || '');
  if (!baseUrl) return null;
  const email = prompt('Jira account email:', c.email || '');
  if (!email) return null;
  const projectKey = prompt('Jira project key (e.g. SEC):', c.projectKey || '');
  if (!projectKey) return null;
  const apiToken = prompt('Jira API token (stored in this browser only):', c.apiToken || '');
  if (!apiToken) return null;
  const cfg = { baseUrl: baseUrl.trim(), email: email.trim(), projectKey: projectKey.trim(), apiToken: apiToken.trim() };
  try { localStorage.setItem(JIRA_CFG_KEY, JSON.stringify(cfg)); } catch { /* quota */ }
  return cfg;
}
document.getElementById('export-jira').addEventListener('click', async () => {
  if (!currentReport) return;
  // Only push what's actionable and not dismissed — issues you've already
  // triaged away shouldn't reopen as Jira tickets.
  const rows = exportRows().filter((r) => !r.dismissed);
  if (!rows.length) { showError('No active (non-dismissed) findings to export to Jira.'); return; }
  if (!confirm(`Create up to ${Math.min(rows.length, 25)} Jira issue(s) from this report?`)) return;
  const cfg = promptJiraCfg();
  if (!cfg) return;
  const btn = document.getElementById('export-jira');
  const original = btn.textContent;
  btn.disabled = true; btn.textContent = 'Creating…';
  try {
    const res = await fetch('/api/export/jira', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...cfg, findings: rows })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    btn.textContent = `✓ Created ${data.count}`;
    if (data.errors && data.errors.length) showError(`Jira: created ${data.count}, but ${data.errors.length} failed — ${data.errors[0]}`);
  } catch (e) {
    btn.textContent = '✗ Failed';
    showError('Jira export failed: ' + e.message);
  } finally {
    setTimeout(() => { btn.disabled = false; btn.textContent = original; }, 2500);
  }
});

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
// --- Projects --------------------------------------------------------------
// Every scan is filed under an active project so results stay attributable and
// reviewers can filter to just their own. Stored locally, like history.
const PROJECT_KEY = 'sentryscan_project';
function getActiveProject() { try { return localStorage.getItem(PROJECT_KEY) || 'Default'; } catch { return 'Default'; } }
function setActiveProject(name) { try { localStorage.setItem(PROJECT_KEY, name || 'Default'); } catch { /* ignore */ } }
function knownProjects() {
  const set = new Set(['Default', getActiveProject()]);
  getHistory().forEach((e) => set.add(e.project || 'Default'));
  return [...set];
}

function saveToHistory(data) {
  const entry = {
    id: 'h' + Date.now() + Math.random().toString(36).slice(2, 6),
    ts: Date.now(), type: data.type, target: titleFor(data),
    project: getActiveProject(),
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
  // Keep the project input + datalist in sync with what's been used.
  const input = document.getElementById('project-input');
  const datalist = document.getElementById('project-list');
  if (input && !input.value) input.value = getActiveProject();
  if (datalist) datalist.innerHTML = knownProjects().map((p) => `<option value="${p.replace(/"/g, '&quot;')}"></option>`).join('');

  const active = getActiveProject();
  const shown = h.filter((e) => (e.project || 'Default') === active);
  list.innerHTML = '';
  if (!h.length) { list.innerHTML = '<p class="hint">No scans yet — run one and it will appear here.</p>'; return; }
  if (!shown.length) { list.innerHTML = `<p class="hint">No scans in project “${active}”. Switch project or run a scan.</p>`; return; }
  shown.forEach((e) => {
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
      `${e.project || 'Default'} · ${CAT_LABELS[e.type] || e.type} · ${e.total} finding(s) · ${new Date(e.ts).toLocaleString()}`;
    item.querySelector('.hi-score').textContent = `${e.score}/100`;
    item.addEventListener('click', () => {
      renderResults(e.data);
      document.querySelector('.tab[data-tab="website"]').click();
      document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    list.appendChild(item);
  });
}
// Switching the active project re-files future scans and filters the list.
document.getElementById('project-input').addEventListener('change', (e) => {
  setActiveProject(e.target.value.trim() || 'Default');
  renderHistory();
});
document.getElementById('clear-history').addEventListener('click', () => {
  if (!getHistory().length || confirm('Clear all saved scan history?')) {
    try { localStorage.removeItem(HISTORY_KEY); } catch { /* ignore */ }
    renderHistory();
  }
});
// Refresh the history list whenever its tab is opened.
document.querySelector('.tab[data-tab="history"]').addEventListener('click', renderHistory);

// ===========================================================================
// Scheduled scans panel (server-side; requires sign-in)
// ===========================================================================
const SCHED = {
  form: () => document.getElementById('sched-form'),
  list: () => document.getElementById('sched-list')
};

async function loadSchedules() {
  const gate = document.getElementById('sched-gate');
  const ui = document.getElementById('sched-ui');
  let res;
  try {
    res = await fetch('/api/schedule', { credentials: 'same-origin' });
  } catch {
    SCHED.list().innerHTML = '<p class="hint">Could not reach the server.</p>';
    return;
  }
  if (res.status === 401) { // not signed in
    gate.classList.remove('hidden');
    ui.classList.add('hidden');
    return;
  }
  gate.classList.add('hidden');
  ui.classList.remove('hidden');
  const data = await res.json().catch(() => ({ schedules: [] }));
  renderSchedules(data.schedules || []);
}

function fmtWhen(iso) { return iso ? new Date(iso).toLocaleString() : '—'; }

function renderSchedules(schedules) {
  const list = SCHED.list();
  list.innerHTML = '';
  if (!schedules.length) {
    list.innerHTML = '<p class="hint">No schedules yet. Create one above — it runs on the next cron tick (or click “Run now”).</p>';
    return;
  }
  schedules.forEach((s) => {
    const card = document.createElement('div');
    card.className = 'sched-item';
    const statusClass = s.lastStatus === 'ok' ? 'ok' : s.lastStatus === 'error' ? 'err' : 'idle';
    const lastBits = s.lastStatus === 'ok'
      ? `Last: ${s.lastGrade ?? '?'} (${s.lastScore ?? '?'}/100, ${s.lastTotal ?? 0} findings)`
      : s.lastStatus === 'error' ? `Last: failed` : 'Not run yet';
    card.innerHTML = `
      <div class="si-head">
        <span class="si-status ${statusClass}" title="${s.lastError ? String(s.lastError).replace(/"/g, '&quot;') : s.lastStatus || 'not run'}"></span>
        <span class="si-name"></span>
        <span class="si-cadence"></span>
        <span class="si-actions">
          <button type="button" class="action-btn si-run">Run now</button>
          <button type="button" class="action-btn si-del">Delete</button>
        </span>
      </div>
      <div class="si-meta">
        <span class="si-target"></span>
        <span class="si-last"></span>
        <span class="si-next"></span>
        <span class="si-hook"></span>
      </div>`;
    card.querySelector('.si-status').textContent = s.lastStatus === 'ok' ? '●' : s.lastStatus === 'error' ? '●' : '○';
    card.querySelector('.si-name').textContent = s.name;
    card.querySelector('.si-cadence').textContent = s.cadence;
    card.querySelector('.si-target').textContent = `${(CAT_LABELS[s.type] || s.type)} · ${s.target}`;
    card.querySelector('.si-last').textContent = `${lastBits} · ${fmtWhen(s.lastRunAt)}`;
    card.querySelector('.si-next').textContent = `Next: ${fmtWhen(s.nextRunAt)}`;
    card.querySelector('.si-hook').textContent = s.webhook ? `→ ${s.webhookFormat} webhook` : 'no webhook';
    card.querySelector('.si-del').addEventListener('click', async () => {
      if (!confirm(`Delete schedule “${s.name}”?`)) return;
      await fetch('/api/schedule/' + encodeURIComponent(s.id), { method: 'DELETE', credentials: 'same-origin' });
      loadSchedules();
    });
    const runBtn = card.querySelector('.si-run');
    runBtn.addEventListener('click', async () => {
      runBtn.disabled = true; runBtn.textContent = 'Running…';
      try {
        const r = await fetch('/api/schedule/' + encodeURIComponent(s.id) + '/run', { method: 'POST', credentials: 'same-origin' });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
        const res = d.result || {};
        runBtn.textContent = res.ok ? `✓ ${res.grade ?? ''} ${res.score ?? ''}` : '✗ Failed';
        if (!res.ok && res.error) showError('Schedule run failed: ' + res.error);
      } catch (e) {
        runBtn.textContent = '✗ Failed';
        showError('Run failed: ' + e.message);
      } finally {
        setTimeout(() => { runBtn.disabled = false; runBtn.textContent = 'Run now'; loadSchedules(); }, 1800);
      }
    });
    list.appendChild(card);
  });
}

document.getElementById('sched-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const type = document.getElementById('sched-type').value;
  const target = document.getElementById('sched-target').value.trim();
  if (!target) { showError('Enter a target URL for the schedule.'); return; }
  const headers = parseAuthHeadersValue(document.getElementById('sched-auth').value);
  const options = { effort: document.getElementById('sched-effort').value };
  if (headers && (type === 'website' || type === 'api')) options.headers = headers;
  if (type === 'website' || type === 'api') options.vapt = document.getElementById('sched-vapt').checked;
  const payload = {
    name: document.getElementById('sched-name').value.trim() || (type + ' scan'),
    type, target,
    cadence: document.getElementById('sched-cadence').value,
    project: document.getElementById('sched-project').value.trim() || 'Default',
    webhook: document.getElementById('sched-webhook').value.trim() || undefined,
    webhookFormat: document.getElementById('sched-format').value,
    options
  };
  const btn = document.getElementById('sched-create');
  btn.disabled = true; btn.textContent = 'Creating…';
  try {
    const r = await fetch('/api/schedule', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    document.getElementById('sched-form').reset();
    loadSchedules();
  } catch (e) {
    showError('Could not create schedule: ' + e.message);
  } finally {
    btn.disabled = false; btn.textContent = 'Create schedule';
  }
});

// Parse a "Name: value" textarea string into a headers object (shared shape with
// parseAuthHeaders, which reads from an element id).
function parseAuthHeadersValue(text) {
  const headers = {};
  String(text || '').split(/\r?\n/).forEach((line) => {
    const i = line.indexOf(':');
    if (i === -1) return;
    const name = line.slice(0, i).trim();
    const value = line.slice(i + 1).trim();
    if (name && value) headers[name] = value;
  });
  return Object.keys(headers).length ? headers : undefined;
}

document.getElementById('sched-refresh').addEventListener('click', loadSchedules);
document.querySelector('.tab[data-tab="schedules"]').addEventListener('click', loadSchedules);

// ===========================================================================
// Projects dashboard (server-side; everything about a project)
// ===========================================================================
const SEV_ORDER_DASH = ['critical', 'high', 'medium', 'low', 'info'];

async function loadProjects() {
  const gate = document.getElementById('proj-gate');
  const list = document.getElementById('proj-list');
  const detail = document.getElementById('proj-detail');
  detail.classList.add('hidden');
  if (!isAuthed()) { gate.classList.remove('hidden'); list.innerHTML = ''; return; }
  gate.classList.add('hidden');
  list.innerHTML = '<p class="hint">Loading…</p>';
  let data;
  try { data = await fetch('/api/projects', { credentials: 'same-origin' }).then((r) => r.json()); }
  catch { list.innerHTML = '<p class="hint">Could not reach the server.</p>'; return; }
  renderProjectCards(data.projects || []);
}

function sevChips(counts) {
  if (!counts) return '';
  return SEV_ORDER_DASH.filter((s) => counts[s]).map((s) =>
    `<span class="sev-chip ${s}">${counts[s]} ${s}</span>`).join('') || '<span class="sev-chip info">0 open</span>';
}

// Tiny inline SVG sparkline of scores (0–100).
function sparkline(trend) {
  if (!trend || trend.length < 2) return '';
  const w = 120, h = 28, n = trend.length;
  const pts = trend.map((t, i) => {
    const x = (i / (n - 1)) * w;
    const y = h - (Math.max(0, Math.min(100, t.score)) / 100) * h;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" preserveAspectRatio="none"><polyline points="${pts}" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>`;
}

function renderProjectCards(projects) {
  const list = document.getElementById('proj-list');
  list.innerHTML = '';
  if (!projects.length) {
    list.innerHTML = '<p class="hint">No saved scans yet. Run a scan (it files under the project set on the History tab) and it will appear here.</p>';
    return;
  }
  projects.forEach((p) => {
    const card = document.createElement('button');
    card.type = 'button';
    card.className = 'proj-card';
    card.innerHTML = `
      <div class="pc-head">
        <span class="pc-grade" style="background:${gradeColor(p.latest ? p.latest.score : 0)}">${p.latest ? p.latest.grade : '–'}</span>
        <span class="pc-name"></span>
        <span class="pc-spark"></span>
      </div>
      <div class="pc-open"></div>
      <div class="pc-meta"></div>`;
    card.querySelector('.pc-name').textContent = p.name;
    card.querySelector('.pc-spark').innerHTML = sparkline(p.trend);
    card.querySelector('.pc-open').innerHTML = sevChips(p.open);
    card.querySelector('.pc-meta').textContent =
      `${p.scanCount} scan(s) · last ${p.lastScanAt ? new Date(p.lastScanAt).toLocaleString() : '—'}`;
    card.addEventListener('click', () => openProject(p.name));
    list.appendChild(card);
  });
}

async function openProject(name) {
  const detail = document.getElementById('proj-detail');
  document.getElementById('proj-list').classList.add('hidden');
  detail.classList.remove('hidden');
  detail.innerHTML = '<p class="hint">Loading…</p>';
  let d;
  try { d = await fetch('/api/projects/' + encodeURIComponent(name), { credentials: 'same-origin' }).then((r) => r.json()); }
  catch { detail.innerHTML = '<p class="hint">Could not load project.</p>'; return; }
  if (!d.ok) { detail.innerHTML = `<p class="hint">${d.error || 'Not found.'}</p>`; return; }
  renderProjectDetail(d);
}

function backToProjects() {
  document.getElementById('proj-detail').classList.add('hidden');
  document.getElementById('proj-list').classList.remove('hidden');
}

function renderProjectDetail(d) {
  const detail = document.getElementById('proj-detail');
  const p = d.project;
  detail.innerHTML = `
    <button type="button" class="link-btn" id="proj-back">← All projects</button>
    <div class="pd-head">
      <span class="pc-grade" style="background:${gradeColor(p.latest ? p.latest.score : 0)}">${p.latest ? p.latest.grade : '–'}</span>
      <h3 class="pd-name"></h3>
      <span class="pd-open"></span>
    </div>
    <div class="pd-cols">
      <div class="pd-col">
        <h4 class="pd-h">Scans (${d.scans.length})</h4>
        <div class="pd-scans"></div>
      </div>
      <div class="pd-col">
        <h4 class="pd-h">Schedules (${d.schedules.length})</h4>
        <div class="pd-scheds"></div>
      </div>
    </div>
    <h4 class="pd-h">Open findings — current across the project (${d.rollup.filter((f) => !f.dismissed).length})</h4>
    <div class="pd-rollup"></div>`;
  detail.querySelector('.pd-name').textContent = p.name;
  detail.querySelector('.pd-open').innerHTML = sevChips(p.open);
  detail.querySelector('#proj-back').addEventListener('click', backToProjects);

  // Scans list — click to open the saved report.
  const scansEl = detail.querySelector('.pd-scans');
  if (!d.scans.length) scansEl.innerHTML = '<p class="hint">No scans.</p>';
  d.scans.forEach((s) => {
    const row = document.createElement('div');
    row.className = 'pd-scan';
    row.innerHTML = `<button type="button" class="pd-scan-open">
        <span class="pd-scan-grade" style="background:${gradeColor(s.score)}">${s.grade}</span>
        <span class="pd-scan-main"><span class="pd-scan-target"></span><span class="pd-scan-meta"></span></span>
      </button><button type="button" class="pd-scan-del" title="Delete scan">✕</button>`;
    row.querySelector('.pd-scan-target').textContent = s.target;
    row.querySelector('.pd-scan-meta').textContent = `${CAT_LABELS[s.type] || s.type} · ${s.total} findings · ${new Date(s.ts).toLocaleString()}`;
    row.querySelector('.pd-scan-open').addEventListener('click', () => viewSavedScan(s.id));
    row.querySelector('.pd-scan-del').addEventListener('click', async () => {
      if (!confirm('Delete this saved scan?')) return;
      await fetch('/api/scans/' + encodeURIComponent(s.id), { method: 'DELETE', credentials: 'same-origin' });
      openProject(p.name);
    });
    scansEl.appendChild(row);
  });

  // Schedules summary.
  const schEl = detail.querySelector('.pd-scheds');
  if (!d.schedules.length) schEl.innerHTML = '<p class="hint">None. Create one on the Schedules tab (set its project to this name).</p>';
  d.schedules.forEach((s) => {
    const row = document.createElement('div');
    row.className = 'pd-sched';
    row.innerHTML = `<span class="si-cadence">${s.cadence}</span> <span class="pd-sched-name"></span>
      <span class="pd-sched-meta"></span>`;
    row.querySelector('.pd-sched-name').textContent = s.name;
    row.querySelector('.pd-sched-meta').textContent = s.lastStatus === 'ok'
      ? `last ${s.lastGrade ?? '?'} · next ${s.nextRunAt ? new Date(s.nextRunAt).toLocaleDateString() : '—'}`
      : (s.lastStatus === 'error' ? 'last run failed' : 'not run yet');
    schEl.appendChild(row);
  });

  // Findings rollup with server-side dismiss.
  const rollEl = detail.querySelector('.pd-rollup');
  if (!d.rollup.length) rollEl.innerHTML = '<p class="hint">No findings.</p>';
  d.rollup.forEach((f) => {
    const el = document.createElement('div');
    el.className = 'pd-finding ' + f.severity + (f.dismissed ? ' dismissed' : '');
    el.innerHTML = `
      <span class="f-sev ${f.severity}">${f.severity}</span>
      ${f.confidence ? `<span class="f-conf ${f.confidence}">${f.confidence}</span>` : ''}
      <span class="pd-f-title"></span>
      <span class="pd-f-target"></span>
      <button type="button" class="pd-f-dismiss">${f.dismissed ? 'Restore' : 'Dismiss'}</button>
      ${f.dismissed ? `<span class="pd-f-reason"></span>` : ''}`;
    el.querySelector('.pd-f-title').textContent = f.title;
    el.querySelector('.pd-f-target').textContent = f.fromTarget || '';
    if (f.dismissed) el.querySelector('.pd-f-reason').textContent = '— ' + f.dismissed;
    el.querySelector('.pd-f-dismiss').addEventListener('click', async () => {
      if (f.dismissed) {
        await fetch('/api/dismissals/' + encodeURIComponent(f.fingerprint), { method: 'DELETE', credentials: 'same-origin' });
      } else {
        const reason = prompt('Why dismiss this finding? (false positive, accepted risk, out of scope…)');
        if (reason === null) return;
        await fetch('/api/dismissals', {
          method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ fingerprint: f.fingerprint, reason: reason.trim(), title: f.title })
        });
      }
      openProject(p.name); // refresh
    });
    rollEl.appendChild(el);
  });
}

// Load a saved report into the main results view.
async function viewSavedScan(id) {
  try {
    const data = await fetch('/api/scans/' + encodeURIComponent(id), { credentials: 'same-origin' }).then((r) => r.json());
    if (!data.ok) { showError(data.error || 'Could not load scan.'); return; }
    renderResults(data);
    document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (e) { showError('Could not load scan: ' + e.message); }
}

// ===========================================================================
// Analytics (VART) — aggregate posture across ALL of the account's scans.
// Everything here is fed by /api/analytics (owner-scoped, secret-masked, no
// external calls); the export is generated entirely in the browser.
// ===========================================================================
let lastAnalytics = null;

function anEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function loadAnalytics() {
  const gate = document.getElementById('an-gate');
  const empty = document.getElementById('an-empty');
  const body = document.getElementById('an-body');
  const exportBtn = document.getElementById('an-export');
  empty.classList.add('hidden');
  if (!isAuthed()) {
    gate.classList.remove('hidden'); body.classList.add('hidden'); body.innerHTML = '';
    exportBtn.hidden = true; lastAnalytics = null; return;
  }
  gate.classList.add('hidden');
  body.classList.remove('hidden');
  body.innerHTML = '<p class="hint">Loading…</p>';
  let data;
  try { data = await fetch('/api/analytics', { credentials: 'same-origin' }).then((r) => r.json()); }
  catch { body.innerHTML = '<p class="hint">Could not reach the server.</p>'; return; }
  if (!data || !data.ok) { body.innerHTML = '<p class="hint">Could not build analytics.</p>'; return; }
  lastAnalytics = data;
  if (data.empty) {
    body.classList.add('hidden'); body.innerHTML = '';
    empty.classList.remove('hidden'); exportBtn.hidden = true; return;
  }
  exportBtn.hidden = false;
  renderAnalytics(data);
}

// Horizontal bar chart. rows: [{label, count, color}] — labels are trusted
// (server-side constant names) but still escaped defensively.
function anBars(rows, emptyMsg) {
  if (!rows.length) return `<p class="hint">${anEsc(emptyMsg || 'Nothing to show.')}</p>`;
  const max = Math.max(1, ...rows.map((r) => r.count));
  return '<div class="an-bars">' + rows.map((r) =>
    `<div class="an-bar-row">
       <span class="an-bar-label">${anEsc(r.label)}</span>
       <span class="an-bar-track"><span class="an-bar-fill" style="width:${(r.count / max * 100).toFixed(1)}%;background:${r.color || 'var(--accent)'}"></span></span>
       <span class="an-bar-val">${r.count}</span>
     </div>`).join('') + '</div>';
}

// Wider sparkline for the trend card (area + line).
function anSparkline(trend, w, h) {
  if (!trend || trend.length < 2) return '<p class="hint">Run more scans to build a trend.</p>';
  w = w || 560; h = h || 90;
  const n = trend.length;
  const xy = trend.map((t, i) => [(i / (n - 1)) * w, h - (Math.max(0, Math.min(100, t.score)) / 100) * h]);
  const line = xy.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ');
  const area = `0,${h} ` + line + ` ${w},${h}`;
  return `<svg class="an-spark" viewBox="0 0 ${w} ${h}" width="100%" height="${h}" preserveAspectRatio="none" role="img" aria-label="Score trend">
     <polygon points="${area}" fill="var(--accent)" opacity="0.12"/>
     <polyline points="${line}" fill="none" stroke="var(--accent)" stroke-width="2"/>
   </svg>`;
}

function renderAnalytics(d) {
  const body = document.getElementById('an-body');
  const t = d.totals, p = d.posture, sev = d.severity || {};
  const critHigh = (sev.critical || 0) + (sev.high || 0);

  const kpis = [
    { label: 'Risk grade', big: p.grade, sub: p.score + ' / 100', color: gradeColor(p.score) },
    { label: 'Open findings', big: t.open, sub: t.dismissed + ' dismissed' },
    { label: 'Critical + High', big: critHigh, sub: (sev.critical || 0) + ' crit · ' + (sev.high || 0) + ' high', color: critHigh ? 'var(--critical)' : 'var(--accent-2)' },
    { label: 'Scans run', big: t.scans, sub: t.targets + ' target(s)' },
    { label: 'Projects', big: t.projects, sub: 'tracked' }
  ];
  const kpiHtml = '<div class="an-kpis">' + kpis.map((k) =>
    `<div class="an-kpi"><span class="an-kpi-big" style="color:${k.color || 'var(--text)'}">${anEsc(k.big)}</span>
       <span class="an-kpi-label">${anEsc(k.label)}</span><span class="an-kpi-sub">${anEsc(k.sub)}</span></div>`).join('') + '</div>';

  const sevRows = (d.severityOrder || SEV_ORDER_DASH).filter((s) => sev[s]).map((s) =>
    ({ label: s, count: sev[s], color: SEV_COLORS[s] }));
  const owaspRows = (d.owaspBreakdown || []).map((o) => ({ label: `${o.code} · ${o.name}`, count: o.count, color: 'var(--accent)' }));
  const catRows = (d.categoryBreakdown || []).map((c) => ({ label: c.label, count: c.count, color: 'var(--accent-2)' }));
  const conf = d.confidence || {};
  const confRows = ['high', 'medium', 'low'].filter((c) => conf[c]).map((c) =>
    ({ label: c + ' confidence', count: conf[c], color: c === 'high' ? 'var(--high)' : c === 'medium' ? 'var(--medium)' : 'var(--low)' }));

  const trendHtml = `<div class="an-card"><h3 class="an-h">Risk score over time</h3>${anSparkline(d.trend)}
     <p class="an-note">${d.trend.length} scan(s) · latest grade <strong>${anEsc(p.grade)}</strong> (${p.score}/100)</p></div>`;

  const gridHtml = `<div class="an-grid">
     <div class="an-card"><h3 class="an-h">Open findings by severity</h3>${anBars(sevRows, 'No open findings — nice.')}</div>
     <div class="an-card"><h3 class="an-h">OWASP Top-10 breakdown</h3>${anBars(owaspRows, 'No OWASP-mapped findings.')}</div>
     <div class="an-card"><h3 class="an-h">Findings by category</h3>${anBars(catRows, 'No findings.')}</div>
     <div class="an-card"><h3 class="an-h">Confidence</h3>${anBars(confRows, 'No findings.')}</div>
   </div>`;

  const projHtml = `<div class="an-card"><h3 class="an-h">Projects</h3><div class="an-proj-list">` +
    (d.projects || []).map((pr) =>
      `<div class="an-proj">
         <span class="pc-grade" style="background:${gradeColor(pr.latest ? pr.latest.score : 0)}">${pr.latest ? anEsc(pr.latest.grade) : '–'}</span>
         <span class="an-proj-name">${anEsc(pr.name)}</span>
         <span class="an-proj-spark">${sparkline(pr.trend)}</span>
         <span class="an-proj-open">${sevChips(pr.open)}</span>
         <span class="an-proj-meta">${pr.scanCount} scan(s)</span>
       </div>`).join('') + '</div></div>';

  const fixHtml = `<div class="an-card"><h3 class="an-h">Top fixes by priority</h3><div class="an-fixes">` +
    (d.topFindings || []).map((f, i) =>
      `<div class="an-fix ${anEsc(f.severity)}">
         <span class="an-fix-rank">${i + 1}</span>
         <span class="f-sev ${anEsc(f.severity)}">${anEsc(f.severity)}</span>
         <div class="an-fix-main">
           <div class="an-fix-title">${anEsc(f.title)}</div>
           <div class="an-fix-tags">
             ${f.owasp ? `<span class="f-owasp">${anEsc(f.owasp)}</span>` : ''}
             <span class="f-cat">${anEsc(CAT_ICONS[f.category] || '•')} ${anEsc(f.categoryLabel || f.category)}</span>
             <span class="an-fix-conf">${anEsc(f.confidence || '')} confidence</span>
             <span class="an-fix-target">${anEsc(f.target || '')}</span>
           </div>
           ${f.remediation ? `<div class="an-fix-fix">${anEsc(f.remediation)}</div>` : ''}
         </div>
       </div>`).join('') + '</div></div>';

  body.innerHTML = kpiHtml + trendHtml + gridHtml + projHtml + fixHtml;
}

// Build a self-contained HTML report from the loaded analytics and download it.
// No network is touched; the data is already secret-masked server-side.
function exportAnalytics() {
  const d = lastAnalytics;
  if (!d || d.empty) return;
  const sev = d.severity || {};
  const row = (label, val) => `<tr><td>${anEsc(label)}</td><td>${anEsc(val)}</td></tr>`;
  const barTable = (rows) => rows.length
    ? '<table class="t">' + rows.map((r) => row(r.label, r.count)).join('') + '</table>'
    : '<p>None.</p>';
  const html =
`<!doctype html><html><head><meta charset="utf-8"><title>SentryScan Analytics Report</title>
<style>body{font:14px/1.5 system-ui,sans-serif;max-width:860px;margin:40px auto;padding:0 20px;color:#1a1f2e}
h1{margin:0 0 4px}h2{margin:28px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px}
.grade{font-size:40px;font-weight:800}.muted{color:#667}.t{border-collapse:collapse;width:100%}
.t td{border-bottom:1px solid #eee;padding:6px 8px}.t td:last-child{text-align:right;width:80px;font-variant-numeric:tabular-nums}
.fix{margin:10px 0;padding:10px 12px;border-left:3px solid #c33;background:#faf7f7}.fix .m{color:#556;font-size:13px}</style></head><body>
<h1>SentryScan — Vulnerability Analytics</h1>
<p class="muted">Generated ${anEsc(new Date(d.generatedAt).toLocaleString())} · Private report · secrets masked</p>
<p class="grade" style="color:${gradeColor(d.posture.score)}">${anEsc(d.posture.grade)} <span style="font-size:18px" class="muted">(${d.posture.score}/100)</span></p>
<h2>Overview</h2><table class="t">
${row('Scans run', d.totals.scans)}${row('Projects', d.totals.projects)}${row('Targets', d.totals.targets)}
${row('Open findings', d.totals.open)}${row('Dismissed', d.totals.dismissed)}</table>
<h2>Open findings by severity</h2>${barTable((d.severityOrder || []).filter((s) => sev[s]).map((s) => ({ label: s, count: sev[s] })))}
<h2>OWASP Top-10 breakdown</h2>${barTable((d.owaspBreakdown || []).map((o) => ({ label: o.code + ' ' + o.name, count: o.count })))}
<h2>By category</h2>${barTable((d.categoryBreakdown || []).map((c) => ({ label: c.label, count: c.count })))}
<h2>Top fixes by priority</h2>
${(d.topFindings || []).map((f, i) => `<div class="fix"><strong>${i + 1}. [${anEsc(f.severity)}] ${anEsc(f.title)}</strong>
<div class="m">${anEsc(f.owasp || '')} · ${anEsc(f.categoryLabel || '')} · ${anEsc(f.confidence || '')} confidence · ${anEsc(f.target || '')}</div>
${f.remediation ? `<div class="m">Fix: ${anEsc(f.remediation)}</div>` : ''}</div>`).join('')}
</body></html>`;
  const blob = new Blob([html], { type: 'text/html' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'sentryscan-analytics-' + new Date().toISOString().slice(0, 10) + '.html';
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

document.getElementById('an-refresh').addEventListener('click', loadAnalytics);
document.getElementById('an-export').addEventListener('click', exportAnalytics);
document.querySelector('.tab[data-tab="analytics"]').addEventListener('click', loadAnalytics);

document.getElementById('proj-refresh').addEventListener('click', loadProjects);
document.querySelector('.tab[data-tab="projects"]').addEventListener('click', loadProjects);
// Re-hydrate dismissals + refresh the dashboard whenever auth state changes.
// Because dismissals are now per-account, switching identity must also re-render
// the current results and refresh whichever dashboard panel is open (otherwise a
// prior user's project cards / schedules linger until a manual tab click).
document.addEventListener('sentry-auth', async () => {
  await hydrateDismissals();
  if (Array.isArray(allFindings) && allFindings.length) {
    try { renderFindings(); } catch { /* no results rendered yet */ }
  }
  const active = document.querySelector('.tab.active');
  const tab = active && active.dataset.tab;
  if (tab === 'projects') loadProjects();
  else if (tab === 'schedules') loadSchedules();
  else if (tab === 'analytics') loadAnalytics();
});

// Populate everything once the DOM is ready.
document.querySelectorAll('.preset-chips').forEach((c) => {
  const t = c.dataset.target;
  const tabName = t === 'api-input' ? 'api' : t === 'vapt-input' ? 'vapt' : 'website';
  buildPresetChips(c, t === 'api-input' ? API_PRESETS : WEBSITE_PRESETS, tabName);
});
buildLearnContent();
buildVaptContent();
initProfiles();
renderHistory();
