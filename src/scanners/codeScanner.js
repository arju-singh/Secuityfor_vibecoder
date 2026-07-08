// Static analysis of uploaded code: secret detection, dangerous patterns,
// sensitive-file presence, and real dependency-vulnerability lookups via OSV.dev.
import AdmZip from 'adm-zip';
import { SECRET_RULES, CODE_RULES, SENSITIVE_FILES, SCANNABLE_EXT, extOf } from './patterns.js';

const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip files larger than 2 MB for line scanning
const MAX_FILES = 5000;
// Zip-bomb guards: cap any single decompressed entry and the total decompressed
// volume so a small malicious archive can't inflate to gigabytes and OOM us.
const MAX_ENTRY_BYTES = 10 * 1024 * 1024;   // 10 MB per extracted file
const MAX_TOTAL_BYTES = 200 * 1024 * 1024;  // 200 MB total across the archive

function finding(severity, title, description, remediation, evidence, location) {
  return { severity, title, description, remediation, evidence: evidence || null, location: location || null };
}

// Restrict a set of { path } entries to one or more directory/path prefixes so a
// scan can target the modules that matter (large-monorepo scoping). Prefixes are
// matched case-insensitively against the normalized path; a bare prefix matches
// both the directory ("src/auth") and files directly named by it. Empty/omitted
// prefixes return every entry unchanged.
export function scopeEntries(entries, paths) {
  const prefixes = (paths || [])
    .map((p) => String(p || '').trim().replace(/^\.?\/+/, '').replace(/\/+$/, '').toLowerCase())
    .filter(Boolean);
  if (!prefixes.length) return entries;
  return entries.filter((e) => {
    const p = String(e.path || '').toLowerCase();
    return prefixes.some((pre) => p === pre || p.startsWith(pre + '/'));
  });
}

function lineOfIndex(content, index) {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === '\n') line++;
  }
  return line;
}

function isBinary(buf) {
  const len = Math.min(buf.length, 8000);
  for (let i = 0; i < len; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

// Extract { path, buffer } entries from either a zip or a set of raw files.
export function entriesFromZip(buffer) {
  const zip = new AdmZip(buffer);
  const out = [];
  let total = 0;
  for (const e of zip.getEntries()) {
    if (e.isDirectory) continue;
    if (out.length >= MAX_FILES) break;
    // Skip dependency/build dirs that are not the user's own code.
    if (/(^|\/)(node_modules|\.next|dist|build|vendor|bower_components)\//i.test(e.entryName)) continue;
    // Reject a decompressed entry that is implausibly large (zip bomb) using the
    // header's declared size BEFORE inflating it, and stop once the running total
    // would exceed the archive cap. header.size is the uncompressed byte length.
    const declared = e.header && e.header.size;
    if (typeof declared === 'number' && declared > MAX_ENTRY_BYTES) continue;
    if (total + (declared || 0) > MAX_TOTAL_BYTES) break;
    const data = e.getData();
    total += data.length;
    if (data.length > MAX_ENTRY_BYTES) continue; // guard against a lying header
    if (total > MAX_TOTAL_BYTES) break;
    out.push({ path: e.entryName, buffer: data });
  }
  return out;
}

function scanText(path, content) {
  const findings = [];
  const ext = extOf(path);

  // Secrets
  for (const rule of SECRET_RULES) {
    rule.regex.lastIndex = 0;
    let m;
    let hits = 0;
    while ((m = rule.regex.exec(content)) !== null && hits < 50) {
      hits++;
      const value = rule.group ? m[rule.group] : (m[1] || m[0]);
      if (!value) continue;
      if (rule.ignoreValues && rule.ignoreValues.test(value)) continue;
      const line = lineOfIndex(content, m.index);
      findings.push(finding(rule.severity, rule.title,
        `A ${rule.title} was detected in source code.`,
        rule.remediation,
        redact(value),
        `${path}:${line}`));
      if (m.index === rule.regex.lastIndex) rule.regex.lastIndex++;
    }
  }

  // Dangerous code patterns
  for (const rule of CODE_RULES) {
    if (rule.extensions && !rule.extensions.includes(ext)) continue;
    rule.regex.lastIndex = 0;
    let m;
    let hits = 0;
    while ((m = rule.regex.exec(content)) !== null && hits < 50) {
      hits++;
      const line = lineOfIndex(content, m.index);
      findings.push(finding(rule.severity, rule.title,
        `${rule.title} found, which is a common source of vulnerabilities.`,
        rule.remediation,
        snippet(content, m.index),
        `${path}:${line}`));
      if (m.index === rule.regex.lastIndex) rule.regex.lastIndex++;
    }
  }
  return findings;
}

function redact(value) {
  if (value.length <= 8) return value[0] + '***';
  return value.slice(0, 4) + '…' + value.slice(-4) + ` (${value.length} chars)`;
}

function snippet(content, index) {
  const start = content.lastIndexOf('\n', index) + 1;
  let end = content.indexOf('\n', index);
  if (end === -1) end = content.length;
  return content.slice(start, end).trim().slice(0, 160);
}

// --- Dependency vulnerabilities via OSV.dev --------------------------------
function collectDependencies(entries) {
  const deps = []; // { ecosystem, name, version }
  for (const e of entries) {
    const base = e.path.split('/').pop().toLowerCase();
    let text;
    try { text = e.buffer.toString('utf8'); } catch { continue; }

    if (base === 'package.json') {
      try {
        const pkg = JSON.parse(text);
        for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
          for (const [name, range] of Object.entries(pkg[field] || {})) {
            const version = String(range).replace(/^[\^~>=<\s]+/, '').split(' ')[0];
            if (version && /^\d/.test(version)) deps.push({ ecosystem: 'npm', name, version });
          }
        }
      } catch { /* malformed package.json */ }
    } else if (base === 'requirements.txt') {
      for (const line of text.split('\n')) {
        const m = line.match(/^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][^\s;#]*)/);
        if (m) deps.push({ ecosystem: 'PyPI', name: m[1], version: m[2] });
      }
    } else if (base === 'composer.json') {
      try {
        const pkg = JSON.parse(text);
        for (const [name, range] of Object.entries(pkg.require || {})) {
          const version = String(range).replace(/^[\^~>=<\s]+/, '').split(' ')[0];
          if (/^\d/.test(version)) deps.push({ ecosystem: 'Packagist', name, version });
        }
      } catch { /* ignore */ }
    } else if (base === 'gemfile.lock') {
      const re = /^\s{4}([a-z0-9_\-]+)\s\(([0-9][^)]*)\)/gim;
      let m;
      while ((m = re.exec(text)) !== null) deps.push({ ecosystem: 'RubyGems', name: m[1], version: m[2] });
    }
  }
  // De-duplicate
  const seen = new Set();
  return deps.filter(d => {
    const k = `${d.ecosystem}:${d.name}@${d.version}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  }).slice(0, 400);
}

async function queryOsv(deps) {
  if (!deps.length) return { findings: [], checked: 0 };
  const queries = deps.map(d => ({ version: d.version, package: { name: d.name, ecosystem: d.ecosystem } }));
  let data;
  try {
    const res = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(20000)
    });
    if (!res.ok) throw new Error(`OSV responded ${res.status}`);
    data = await res.json();
  } catch (e) {
    return { findings: [], checked: deps.length, error: `Dependency vulnerability lookup unavailable: ${e.message}` };
  }

  const results = data.results || [];
  const vulnerable = [];
  results.forEach((r, i) => {
    if (r && Array.isArray(r.vulns) && r.vulns.length) {
      vulnerable.push({ dep: deps[i], vulns: r.vulns });
    }
  });
  if (!vulnerable.length) return { findings: [], checked: deps.length };

  // Fetch detail (severity + summary) for the discovered vuln IDs.
  const findings = [];
  await Promise.allSettled(vulnerable.map(async ({ dep, vulns }) => {
    const ids = vulns.map(v => v.id).slice(0, 8);
    const details = await Promise.allSettled(ids.map(id =>
      fetch(`https://api.osv.dev/v1/vulns/${id}`, { signal: AbortSignal.timeout(15000) }).then(r => r.ok ? r.json() : null)
    ));
    let worst = 'medium';
    const summaries = [];
    for (const d of details) {
      if (d.status !== 'fulfilled' || !d.value) continue;
      const v = d.value;
      const sev = osvSeverity(v);
      if (rank(sev) > rank(worst)) worst = sev;
      summaries.push(`${v.id}: ${(v.summary || (v.aliases || []).join(', ') || 'see advisory').slice(0, 120)}`);
    }
    findings.push(finding(worst, `Vulnerable dependency: ${dep.name}@${dep.version}`,
      `${ids.length} known advisory(ies) affect this ${dep.ecosystem} package version.`,
      `Upgrade ${dep.name} to a patched release. Run your package manager's audit tool to confirm the fixed version.`,
      summaries.join('\n').slice(0, 500),
      dep.name));
  }));
  return { findings, checked: deps.length };
}

// Compute a CVSS v3.0/3.1 base score from its vector string (per the FIRST spec),
// returning a 0–10 number or null if the vector can't be parsed. Deterministic —
// no rounding surprises beyond the spec's round-up-to-one-decimal.
function cvssV3BaseScore(vector) {
  const m = {};
  for (const part of String(vector).split('/')) {
    const [k, v] = part.split(':');
    if (k && v) m[k] = v;
  }
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const changed = m.S === 'C';
  const PR = (changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 })[m.PR];
  const cia = { H: 0.56, L: 0.22, N: 0 };
  const C = cia[m.C], I = cia[m.I], A = cia[m.A];
  if ([AV, AC, UI, PR, C, I, A].some((x) => x === undefined)) return null;

  const iss = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * AV * AC * PR * UI;
  const roundup = (x) => Math.ceil(x * 10) / 10;
  const raw = changed ? 1.08 * (impact + exploitability) : impact + exploitability;
  return roundup(Math.min(raw, 10));
}

function severityForScore(score) {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

function osvSeverity(vuln) {
  const sevArr = vuln.severity || [];
  // Prefer an actual CVSS base score parsed from the vector.
  for (const s of sevArr) {
    if (typeof s.score === 'string' && /^CVSS:3/.test(s.score)) {
      const score = cvssV3BaseScore(s.score);
      if (score != null) return severityForScore(score);
    }
  }
  // Database-specific severity (GHSA) often in ecosystem_specific or database_specific.
  const ds = vuln.database_specific && vuln.database_specific.severity;
  if (ds) {
    const map = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };
    if (map[String(ds).toUpperCase()]) return map[String(ds).toUpperCase()];
  }
  // A CVSS vector we couldn't parse (e.g. v2) still signals a real advisory.
  if (sevArr.some((s) => typeof s.score === 'string' && s.score.startsWith('CVSS'))) return 'high';
  return 'medium';
}

const RANKS = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function rank(s) { return RANKS[s] ?? 2; }

export async function scanCode(entries) {
  if (entries.length > MAX_FILES) entries = entries.slice(0, MAX_FILES);
  const findings = [];
  let scannedFiles = 0;
  let textFiles = 0;

  for (const e of entries) {
    scannedFiles++;
    const path = e.path.replace(/\\/g, '/');

    // Sensitive file presence
    for (const sf of SENSITIVE_FILES) {
      if (sf.match.test(path)) {
        findings.push(finding(sf.severity, sf.title,
          `The file "${path}" should not be part of a deployable web bundle.`,
          sf.remediation, path, path));
      }
    }

    if (isBinary(e.buffer)) continue;
    const ext = extOf(path);
    const base = path.split('/').pop();
    const isDotEnv = /^\.env/i.test(base);
    if (!SCANNABLE_EXT.has(ext) && !isDotEnv) continue;
    if (e.buffer.length > MAX_FILE_BYTES) continue;

    textFiles++;
    const content = e.buffer.toString('utf8');
    findings.push(...scanText(path, content));
  }

  // Dependency vulnerabilities (network)
  const deps = collectDependencies(entries);
  const osv = await queryOsv(deps);
  findings.push(...osv.findings);

  const meta = {
    filesScanned: scannedFiles,
    textFilesAnalyzed: textFiles,
    dependenciesChecked: osv.checked || 0,
    notes: osv.error ? [osv.error] : []
  };
  return { type: 'code', meta, findings };
}
