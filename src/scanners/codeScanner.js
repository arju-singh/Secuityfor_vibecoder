// Static analysis of uploaded code: secret detection, dangerous patterns,
// sensitive-file presence, and real dependency-vulnerability lookups via OSV.dev.
import AdmZip from 'adm-zip';
import { SECRET_RULES, CODE_RULES, SENSITIVE_FILES, SCANNABLE_EXT, extOf } from './patterns.js';

const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip files larger than 2 MB for line scanning
const MAX_FILES = 5000;

function finding(severity, title, description, remediation, evidence, location) {
  return { severity, title, description, remediation, evidence: evidence || null, location: location || null };
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
  for (const e of zip.getEntries()) {
    if (e.isDirectory) continue;
    if (out.length >= MAX_FILES) break;
    // Skip dependency/build dirs that are not the user's own code.
    if (/(^|\/)(node_modules|\.next|dist|build|vendor|bower_components)\//i.test(e.entryName)) continue;
    out.push({ path: e.entryName, buffer: e.getData() });
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

function osvSeverity(vuln) {
  // Prefer CVSS score if present.
  const sevArr = vuln.severity || [];
  for (const s of sevArr) {
    if (typeof s.score === 'string') {
      const m = s.score.match(/\/A:[NLH]/) ? null : null; // placeholder, parse base score below
    }
  }
  // Database-specific severity (GHSA) often in ecosystem_specific or database_specific.
  const ds = vuln.database_specific && vuln.database_specific.severity;
  if (ds) {
    const map = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', LOW: 'low' };
    if (map[String(ds).toUpperCase()]) return map[String(ds).toUpperCase()];
  }
  // CVSS vector base score heuristic
  for (const s of sevArr) {
    if (typeof s.score === 'string' && s.score.startsWith('CVSS')) {
      // We cannot fully parse CVSS here; treat presence as high.
      return 'high';
    }
  }
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
