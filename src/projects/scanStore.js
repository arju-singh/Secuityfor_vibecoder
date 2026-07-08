// Persistent per-user scan store (JSON file), mirroring the user/schedule stores.
// Each saved scan keeps enough to rebuild the report view and to aggregate a
// project dashboard. Single-node; swap for a real DB to scale.
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'data');
const FILE = path.join(DIR, 'scans.json');

// Caps so the file can't grow without bound. Findings are capped per scan; the
// oldest scans past the per-user limit are dropped on save.
const MAX_SCANS_PER_USER = 200;
const MAX_FINDINGS_PER_SCAN = 1000;

function load() {
  try { return JSON.parse(readFileSync(FILE, 'utf8')); }
  catch { return {}; }
}
function save(map) {
  if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true });
  // Atomic write: serialize to a temp file, then rename over the target. A crash
  // mid-write leaves the previous good file intact instead of a truncated one.
  const tmp = `${FILE}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(map), { mode: 0o600 });
  renameSync(tmp, FILE);
}

const norm = (email) => String(email || '').trim().toLowerCase();
const projOf = (p) => (String(p || 'Default').trim() || 'Default').slice(0, 60);

// Persist a finished report under owner + project. Stores a trimmed copy (report
// findings can be large). Returns the saved scan's summary record.
export function saveScan(ownerEmail, project, report) {
  const owner = norm(ownerEmail);
  if (!owner) return null;
  const map = load();
  const id = randomUUID();
  const findings = (report.findings || []).slice(0, MAX_FINDINGS_PER_SCAN);
  const rec = {
    id,
    ownerEmail: owner,
    project: projOf(project),
    ts: new Date().toISOString(),
    type: report.type,
    target: report.meta?.target || report.meta?.repo || report.meta?.finalUrl || report.type,
    score: report.score,
    grade: report.grade,
    total: report.total,
    counts: report.counts || {},
    meta: report.meta || {},
    categories: report.categories || [],
    findings
  };
  map[id] = rec;

  // Trim this user's oldest scans beyond the cap.
  const mine = Object.values(map).filter((s) => s.ownerEmail === owner)
    .sort((a, b) => b.ts.localeCompare(a.ts));
  for (const old of mine.slice(MAX_SCANS_PER_USER)) delete map[old.id];

  save(map);
  return summaryOf(rec);
}

export function getScan(id) { return load()[id] || null; }

export function deleteScan(id) {
  const map = load();
  if (!map[id]) return false;
  delete map[id];
  save(map);
  return true;
}

// Light record for lists/aggregates (no findings array).
export function summaryOf(s) {
  const { findings, meta, categories, ...rest } = s;
  return { ...rest, target: s.target };
}

export function listScans(ownerEmail, project) {
  const owner = norm(ownerEmail);
  let mine = Object.values(load()).filter((s) => s.ownerEmail === owner);
  if (project) mine = mine.filter((s) => s.project === projOf(project));
  return mine.sort((a, b) => b.ts.localeCompare(a.ts));
}

// Distinct project names the user has scans under.
export function listProjectNames(ownerEmail) {
  const owner = norm(ownerEmail);
  const set = new Set();
  for (const s of Object.values(load())) if (s.ownerEmail === owner) set.add(s.project);
  return [...set];
}
