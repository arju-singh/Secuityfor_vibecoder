// Persistent store for recurring scan schedules (JSON file), mirroring the user
// store's pattern. Single-node; swap for a real DB to scale. The data directory
// is gitignored and the file is written 0600 because a schedule MAY carry auth
// headers for authenticated scans.
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'data');
const FILE = path.join(DIR, 'schedules.json');

function load() {
  try { return JSON.parse(readFileSync(FILE, 'utf8')); }
  catch { return {}; }
}
function save(map) {
  if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true });
  const tmp = `${FILE}.${process.pid}.tmp`; // atomic write — see other stores
  writeFileSync(tmp, JSON.stringify(map, null, 2), { mode: 0o600 });
  renameSync(tmp, FILE);
}

const norm = (email) => String(email || '').trim().toLowerCase();

// How far apart runs are, per cadence.
export const CADENCE_MS = {
  hourly: 60 * 60 * 1000,
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000
};

export function listSchedules(ownerEmail) {
  const all = Object.values(load());
  return ownerEmail ? all.filter((s) => s.ownerEmail === norm(ownerEmail)) : all;
}
export function getSchedule(id) { return load()[id] || null; }

export function putSchedule(schedule) {
  const map = load();
  map[schedule.id] = schedule;
  save(map);
  return schedule;
}

// Merge a patch into a schedule. Returns the updated record, or null if absent.
export function patchSchedule(id, patch) {
  const map = load();
  if (!map[id]) return null;
  Object.assign(map[id], patch);
  save(map);
  return map[id];
}

export function deleteSchedule(id) {
  const map = load();
  if (!map[id]) return false;
  delete map[id];
  save(map);
  return true;
}
