// Per-account finding dismissals (JSON file). Keyed by owner then by finding
// fingerprint so a dismissal applies across every scan that surfaces the same
// issue, and syncs across the user's devices (unlike the browser-local fallback).
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'data');
const FILE = path.join(DIR, 'dismissals.json');

function load() {
  try { return JSON.parse(readFileSync(FILE, 'utf8')); }
  catch { return {}; }
}
function save(map) {
  if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true });
  writeFileSync(FILE, JSON.stringify(map, null, 2), { mode: 0o600 });
}

const norm = (email) => String(email || '').trim().toLowerCase();

// { [fingerprint]: { reason, ts, title } } for one user.
export function getDismissals(ownerEmail) {
  return load()[norm(ownerEmail)] || {};
}

export function setDismissal(ownerEmail, fingerprint, reason, title) {
  const map = load();
  const owner = norm(ownerEmail);
  if (!map[owner]) map[owner] = {};
  map[owner][fingerprint] = { reason: String(reason || '(no reason given)').slice(0, 500), ts: new Date().toISOString(), title: String(title || '').slice(0, 240) };
  save(map);
  return map[owner][fingerprint];
}

export function clearDismissal(ownerEmail, fingerprint) {
  const map = load();
  const owner = norm(ownerEmail);
  if (map[owner] && map[owner][fingerprint]) { delete map[owner][fingerprint]; save(map); return true; }
  return false;
}
