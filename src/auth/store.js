// Minimal persistent user store (JSON file). Stores only email + bcrypt hash —
// never plaintext passwords. Single-node; swap for a real DB to scale.
// The data directory is gitignored so credentials never enter version control.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'data');
const FILE = path.join(DIR, 'users.json');

function load() {
  try { return JSON.parse(readFileSync(FILE, 'utf8')); }
  catch { return {}; }
}
function save(users) {
  if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true });
  writeFileSync(FILE, JSON.stringify(users, null, 2), { mode: 0o600 });
}

const norm = (email) => String(email || '').trim().toLowerCase();

export function getUser(email) { return load()[norm(email)] || null; }
export function hasUser(email) { return !!load()[norm(email)]; }
export function userCount() { return Object.keys(load()).length; }

export function putUser(email, passwordHash) {
  const users = load();
  const key = norm(email);
  users[key] = { email: key, passwordHash, plan: 'free', createdAt: new Date().toISOString() };
  save(users);
  return users[key];
}

// Update a user's plan (called only from the verified Stripe webhook).
export function setUserPlan(email, plan) {
  const users = load();
  const key = norm(email);
  if (!users[key]) return null;
  users[key].plan = plan;
  users[key].planUpdatedAt = new Date().toISOString();
  save(users);
  return users[key];
}
