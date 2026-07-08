// Minimal persistent user store (JSON file). Stores only email + bcrypt hash —
// never plaintext passwords. Single-node; swap for a real DB to scale.
// The data directory is gitignored so credentials never enter version control.
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from 'node:fs';
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
  // Atomic write (temp + rename) so a crash mid-write can't truncate the user
  // store and wipe every account on the next load.
  const tmp = `${FILE}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(users, null, 2), { mode: 0o600 });
  renameSync(tmp, FILE);
}

const norm = (email) => String(email || '').trim().toLowerCase();

export function getUser(email) { return load()[norm(email)] || null; }
export function hasUser(email) { return !!load()[norm(email)]; }
export function userCount() { return Object.keys(load()).length; }

export function putUser(email, passwordHash, extra = {}) {
  const users = load();
  const key = norm(email);
  users[key] = {
    email: key,
    passwordHash,
    plan: 'free',
    emailVerified: false,
    provider: 'password',
    createdAt: new Date().toISOString(),
    ...extra
  };
  save(users);
  return users[key];
}

// Merge `patch` into an existing user. Keys set to null are removed (used to
// clear single-use token nonces). Returns the updated record, or null if absent.
export function updateUser(email, patch) {
  const users = load();
  const key = norm(email);
  if (!users[key]) return null;
  Object.assign(users[key], patch);
  for (const k of Object.keys(patch)) if (patch[k] === null) delete users[key][k];
  save(users);
  return users[key];
}

// Look up a user by their Stripe customer id (used by the billing webhook when an
// event carries the customer but not the email, e.g. subscription cancellation).
export function findByCustomerId(customerId) {
  if (!customerId) return null;
  const users = load();
  return Object.values(users).find((u) => u.stripeCustomerId === customerId) || null;
}

// Update a user's plan (called only from a verified payment signature/webhook).
// `expiresAt` (ISO) stamps when a paid plan lapses back to free; pass null to
// clear it (e.g. when dropping to free).
export function setUserPlan(email, plan, expiresAt) {
  const users = load();
  const key = norm(email);
  if (!users[key]) return null;
  users[key].plan = plan;
  users[key].planUpdatedAt = new Date().toISOString();
  if (expiresAt === undefined) { /* leave existing expiry untouched */ }
  else if (expiresAt === null) delete users[key].planExpiresAt;
  else users[key].planExpiresAt = expiresAt;
  save(users);
  return users[key];
}
