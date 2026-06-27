// Brute-force / credential-stuffing prevention for login (OWASP A07).
// Tracks failed attempts per key (email and IP are both checked) within a
// rolling window; after MAX failures the key is locked for LOCK_MS. Successful
// login clears the counter. In-memory (single node) — back with a shared store
// when running multiple instances.
const MAX_FAILS = Number(process.env.LOGIN_MAX_FAILS) || 5;
const WINDOW_MS = Number(process.env.LOGIN_WINDOW_MS) || 15 * 60 * 1000;
const LOCK_MS = Number(process.env.LOGIN_LOCK_MS) || 15 * 60 * 1000;

const attempts = new Map(); // key -> { count, first, lockUntil }

const sweep = setInterval(() => {
  const now = Date.now();
  for (const [k, a] of attempts) {
    if ((a.lockUntil || 0) < now && now - a.first > WINDOW_MS) attempts.delete(k);
  }
}, WINDOW_MS);
if (typeof sweep.unref === 'function') sweep.unref();

// Returns seconds remaining if locked, else 0.
export function lockedFor(key) {
  const a = attempts.get(key);
  if (a && a.lockUntil && Date.now() < a.lockUntil) return Math.ceil((a.lockUntil - Date.now()) / 1000);
  return 0;
}

// Check every key (e.g. email + IP); returns the longest active lock in seconds.
export function checkLock(keys) {
  return keys.reduce((max, k) => Math.max(max, lockedFor(k)), 0);
}

export function recordFailure(keys) {
  const now = Date.now();
  for (const key of keys) {
    let a = attempts.get(key);
    if (!a || now - a.first > WINDOW_MS) a = { count: 0, first: now, lockUntil: 0 };
    a.count += 1;
    if (a.count >= MAX_FAILS) a.lockUntil = now + LOCK_MS;
    attempts.set(key, a);
  }
}

export function recordSuccess(keys) {
  for (const key of keys) attempts.delete(key);
}
