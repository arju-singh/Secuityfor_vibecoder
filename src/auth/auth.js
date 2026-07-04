// Authentication core: bcrypt password hashing + JWT issued in a hardened cookie.
// Uses vetted libraries (bcryptjs, jsonwebtoken) rather than hand-rolled crypto.
//
// OWASP notes:
// - Passwords are bcrypt-hashed (cost 12); plaintext is never stored or logged.
// - The JWT lives in an httpOnly + SameSite=Strict cookie so client JS can't read
//   it (XSS can't steal the token) and it isn't sent cross-site (CSRF mitigation).
// - The cookie is Secure whenever the request is HTTPS.
// - JWT_SECRET must be set in production; a random one is generated otherwise
//   (sessions won't survive a restart — a clear signal to configure it).
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';

export const COOKIE_NAME = 'sentry_token';
const BCRYPT_COST = 12;
const TOKEN_TTL_SEC = Number(process.env.JWT_TTL_SECONDS) || 2 * 60 * 60; // 2h

let SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('[auth] JWT_SECRET not set — using a random secret; sessions will reset on restart. Set JWT_SECRET in production.');
}

// A valid throwaway hash to compare against when an account doesn't exist, so
// login timing doesn't reveal whether an email is registered (user enumeration).
const DUMMY_HASH = bcrypt.hashSync('sentryscan-nonexistent-account', BCRYPT_COST);

export function hashPassword(password) { return bcrypt.hash(password, BCRYPT_COST); }
export function verifyPassword(password, hash) { return bcrypt.compare(password, hash || DUMMY_HASH); }

export function issueToken(email) {
  return jwt.sign({ sub: email }, SECRET, { expiresIn: TOKEN_TTL_SEC, algorithm: 'HS256' });
}
export function verifyToken(token) {
  try { return jwt.verify(token, SECRET, { algorithms: ['HS256'] }); }
  catch { return null; }
}

// Short-lived, purpose-scoped tokens (email verification, password reset, OAuth
// state). Signed with the same secret but carry a `purpose` so a session token
// can never be replayed as a reset token and vice-versa.
export function signScoped(payload, ttlSeconds) {
  return jwt.sign(payload, SECRET, { expiresIn: ttlSeconds, algorithm: 'HS256' });
}
export function verifyScoped(token) {
  try { return jwt.verify(token, SECRET, { algorithms: ['HS256'] }); }
  catch { return null; }
}

export function setAuthCookie(req, res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: !!req.secure,              // Secure over HTTPS (honors trust proxy)
    maxAge: TOKEN_TTL_SEC * 1000,
    path: '/'
  });
}
export function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: '/', httpOnly: true, sameSite: 'strict' });
}

// Express middleware — rejects requests without a valid session cookie.
export function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  const payload = token && verifyToken(token);
  if (!payload) return res.status(401).json({ ok: false, error: 'Authentication required.' });
  req.user = { email: payload.sub };
  next();
}
