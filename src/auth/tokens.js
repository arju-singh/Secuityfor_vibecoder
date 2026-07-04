// Single-use, purpose-scoped tokens for email verification and password reset.
// The token itself is a short-lived signed JWT carrying { sub: email, purpose,
// nonce }. The nonce is also stored on the user record; consuming the token
// requires the nonce to match and then clears it — so a link works exactly once
// and a leaked-then-used link cannot be replayed. Email lives inside the signed
// token, so reset/verify links never put the address in the URL.
import crypto from 'node:crypto';
import { signScoped, verifyScoped } from './auth.js';
import { getUser, updateUser } from './store.js';

const TTL_SECONDS = { reset: 60 * 60, verify: 24 * 60 * 60 }; // 1h / 24h
const nonceField = (purpose) => `${purpose}Nonce`;

// Create a token for an existing user. Returns the signed token string.
export function createToken(email, purpose) {
  if (!(purpose in TTL_SECONDS)) throw new Error(`Unknown token purpose: ${purpose}`);
  const nonce = crypto.randomBytes(12).toString('base64url');
  updateUser(email, { [nonceField(purpose)]: nonce });
  return signScoped({ sub: String(email).toLowerCase(), purpose, nonce }, TTL_SECONDS[purpose]);
}

// Validate + single-use-consume a token. Returns the email on success, else null.
export function consumeToken(purpose, token) {
  const payload = verifyScoped(token);
  if (!payload || payload.purpose !== purpose || !payload.sub || !payload.nonce) return null;
  const user = getUser(payload.sub);
  const field = nonceField(purpose);
  if (!user || !user[field]) return null; // already used or never issued
  const a = Buffer.from(String(user[field]));
  const b = Buffer.from(String(payload.nonce));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  updateUser(payload.sub, { [field]: null }); // burn it — single use
  return payload.sub;
}
