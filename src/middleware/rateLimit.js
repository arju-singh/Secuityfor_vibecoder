// In-memory sliding-window rate limiter (OWASP API4:2023 — Unrestricted Resource
// Consumption). Keyed by client IP plus, when an Authorization header is present,
// a hash of that credential — so distinct callers get separate budgets (the
// "user-based" dimension). SentryScan has no built-in user accounts, so in
// practice this is IP-based with a per-credential split when callers authenticate.
//
// NOTE: in-memory state is per-process — fine for a single node. Behind a load
// balancer, front this with a shared store (e.g. Redis) and set TRUST_PROXY so
// req.ip is the real client address.
import crypto from 'node:crypto';

// Derive the bucket key. Uses req.ip (which honours Express "trust proxy"); if
// trust proxy is off, all proxied clients share the proxy's IP — a safe,
// stricter default that cannot be spoofed via X-Forwarded-For.
export function clientKey(req) {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const auth = req.headers['authorization'];
  const user = auth ? crypto.createHash('sha256').update(auth).digest('hex').slice(0, 12) : 'anon';
  return `${ip}|${user}`;
}

export function rateLimit({ windowMs, max, name }) {
  const hits = new Map(); // key -> sorted array of request timestamps (ms)

  // Periodically drop expired buckets so memory can't grow unbounded.
  const sweep = setInterval(() => {
    const cutoff = Date.now() - windowMs;
    for (const [k, arr] of hits) {
      const keep = arr.filter((t) => t > cutoff);
      if (keep.length) hits.set(k, keep); else hits.delete(k);
    }
  }, windowMs);
  if (typeof sweep.unref === 'function') sweep.unref(); // don't keep the process alive

  return function rateLimiter(req, res, next) {
    const now = Date.now();
    const key = clientKey(req);
    const recent = (hits.get(key) || []).filter((t) => now - t < windowMs);

    res.set('RateLimit-Limit', String(max));
    if (recent.length >= max) {
      const retryAfter = Math.max(1, Math.ceil((recent[0] + windowMs - now) / 1000));
      res.set('Retry-After', String(retryAfter));
      res.set('RateLimit-Remaining', '0');
      return res.status(429).json({
        ok: false,
        error: `Too many requests${name ? ` to ${name}` : ''}. Please retry in ${retryAfter}s.`
      });
    }
    recent.push(now);
    hits.set(key, recent);
    res.set('RateLimit-Remaining', String(max - recent.length));
    next();
  };
}
