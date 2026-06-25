// Security response headers (OWASP Secure Headers Project) applied to every
// response, including the static UI. script-src is strict 'self' (no inline
// scripts — the one bootstrap script lives in public/head-init.js). style-src
// keeps 'unsafe-inline' only because the UI uses inline style attributes;
// inline styles are a far lower risk than inline scripts.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'"
].join('; ');

export function securityHeaders(req, res, next) {
  res.set('Content-Security-Policy', CSP);
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  res.set('Cross-Origin-Opener-Policy', 'same-origin');
  res.set('Cross-Origin-Resource-Policy', 'same-origin');
  // HSTS only matters over HTTPS; harmless to send and correct behind TLS.
  res.set('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  next();
}
