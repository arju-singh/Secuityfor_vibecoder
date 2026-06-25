// Security response headers via Helmet (the vetted, OWASP-recommended library —
// safer than hand-rolling). CSP is pinned to the exact policy the UI is verified
// against: strict script-src 'self' (the one bootstrap script lives in
// public/head-init.js); style-src keeps 'unsafe-inline' only for the UI's inline
// style attributes, which are far lower risk than inline scripts.
import helmet from 'helmet';

const base = helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      'default-src': ["'self'"],
      'script-src': ["'self'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:'],
      'font-src': ["'self'"],
      'connect-src': ["'self'"],
      'object-src': ["'none'"],
      'base-uri': ["'self'"],
      'form-action': ["'self'"],
      'frame-ancestors': ["'none'"]
    }
  },
  frameguard: { action: 'deny' },              // X-Frame-Options: DENY
  referrerPolicy: { policy: 'no-referrer' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  hsts: { maxAge: 15552000, includeSubDomains: true }
  // Helmet also sets X-Content-Type-Options: nosniff, X-DNS-Prefetch-Control,
  // X-Permitted-Cross-Domain-Policies, Origin-Agent-Cluster, etc. by default.
});

// Helmet does not emit Permissions-Policy; add it alongside Helmet's headers.
export function securityHeaders(req, res, next) {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  base(req, res, next);
}
