// Security response headers via Helmet (the vetted, OWASP-recommended library —
// safer than hand-rolling). CSP is pinned to the exact policy the UI is verified
// against: strict script-src 'self' (the one bootstrap script lives in
// public/head-init.js); style-src keeps 'unsafe-inline' only for the UI's inline
// style attributes, which are far lower risk than inline scripts.
import helmet from 'helmet';

// Razorpay Checkout runs from these hosts; they must be whitelisted or the
// payment modal is blocked by CSP. Scoped to Razorpay only — everything else
// stays locked to 'self'.
const RZP_SCRIPT = ['https://checkout.razorpay.com'];
const RZP_FRAME = ['https://api.razorpay.com', 'https://checkout.razorpay.com'];
const RZP_CONNECT = ['https://api.razorpay.com', 'https://lumberjack.razorpay.com', 'https://lumberjack-metrics.razorpay.com'];
const RZP_IMG = ['https://cdn.razorpay.com', 'https://checkout.razorpay.com'];

const base = helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      'default-src': ["'self'"],
      'script-src': ["'self'", ...RZP_SCRIPT],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:', ...RZP_IMG],
      'font-src': ["'self'"],
      'connect-src': ["'self'", ...RZP_CONNECT],
      'frame-src': ["'self'", ...RZP_FRAME],
      'child-src': ["'self'", ...RZP_FRAME],
      'object-src': ["'none'"],
      'base-uri': ["'self'"],
      'form-action': ["'self'", 'https://api.razorpay.com'],
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
