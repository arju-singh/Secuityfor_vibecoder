// Schema-based request validation (OWASP: positive/allowlist input validation).
// Dependency-free. Enforces types, length/enum/array limits, applies defaults,
// and REJECTS any field not declared in the schema (no mass-assignment surface).
// On success, req.body is replaced with the normalized, trimmed value.

function err(field, msg) { return { ok: false, error: `Field "${field}" ${msg}.` }; }
function ok(value) { return { ok: true, value }; }

function checkField(key, v, rule) {
  switch (rule.type) {
    case 'string': {
      if (typeof v !== 'string') return err(key, 'must be a string');
      const s = rule.trim === false ? v : v.trim();
      if (rule.maxLength && s.length > rule.maxLength) return err(key, `must be ≤ ${rule.maxLength} characters`);
      if (rule.minLength && s.length < rule.minLength) return err(key, `must be ≥ ${rule.minLength} characters`);
      if (rule.enum && !rule.enum.includes(rule.uppercase ? s.toUpperCase() : s)) return err(key, `must be one of: ${rule.enum.join(', ')}`);
      return ok(rule.uppercase ? s.toUpperCase() : s);
    }
    case 'boolean':
      if (typeof v !== 'boolean') return err(key, 'must be a boolean');
      return ok(v);
    case 'string[]': {
      if (!Array.isArray(v)) return err(key, 'must be an array');
      if (rule.maxItems && v.length > rule.maxItems) return err(key, `must have ≤ ${rule.maxItems} items`);
      for (const it of v) {
        if (typeof it !== 'string') return err(key, 'items must be strings');
        if (rule.maxItemLength && it.length > rule.maxItemLength) return err(key, `items must be ≤ ${rule.maxItemLength} characters`);
      }
      return ok(v);
    }
    case 'headers': // object {Name: value} or "Name: value" lines; sanitized downstream
      if (typeof v === 'string') { if (v.length > 8192) return err(key, 'is too large'); return ok(v); }
      if (v && typeof v === 'object' && !Array.isArray(v)) return ok(v);
      return err(key, 'must be an object or a string');
    default:
      return ok(v);
  }
}

export function validateBody(schema, body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, error: 'Request body must be a JSON object.' };
  }
  // Reject unexpected fields (allowlist — prevents mass assignment / typos).
  for (const key of Object.keys(body)) {
    if (!Object.prototype.hasOwnProperty.call(schema, key)) return { ok: false, error: `Unexpected field: "${key}".` };
  }
  const out = {};
  for (const [key, rule] of Object.entries(schema)) {
    const v = body[key];
    if (v === undefined || v === null) {
      if (rule.required) return { ok: false, error: `Missing required field: "${key}".` };
      if ('default' in rule) out[key] = rule.default;
      continue;
    }
    const r = checkField(key, v, rule);
    if (!r.ok) return r;
    out[key] = r.value;
  }
  return { ok: true, value: out };
}

// Express middleware factory: validates req.body against `schema`.
export function validate(schema) {
  return function validator(req, res, next) {
    const result = validateBody(schema, req.body || {});
    if (!result.ok) return res.status(400).json({ ok: false, error: result.error });
    req.body = result.value; // normalized + trimmed
    next();
  };
}

// ---- Endpoint schemas ------------------------------------------------------
const URL_MAX = 2048;

// Scan effort: 'extended' is the full deep-dive (current behaviour, kept as the
// default so coverage never silently drops); 'regular' skips the slower
// extra-request probes and heavier audits for fast incremental re-scans.
const EFFORT = { type: 'string', default: 'extended', maxLength: 10, enum: ['regular', 'extended'] };
// Directory scoping: path prefixes to restrict a code scan to (large-monorepo
// friendly). Empty/omitted = whole tree.
const PATHS = { type: 'string[]', maxItems: 50, maxItemLength: 400 };
// Project a scan is filed under on the user's dashboard.
const PROJECT = { type: 'string', maxLength: 60 };

export const websiteSchema = {
  url: { type: 'string', required: true, maxLength: URL_MAX },
  render: { type: 'boolean', default: true },
  audits: { type: 'boolean', default: true },
  vapt: { type: 'boolean', default: false },
  effort: EFFORT,
  project: PROJECT,
  headers: { type: 'headers' }
};

export const githubSchema = {
  url: { type: 'string', required: true, maxLength: 300 },
  effort: EFFORT,
  paths: PATHS,
  project: PROJECT
};

// Full VAPT assessment: runs the whole scanner battery against one target.
export const vaptSchema = {
  url: { type: 'string', required: true, maxLength: URL_MAX },
  effort: EFFORT,
  allowWrite: { type: 'boolean', default: false },
  project: PROJECT,
  headers: { type: 'headers' }
};

export const billingSchema = {
  plan: { type: 'string', required: true, maxLength: 10, enum: ['pro', 'team'] }
};

export const credentialsSchema = {
  email: { type: 'string', required: true, maxLength: 254, minLength: 3 },
  password: { type: 'string', required: true, maxLength: 200, minLength: 8, trim: false }
};

export const forgotSchema = {
  email: { type: 'string', required: true, maxLength: 254, minLength: 3 }
};

export const resetSchema = {
  token: { type: 'string', required: true, maxLength: 1000, trim: false },
  password: { type: 'string', required: true, maxLength: 200, minLength: 8, trim: false }
};

export const apiSchema = {
  url: { type: 'string', required: true, maxLength: URL_MAX },
  headers: { type: 'headers' },
  project: PROJECT,
  fuzz: { type: 'boolean', default: false },
  access: { type: 'boolean', default: true },
  enumerate: { type: 'boolean', default: false },
  vapt: { type: 'boolean', default: false },
  rateLimit: { type: 'boolean', default: false },
  allowWrite: { type: 'boolean', default: false },
  method: { type: 'string', maxLength: 10, uppercase: true, enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'] },
  body: { type: 'string', maxLength: 100000, trim: false },
  contentType: { type: 'string', maxLength: 200 },
  customPayloads: { type: 'string[]', maxItems: 50, maxItemLength: 2000 }
};
