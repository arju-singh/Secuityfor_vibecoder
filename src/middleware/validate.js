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

export const websiteSchema = {
  url: { type: 'string', required: true, maxLength: URL_MAX },
  render: { type: 'boolean', default: true },
  audits: { type: 'boolean', default: true },
  headers: { type: 'headers' }
};

export const apiSchema = {
  url: { type: 'string', required: true, maxLength: URL_MAX },
  headers: { type: 'headers' },
  fuzz: { type: 'boolean', default: false },
  access: { type: 'boolean', default: true },
  enumerate: { type: 'boolean', default: false },
  rateLimit: { type: 'boolean', default: false },
  allowWrite: { type: 'boolean', default: false },
  method: { type: 'string', maxLength: 10, uppercase: true, enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'] },
  body: { type: 'string', maxLength: 100000, trim: false },
  contentType: { type: 'string', maxLength: 200 },
  customPayloads: { type: 'string[]', maxItems: 50, maxItemLength: 2000 }
};
