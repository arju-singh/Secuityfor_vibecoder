// Secret masking for the Analytics view/export. A finding's evidence can quote a
// live token (a JWT it echoed back, an AWS key found in source, a password in a
// connection string). The Analytics page and its export must never surface those
// raw — so every string that leaves buildAnalytics() is run through maskSecrets()
// first. This is deliberately conservative: it only redacts things that clearly
// look like credentials, leaving ordinary prose intact.

// Ordered high→low specificity. Each entry replaces the sensitive run with a
// short, labelled placeholder so the reader still knows WHAT was redacted.
const RULES = [
  [/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, '[REDACTED private key]'],
  [/eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+/g, '[REDACTED JWT]'],
  [/AKIA[0-9A-Z]{16}/g, '[REDACTED AWS key id]'],
  [/AIza[0-9A-Za-z_-]{35}/g, '[REDACTED Google API key]'],
  [/\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}/g, '[REDACTED Stripe key]'],
  [/xox[baprs]-[0-9A-Za-z-]{10,}/g, '[REDACTED Slack token]'],
  [/gh[pousr]_[0-9A-Za-z]{20,}/g, '[REDACTED GitHub token]'],
  [/\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/gi, 'Bearer [REDACTED]'],
  // Passwords embedded in URLs / connection strings: scheme://user:pass@host
  [/(\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)[^\s@/]+(@)/gi, '$1[REDACTED]$2'],
  // key=value / key: value where the key names a secret.
  [/((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\s*[=:]\s*)(["']?)[^\s"'&,;]{4,}\2/gi, '$1[REDACTED]'],
  // Generic long high-entropy blobs (32+ base64/hex chars) that survived above.
  [/\b[A-Za-z0-9+/_-]{40,}={0,2}\b/g, '[REDACTED token]'],
  [/\b[0-9a-fA-F]{32,}\b/g, '[REDACTED hex secret]']
];

export function maskSecrets(input) {
  if (input == null) return input;
  let s = String(input);
  for (const [re, repl] of RULES) s = s.replace(re, repl);
  return s;
}

// Return a shallow copy of a finding with its free-text fields masked. Structural
// fields (severity, category, confidence, owasp, fingerprint) are left intact.
export function maskFinding(f) {
  if (!f || typeof f !== 'object') return f;
  return {
    ...f,
    title: maskSecrets(f.title),
    description: maskSecrets(f.description),
    remediation: maskSecrets(f.remediation),
    evidence: maskSecrets(f.evidence),
    location: maskSecrets(f.location),
    impact: maskSecrets(f.impact),
    reproduction: maskSecrets(f.reproduction),
    handoff: maskSecrets(f.handoff)
  };
}
