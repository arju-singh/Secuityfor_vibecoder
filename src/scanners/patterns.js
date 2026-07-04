// Detection rule sets for the code scanner.
// Each secret rule has a verifier to suppress low-entropy false positives where useful.

export const SECRET_RULES = [
  {
    id: 'aws-access-key-id',
    title: 'AWS Access Key ID',
    severity: 'critical',
    regex: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA)[A-Z0-9]{16})\b/g,
    remediation: 'Revoke the key in the AWS IAM console immediately and rotate. Never commit AWS keys; use IAM roles or a secrets manager.'
  },
  {
    id: 'aws-secret-access-key',
    title: 'AWS Secret Access Key',
    severity: 'critical',
    // Only flag when contextually labelled to avoid matching arbitrary base64.
    regex: /(?:aws.{0,20})?(?:secret|access)[\w.\- ]{0,20}['"=:\s]+([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/gi,
    group: 1,
    remediation: 'Rotate the AWS secret access key immediately and remove it from source. Use environment variables or AWS Secrets Manager.'
  },
  {
    id: 'gcp-api-key',
    title: 'Google API Key',
    severity: 'high',
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    remediation: 'Restrict or regenerate the key in the Google Cloud Console. Apply application and API restrictions.'
  },
  {
    id: 'google-oauth-token',
    title: 'Google OAuth Access Token',
    severity: 'high',
    regex: /\b(ya29\.[0-9A-Za-z\-_]+)\b/g,
    remediation: 'Revoke the OAuth token and rotate the associated client secret.'
  },
  {
    id: 'stripe-secret-key',
    title: 'Stripe Secret Key',
    severity: 'critical',
    regex: /\b(sk_live_[0-9a-zA-Z]{24,})\b/g,
    remediation: 'Roll the key in the Stripe Dashboard immediately. Live secret keys grant full account access.'
  },
  {
    id: 'stripe-restricted-key',
    title: 'Stripe Restricted Key',
    severity: 'high',
    regex: /\b(rk_live_[0-9a-zA-Z]{24,})\b/g,
    remediation: 'Roll the restricted key in the Stripe Dashboard and review its granted scopes.'
  },
  {
    id: 'github-token',
    title: 'GitHub Personal Access / App Token',
    severity: 'critical',
    regex: /\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,255})\b/g,
    remediation: 'Revoke the token under GitHub Settings → Developer settings → Tokens, and regenerate with least privilege.'
  },
  {
    id: 'gitlab-token',
    title: 'GitLab Personal Access Token',
    severity: 'critical',
    regex: /\b(glpat-[0-9A-Za-z\-_]{20})\b/g,
    remediation: 'Revoke the token in GitLab → Access Tokens and rotate.'
  },
  {
    id: 'slack-token',
    title: 'Slack Token',
    severity: 'high',
    regex: /\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b/g,
    remediation: 'Revoke the token in the Slack app settings and rotate the signing secret.'
  },
  {
    id: 'slack-webhook',
    title: 'Slack Incoming Webhook URL',
    severity: 'medium',
    regex: /(https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z_]+\/B[0-9A-Za-z_]+\/[0-9A-Za-z_]+)/g,
    remediation: 'Regenerate the webhook; anyone with the URL can post to your channel.'
  },
  {
    id: 'private-key',
    title: 'Cryptographic Private Key',
    severity: 'critical',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    remediation: 'Treat the key as compromised: rotate the key pair and re-issue any certificates signed with it.'
  },
  {
    id: 'jwt',
    title: 'JSON Web Token (JWT)',
    severity: 'medium',
    regex: /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g,
    remediation: 'If this is a live token, invalidate the session/secret. Do not embed bearer tokens in shipped code.'
  },
  {
    id: 'google-service-account',
    title: 'Google Service Account Private Key Block',
    severity: 'critical',
    regex: /"type"\s*:\s*"service_account"/g,
    remediation: 'Delete and regenerate the service-account key in Google Cloud IAM. Never ship service-account JSON to clients.'
  },
  {
    id: 'firebase-cloud-messaging',
    title: 'Firebase Cloud Messaging Server Key',
    severity: 'high',
    regex: /\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,})\b/g,
    remediation: 'Rotate the FCM server key in the Firebase console; it allows sending push notifications to all users.'
  },
  {
    id: 'sendgrid-key',
    title: 'SendGrid API Key',
    severity: 'high',
    regex: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
    remediation: 'Delete the key in SendGrid → API Keys and create a new scoped key.'
  },
  {
    id: 'twilio-key',
    title: 'Twilio Account SID / API Key',
    severity: 'high',
    regex: /\b((?:AC|SK)[0-9a-fA-F]{32})\b/g,
    remediation: 'Rotate Twilio credentials in the console; exposed SIDs paired with tokens allow billing abuse.'
  },
  {
    id: 'npm-token',
    title: 'npm Access Token',
    severity: 'high',
    regex: /\b(npm_[A-Za-z0-9]{36})\b/g,
    remediation: 'Revoke the token with `npm token revoke` and remove it from .npmrc in source control.'
  },
  {
    id: 'openai-key',
    title: 'OpenAI API Key',
    severity: 'high',
    regex: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b/g,
    remediation: 'Revoke the key in the OpenAI dashboard. Proxy API calls through a backend so keys never reach the client.'
  },
  {
    id: 'anthropic-key',
    title: 'Anthropic API Key',
    severity: 'high',
    regex: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g,
    remediation: 'Revoke the key in the Anthropic console and route requests through a server-side proxy.'
  },
  {
    id: 'mailgun-key',
    title: 'Mailgun API Key',
    severity: 'high',
    regex: /\b(key-[0-9a-zA-Z]{32})\b/g,
    remediation: 'Rotate the Mailgun key in your account settings.'
  },
  {
    id: 'generic-secret-assignment',
    title: 'Hardcoded Secret / Password Assignment',
    severity: 'medium',
    regex: /\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*['"]([^'"\s]{6,})['"]/gi,
    group: 1,
    // Suppress obvious placeholders.
    ignoreValues: /^(?:your[_-]?|xxx|placeholder|changeme|example|test|dummy|none|null|undefined|process\.env|import\.meta|\$\{|<|\{\{)/i,
    remediation: 'Move the secret to an environment variable or secrets manager. Do not hardcode credentials in source.'
  },
  {
    id: 'db-connection-string',
    title: 'Database Connection String with Credentials',
    severity: 'high',
    regex: /\b((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s:@/'"]+:[^\s:@/'"]+@[^\s'"]+)/gi,
    remediation: 'Remove inline credentials from the connection string; load them from environment variables.'
  },
  {
    id: 'basic-auth-url',
    title: 'Credentials Embedded in URL',
    severity: 'medium',
    regex: /\bhttps?:\/\/[^\s:@/'"]+:[^\s:@/'"]+@[^\s'"]+/gi,
    remediation: 'Do not embed user:password in URLs; they leak via logs, history, and referrer headers.'
  }
];

// Insecure / dangerous code patterns (not secrets — risky constructs).
export const CODE_RULES = [
  {
    id: 'js-eval',
    title: 'Use of eval()',
    severity: 'high',
    extensions: ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'html'],
    regex: /(?<![.\w])eval\s*\(/g,
    remediation: 'Avoid eval(); it enables code injection. Use JSON.parse or explicit logic instead.'
  },
  {
    id: 'js-function-constructor',
    title: 'Dynamic Function() constructor',
    severity: 'medium',
    extensions: ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs'],
    regex: /\bnew\s+Function\s*\(/g,
    remediation: 'The Function constructor evaluates strings as code, enabling injection. Refactor to avoid it.'
  },
  {
    id: 'js-inner-html',
    title: 'Assignment to innerHTML / outerHTML',
    severity: 'medium',
    extensions: ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'html'],
    regex: /\.(inner|outer)HTML\s*=/g,
    remediation: 'Setting innerHTML with untrusted data causes XSS. Use textContent or sanitize with a trusted library (DOMPurify).'
  },
  {
    id: 'react-dangerous-html',
    title: 'React dangerouslySetInnerHTML',
    severity: 'medium',
    extensions: ['js', 'jsx', 'ts', 'tsx'],
    regex: /dangerouslySetInnerHTML/g,
    remediation: 'Sanitize HTML before injecting it; unsanitized content leads to XSS.'
  },
  {
    id: 'js-document-write',
    title: 'document.write()',
    severity: 'low',
    extensions: ['js', 'jsx', 'ts', 'tsx', 'html'],
    regex: /document\.write(?:ln)?\s*\(/g,
    remediation: 'document.write can introduce XSS and blocks rendering. Use DOM APIs instead.'
  },
  {
    id: 'node-child-process',
    title: 'Shell command execution (exec)',
    severity: 'high',
    extensions: ['js', 'ts', 'mjs', 'cjs'],
    regex: /\b(?:child_process|require\(['"]child_process['"]\))[\s\S]{0,40}\bexec\s*\(/g,
    remediation: 'Avoid passing concatenated input to exec(); use execFile/spawn with an argument array to prevent command injection.'
  },
  {
    id: 'sql-string-concat',
    title: 'Possible SQL string concatenation',
    severity: 'high',
    extensions: ['js', 'ts', 'php', 'py', 'java', 'rb', 'mjs', 'cjs'],
    regex: /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;'"\n]*['"]\s*\+\s*\w+/gi,
    remediation: 'Use parameterized queries / prepared statements instead of string concatenation to prevent SQL injection.'
  },
  {
    id: 'insecure-http',
    title: 'Insecure http:// resource',
    severity: 'low',
    extensions: ['html', 'js', 'jsx', 'ts', 'tsx', 'css'],
    regex: /["'(]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|schemas?\.|www\.w3\.org|xmlns)[^"')\s]+/g,
    remediation: 'Load all resources over HTTPS. Mixed content is blocked by browsers and exposes data in transit.'
  },
  {
    id: 'target-blank-noopener',
    title: 'target="_blank" without rel="noopener"',
    severity: 'low',
    extensions: ['html', 'jsx', 'tsx'],
    regex: /<a\b(?=[^>]*target\s*=\s*["']_blank["'])(?![^>]*rel\s*=\s*["'][^"']*noopener)[^>]*>/gi,
    remediation: 'Add rel="noopener noreferrer" to external _blank links to prevent reverse tabnabbing.'
  },
  {
    id: 'debug-flag',
    title: 'Debug mode enabled',
    severity: 'low',
    extensions: ['js', 'ts', 'py', 'php', 'env', 'rb', 'mjs', 'cjs'],
    regex: /\b(?:DEBUG|debug)\s*[:=]\s*(?:true|True|1|on)\b/g,
    remediation: 'Disable debug mode in production; it can leak stack traces and internal details.'
  }
];

// Files whose mere presence in a deployable bundle is a finding.
export const SENSITIVE_FILES = [
  { match: /(^|\/)\.env(\..+)?$/i, title: 'Environment file (.env) included', severity: 'high', remediation: 'Never deploy .env files. Add them to .gitignore and load secrets from the host environment.' },
  { match: /(^|\/)\.git(\/|$)/i, title: 'Git metadata (.git) included', severity: 'high', remediation: 'Remove the .git directory from your web root; it can expose full source history.' },
  { match: /(^|\/)id_rsa$/i, title: 'SSH private key (id_rsa) included', severity: 'critical', remediation: 'Remove and rotate the SSH key pair immediately.' },
  { match: /(^|\/)wp-config\.php$/i, title: 'WordPress config (wp-config.php) present', severity: 'medium', remediation: 'Ensure database credentials in wp-config.php are protected and not web-readable.' },
  { match: /(^|\/)\.htpasswd$/i, title: '.htpasswd file included', severity: 'high', remediation: 'Move credential files outside the web root.' },
  { match: /(^|\/)\.npmrc$/i, title: '.npmrc included (may contain tokens)', severity: 'medium', remediation: 'Check .npmrc for auth tokens and exclude it from deployment.' },
  { match: /(^|\/)docker-compose\.ya?ml$/i, title: 'docker-compose file present', severity: 'low', remediation: 'Ensure compose files with secrets are not served publicly.' },
  { match: /\.(bak|old|orig|swp|save)$/i, title: 'Backup/temporary source file', severity: 'medium', remediation: 'Backup files often contain readable source and secrets; remove them from the web root.' },
  { match: /(^|\/)\.DS_Store$/i, title: '.DS_Store included', severity: 'info', remediation: 'Remove macOS .DS_Store files; they leak directory listings.' }
];

// Text file extensions worth scanning for secrets/patterns.
export const SCANNABLE_EXT = new Set([
  'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'json', 'html', 'htm', 'css', 'scss',
  'env', 'yml', 'yaml', 'xml', 'php', 'py', 'rb', 'java', 'go', 'sh', 'bash',
  'txt', 'md', 'ini', 'conf', 'config', 'properties', 'pem', 'key', 'sql', 'vue', 'svelte',
  'cs', 'c', 'cpp', 'cc', 'h', 'hpp'
]);

export function extOf(path) {
  const base = path.split('/').pop() || '';
  const dot = base.lastIndexOf('.');
  // Dotfile (leading dot, no other): treat the name after the dot as the ext, so
  // ".env" -> "env" (matches SCANNABLE_EXT, which stores extensions without a dot).
  if (dot === 0) return base.slice(1).toLowerCase();
  if (dot < 0) return base.toLowerCase(); // no extension at all
  return base.slice(dot + 1).toLowerCase();
}
