# SentryScan — Testing Tools Inventory

A reference of everything SentryScan can test. **3 input modes → 17 test suites → 11 scanner engines → 130+ individual checks**, verified by a 39-assertion integration test (`npm test`).

---

## 3 input modes
1. **Website URL** — full site test
2. **API URL** — endpoint + API-security test
3. **Source-code upload** — static analysis of a `.zip` or loose files

---

## 12 test suites

### Website (7 suites)

| # | Suite | Engine |
|---|-------|--------|
| 1 | 🧩 UI / health | `uiScanner.js` |
| 2 | 🛡️ Security | `urlScanner.js` |
| 3 | 🎯 Vulnerabilities & OWASP | `vulnScanner.js` |
| 4 | 🖥️ JavaScript / render | `renderScanner.js` |
| 5 | ⚡ Performance | `auditScanner.js` |
| 6 | ♿ Accessibility (WCAG) | `auditScanner.js` |
| 7 | 🔎 SEO | `auditScanner.js` |

### API (4 suites)

| # | Suite | Engine |
|---|-------|--------|
| 8 | 🔌 API checks | `apiScanner.js` |
| 9 | 🔓 Access control | `accessScanner.js` |
| 10 | 📜 API surface (OpenAPI enumeration) | `apiSpecScanner.js` |
| 11 | 🧬 Parameter fuzzing | `apiFuzzScanner.js` |

### Code upload (6 suites)

| # | Suite | Engine |
|---|-------|--------|
| 12 | 📦 Source code (secrets, dangerous patterns, sensitive files, dep CVEs) | `codeScanner.js` |
| 13 | 🧹 Code quality (+ perf anti-patterns + AI-hallucinated imports) | `codeAuditScanner.js` |
| 14 | 🎨 Frontend quality | `codeAuditScanner.js` |
| 15 | ⚙️ Config & DevOps | `codeAuditScanner.js` |
| 16 | 🧪 Testing quality | `codeAuditScanner.js` |
| 17 | 📋 Project hygiene | `codeAuditScanner.js` |

---

## 11 scanner engines & their checks

### 1. `uiScanner.js` — UI / health
Load time & size · broken links/resources (real HEAD/GET, browser-like UA; 401/403 noted as auth-required, not broken) · missing `<title>` / viewport / charset / `lang` / `<h1>` · multiple `<h1>` · images missing `alt` · insecure form submission · blank/broken-page detection.

### 2. `urlScanner.js` — Security
HTTP→HTTPS redirect · HSTS · CSP · X-Content-Type-Options · X-Frame-Options / clickjacking · Referrer-Policy · Permissions-Policy · TLS cert (expired / expiring / untrusted / weak version / handshake) · cookie flags (Secure/HttpOnly/SameSite) · CORS (wildcard/insecure) · Server & X-Powered-By disclosure · mixed content · API key in page source · 11 exposed paths (`.env`, `.git/config`, `.git/HEAD`, `config.php`, `wp-config.php.bak`, `.htaccess`, `phpinfo.php`, `.DS_Store`, `backup.zip`, `.svn/entries`, `server-status`).

### 3. `vulnScanner.js` — Vulnerabilities & OWASP (Top 10 mapped)
CSP weaknesses (unsafe-inline / unsafe-eval / wildcard / missing object-src / missing base-uri) · HSTS quality · COOP & X-Permitted-Cross-Domain-Policies · Subresource Integrity (SRI) · outdated jQuery / AngularJS (EOL) / Bootstrap · CMS/generator version & WordPress detection · password-field autocomplete · POST form without CSRF token · secrets in page source (AWS, Google, Stripe pub/secret, private key, JWT, internal IP) · source-map exposure · `security.txt` · HTTP TRACE (XST) · CORS reflection · directory listing · reflected-input (XSS signal) · SQL-error (SQLi signal) · open redirect · unsafe HTTP methods · exposed dev endpoints (Spring Actuator, Swagger/OpenAPI docs, OpenID config) · GraphQL introspection.

### 4. `renderScanner.js` — JavaScript / render (headless Chromium)
Console errors · uncaught exceptions · failed network requests · post-JS render verification (blank-page detection). Honors authenticated-scan headers.

### 5. `apiScanner.js` — API checks
Reachability · status code · response time · JSON validity · content-type · CORS · supported methods (OPTIONS) · auth behavior · HTTPS.

### 6. `apiFuzzScanner.js` — Parameter fuzzing
Targets: query params + nested/array JSON body fields (`user.roles.0`) + your custom payloads.
Payloads: SQLi (`'`, boolean) · reflected XSS · path traversal · command injection (`;id`, `|id`) · SSTI (`${7*7}`, `{{7*7}}`) · oversized · type-confusion (array).
Detectors: SQL errors · reflection (content-type aware) · `/etc/passwd` · command output · SSTI arithmetic · HTTP 500 · stack traces.
**Non-destructive boolean-based SQLi confirmation** (tautology vs contradiction). GET-safe by default; write-method/body fuzzing is opt-in.

### 7. `accessScanner.js` — Access control (OWASP A01)
Authentication enforcement (authenticated vs anonymous) · IDOR heuristic (sequential IDs) · 401/403 auth-bypass (spoofed `X-Forwarded-*`/`X-Original-URL` headers + path-normalisation) · rate-limit probe (opt-in) · race-condition probe (opt-in, experimental).

### 8. `apiSpecScanner.js` — API surface
OpenAPI/Swagger spec discovery (common paths or a given spec URL) · documented-endpoint enumeration · flags documented endpoints reachable without authentication.

### 9. `auditScanner.js` — Performance / Accessibility / SEO
**Performance:** TTFB · gzip/brotli compression · caching headers · render-blocking `<head>` scripts · page weight · resource count.
**Accessibility (WCAG, static):** unlabeled form fields · empty links/buttons · pinch-zoom disabled · duplicate IDs · skipped heading levels.
**SEO:** title length · meta description · canonical · Open Graph tags · `noindex` robots meta · `robots.txt` · `sitemap.xml`.

### 10. `codeScanner.js` — Source code
Secrets/keys (AWS, Google, Stripe, GitHub, GitLab, Slack, SendGrid, Twilio, npm, OpenAI, Anthropic, Mailgun, private keys, JWTs, Google service accounts, hardcoded passwords, DB connection strings) · dangerous patterns (`eval`, `Function`, `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, shell exec, SQL concatenation) · committed sensitive files (`.env`, `.git`, SSH keys, `.htpasswd`, backups) · known-vulnerable dependencies via **OSV.dev** (npm, PyPI, Composer, RubyGems).

### 11. `codeAuditScanner.js` — Code quality / frontend / config / testing / hygiene (native static analysis)
**Code quality:** oversized files (>300 lines) · god modules (20+ exports) · TODO/FIXME/"not implemented" stubs · empty function bodies · commented-out code blocks · **AI-hallucinated/undeclared imports** (imported but not in package.json).
**Performance anti-patterns:** `await` inside `.map()` · synchronous I/O (`…Sync`) · JSON parse/stringify inside loops.
**Frontend quality:** `<img>` without alt · `target="_blank"` without `rel="noopener"` · full lodash/moment imports · direct DOM access in React · `useEffect` timers/listeners without cleanup · list render without `key`.
**Config & DevOps:** hardcoded localhost URLs · unpinned Docker `:latest` · missing health endpoint · excessive `console.log` · TypeScript strict mode disabled.
**Testing:** no tests · low test-to-source ratio · empty test bodies · tests without assertions.
**Project hygiene:** committed `.env` · weak/missing `.gitignore` · missing README · missing `.env.example` · missing lock file.

> Native & dependency-free (regex/heuristic) — these approximate what ESLint / SonarQube cover. For full depth, integrate those tools in CI. Dependency CVEs already use OSV.dev (Trivy-equivalent).

*Shared helpers (not test engines): `util.js`, `scoring.js`, `patterns.js`, `repro.js`.*

---

## Supporting tools

- **Authenticated scanning** — attach headers (Authorization/Cookie) to every request across all suites incl. the headless browser; credentials redacted in exports.
- **Saved auth profiles** — store/apply named header sets (browser `localStorage`).
- **Practice-site presets** — one-click legal test targets (SauceDemo, the-internet, Juice Shop demo, JSONPlaceholder, Restful-Booker, PetStore, httpbin…).
- **Reproduction PoC + hand-off** — copy-paste `curl` per finding (credentials redacted) and a `sqlmap` hand-off command for confirmed SQLi.
- **Reports** — export JSON, save as PDF (print stylesheet).
- **Scan history** — recent scans saved locally; re-open any report without re-scanning.
- **Learn & roadmap tab** — pentest methodology, manual business-logic/workflow-abuse playbook, OWASP Top 10 reference, security-engineer roadmap, curated practice & learning links.

---

## Scope & safety (what it does NOT do — by design)

- **Non-intrusive:** confirms vulnerabilities (boolean SQLi, SSTI, open redirect) but never weaponises — no data exfiltration, RCE, data modification/deletion, or DoS.
- **Black-box limits:** no database/server internals (not visible over HTTP without credentials), no native mobile-app testing, no load/stress testing.
- **Authorization:** scan only systems you own or are authorized to assess. `localhost`/private ranges are blocked unless `SENTRYSCAN_ALLOW_LOCAL=1`; cloud-metadata IPs always blocked.
