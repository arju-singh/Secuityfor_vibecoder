# SentryScan — Website Tester

A full-stack web app to test any website across four dimensions — UI health, API behavior, security, and live JavaScript rendering — plus a source-code scanner. Three modes:

1. **Test a website** (URL) — runs four suites and merges the results:
   - **UI / health**: page load time & size, HTTP status, broken links & missing resources (verified with real HEAD/GET requests), missing `<title>`/viewport/charset/`lang`/`<h1>`, images missing `alt`, insecure form submission, and blank/broken-page detection.
   - **Security**: HTTPS enforcement, security headers, TLS certificate health, cookie flags, CORS, clickjacking, mixed content, exposed files (`.env`, `.git`, backups, `phpinfo`).
   - **Vulnerabilities & OWASP**: non-destructive vulnerability checks of the class used by baseline DAST tools, each mapped to an OWASP Top 10 (2021) category — see the table below.
   - **Render (JavaScript)**: a real headless Chromium loads the page and captures console errors, uncaught exceptions, failed network requests, and verifies content actually renders after scripts run.
   - **Quality audits** (optional, on by default): **Performance** (TTFB, compression, caching headers, render-blocking scripts, page weight), **Accessibility/WCAG** (static checks: unlabeled fields, empty links/buttons, pinch-zoom disabled, duplicate IDs, skipped heading levels), and **SEO** (title/description length, canonical, Open Graph, robots meta, robots.txt & sitemap.xml). These are static, read-only audits — no load/stress testing.
2. **Test an API** (URL) — reachability, status code, response time, JSON validity, content-type, CORS, supported methods (OPTIONS), auth behavior, and HTTPS. Also runs **access-control checks** (OWASP A01): authentication enforcement (compares authenticated vs anonymous responses), an **IDOR heuristic** (are sequential object IDs directly addressable while out-of-range IDs 404?), **401/403 auth-bypass** attempts (spoofed `X-Forwarded-*`/`X-Original-URL` headers and path-normalisation tricks), an opt-in **rate-limit test** (burst of requests, watches for HTTP 429), opt-in **OpenAPI/Swagger endpoint enumeration** (finds the API's spec, maps the documented surface, and flags documented endpoints reachable without auth), and an opt-in, experimental **race-condition probe** (concurrent write requests). These are *signals* to confirm manually — business-logic / workflow-abuse flaws cannot be automated and stay a manual exercise. Optionally **fuzz query parameters** (and, with explicit opt-in, **JSON request-body fields** — including **nested objects and array elements** like `user.roles.0` — via POST/PUT/PATCH/DELETE, plus your own **custom payload list**): each parameter/field is probed with crafted payloads (SQL injection, reflected XSS, path traversal, command injection, server-side template injection, oversized/type-confusion inputs) and the responses are checked for SQL errors, command output, reflected markers, stack traces, and unhandled 500s — each mapped to OWASP A03/A04.
3. **Scan source code** (upload) — leaked API keys & secrets, private keys, hardcoded passwords, dangerous code patterns (`eval`, `innerHTML`, SQL concatenation, command execution), committed sensitive files, and **known-vulnerable dependencies** checked live against the [OSV.dev](https://osv.dev) advisory database (npm, PyPI, Composer, RubyGems). Plus native static-analysis audits: **code quality** (oversized files, god modules, TODO/empty stubs, **AI-hallucinated/undeclared imports**, `await`-in-`.map()` and other perf anti-patterns), **frontend quality** (missing alt, missing `key`, `useEffect` leaks, unsafe `target="_blank"`), **config/DevOps** (hardcoded localhost, unpinned Docker, TS strict, missing health endpoint), **testing quality** (no tests, empty tests, no assertions), and **project hygiene** (committed `.env`, weak `.gitignore`, missing README/lock file).
Every report can be **exported as JSON** (the full structured result) or **saved as PDF** (via the browser's print-to-PDF, with a clean print stylesheet). Completed scans are kept in a **History** tab (stored locally in your browser) so you can re-open any past report without re-scanning. Nothing is persisted on the server.

4. **Learn & roadmap** — an in-app reference: the penetration-testing methodology, the full OWASP Top 10 (2021) with what SentryScan automates vs. what to test manually, a security-engineer career roadmap, and curated **legal practice targets** (one click loads them into the testers) plus guided learning paths (OWASP, PortSwigger Web Academy, TryHackMe, Hack The Box).

### Authenticated scanning

Both the Website and API tabs have an optional **Authenticated scan** box. Provide request headers (one per line, e.g. `Authorization: Bearer …` or `Cookie: session=…`) and SentryScan attaches them to **every** request across all suites — including the headless-browser render — so it tests pages and endpoints as a logged-in user. Headers are validated server-side (forbidden headers like `Host`/`Content-Length` are stripped, max 12) and applied per-request via `AsyncLocalStorage`, so they never leak between concurrent scans and are never persisted server-side. Header sets can be **saved as named profiles** (stored locally in your browser via `localStorage`) and re-applied across both tabs.

The Website and API tabs also include **one-click practice presets** (SauceDemo, the-internet, OWASP Juice Shop demo, JSONPlaceholder, Restful-Booker, PetStore, httpbin, …) so you can try it as a tester immediately.

Every finding is tagged with a category and severity (Critical → Info) and carries evidence, a location, and a concrete fix. Results are grouped by category with an overall 0–100 score and letter grade. Works against any of the common practice/automation sites (SauceDemo, the-internet, JSONPlaceholder, httpbin, PetStore, etc.) as well as your own.

## Requirements

- Node.js 18 or newer (uses native `fetch` and `tls`).

## Setup

```bash
npm install
npx playwright install chromium   # enables the live JS/render test
npm start
```

Then open <http://localhost:3000>.

> The render test needs Chromium. If you skip `npx playwright install chromium`, the website test still runs UI + security and clearly reports the render suite as unavailable — it never fails silently or fabricates results.

To run with auto-reload during development:

```bash
npm run dev
```

The server listens on `PORT` (default `3000`).

## How it works

- **Backend** (`server.js` + `src/scanners/`): Express API.
  - `POST /api/test/website` — `{ "url": "example.com", "render": true, "headers": { "Authorization": "Bearer …" } }` (UI + security + vuln + render; `headers` optional for authenticated scans)
  - `POST /api/test/api` — `{ "url": "https://api.example.com/endpoint?q=1", "fuzz": true, "headers": { … }, "method": "POST", "body": "{\"user\":\"a\"}", "allowWrite": true }` (`fuzz`, `headers`, and the write-fuzz fields are optional)
  - `POST /api/scan/files` — multipart upload (`.zip` or loose files)
- **Frontend** (`public/`): single-page UI with a score gauge, per-category summary cards, severity + category filters, and per-finding remediation.

### Scanner modules

| File | Responsibility |
|------|----------------|
| `src/scanners/uiScanner.js` | UI/health: load, broken links/resources, structure, accessibility, forms |
| `src/scanners/auditScanner.js` | Quality audits: performance, accessibility (WCAG, static), SEO (one fetch → 3 sections) |
| `src/scanners/apiScanner.js` | API: status, timing, JSON validity, CORS, methods, auth, HTTPS |
| `src/scanners/apiFuzzScanner.js` | API parameter fuzzing: per-parameter injection payloads + anomaly detection (GET-only) |
| `src/scanners/accessScanner.js` | Access control (A01): auth enforcement, IDOR, 401/403 bypass, rate-limit, race-condition probe |
| `src/scanners/apiSpecScanner.js` | OpenAPI/Swagger discovery + documented-endpoint enumeration |
| `src/scanners/urlScanner.js` | Security: headers, TLS, cookies, CORS, exposed paths, mixed content |
| `src/scanners/renderScanner.js` | Headless Chromium: console/JS errors, failed requests, render check |
| `src/scanners/codeScanner.js` | Secret detection, dangerous patterns, sensitive files, OSV dependency lookups |
| `src/scanners/patterns.js` | Secret regex rules, code-pattern rules, sensitive-file rules |
| `src/scanners/util.js` | URL normalization + SSRF guard, fetch-with-timeout, finding helper |
| `src/scanners/scoring.js` | Severity weighting and grade computation |

## OWASP Top 10 (2021) coverage

The vulnerability suite maps each finding to an OWASP category:

| OWASP category | What SentryScan checks |
|----------------|------------------------|
| A01 Broken Access Control | Directory listing exposure, POST forms without a CSRF token, open-redirect parameters, exposed `.git`/admin paths |
| A02 Cryptographic Failures | HTTP (no HTTPS), weak/expired TLS, weak HSTS, secrets & keys exposed in page source |
| A03 Injection | Reflected-input canary (reflected-XSS signal), SQL-error signature probe (parameters only) |
| A05 Security Misconfiguration | CSP weaknesses (`unsafe-inline`/`unsafe-eval`/wildcard, missing `object-src`/`base-uri`), TRACE/XST, CORS Origin reflection, unsafe HTTP methods (PUT/DELETE/PATCH via OPTIONS), exposed Spring Actuator / Swagger-OpenAPI / GraphQL introspection, missing cross-origin headers, source-map exposure, version disclosure |
| A06 Vulnerable & Outdated Components | Outdated jQuery / AngularJS (EOL) / Bootstrap, CMS & server version fingerprinting, vulnerable dependencies via OSV (code scan) |
| A07 Identification & Authentication Failures | Insecure cookie flags, password fields on non-HTTPS, autocomplete on credential fields |
| A08 Software & Data Integrity Failures | Third-party scripts/styles loaded without Subresource Integrity (SRI) |
| A09 Security Logging & Monitoring Failures | Missing `security.txt` (RFC 9116) disclosure contact |

The reflected-input and SQL-error probes only run when the tested URL already contains query parameters, and they send a single benign, non-executing request per technique. They flag *signals* to investigate — confirm manually before remediation sign-off.

## Exploitation stance

Each actionable finding carries a **reproduction PoC** — a copy-paste `curl` command that reproduces the exact request (with your credentials **redacted** to `<your-credential>` so exported reports never leak tokens) — and, for SQL injection, an **authorized hand-off command** (`sqlmap …`) to run yourself within an authorized engagement. The scanner finds and confirms; the human exploits, under their own authorization.

SentryScan **confirms** vulnerabilities but never **weaponises** them. For SQL injection on a GET query parameter it runs a **non-destructive boolean-based confirmation** (a tautology `1=1` vs a contradiction `1=2`); if responses differ reliably, the parameter is *confirmed* injectable — **without reading or modifying any data**. Server-side template injection is confirmed by safe arithmetic (`7*7`→`49`) and open redirects by following the `Location` header. The tool deliberately does **not** extract data, run OS commands (RCE), modify/delete data, or perform DoS — those require explicit, contextual authorization and are left to manual testing.

## Safety & scope

SentryScan is a **non-intrusive** auditor. The URL scanner issues only ordinary `GET` requests — the same a browser makes — and never attempts exploits. **Parameter fuzzing is GET-only by default** and cannot modify server-side data. Fuzzing a **JSON request body** (and using write methods POST/PUT/PATCH/DELETE) is supported but **off unless you explicitly enable "Allow destructive (write) requests"** — those requests can create or modify data, so only enable them on systems you own or are authorized to test. Either way, fuzzing sends many requests; use it responsibly. Scans of `localhost` and private/internal network addresses are blocked (SSRF protection). The code scanner analyzes files in memory and only contacts OSV.dev to check dependency versions. No scan results are persisted.

Scans of `localhost` and private/internal addresses are **blocked by default**. To scan your own local/dev server, start with `SENTRYSCAN_ALLOW_LOCAL=1 npm start` — cloud metadata endpoints (`169.254.169.254`) stay blocked regardless. The behavior is covered by an integration test (`npm test`) that fuzzes a deliberately-vulnerable local server and asserts SQLi, XSS, path-traversal, command-injection, SSTI, and authenticated-scan detection all work with no false positives.

**Only scan websites and code you own or are explicitly authorized to assess.**

## What it detects

**URL scan**
- Site served over plain HTTP / missing HTTP→HTTPS redirect
- Missing HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- Clickjacking exposure
- Weak/expired/untrusted TLS certificates and deprecated TLS versions
- Insecure cookies (missing Secure / HttpOnly / SameSite)
- Wildcard or credentialed CORS misconfiguration
- Server / X-Powered-By version disclosure
- Mixed (HTTP) content on HTTPS pages
- Publicly accessible `.env`, `.git`, backups, `phpinfo`, `server-status`, and more

**Code scan**
- AWS, Google, Stripe, GitHub, GitLab, Slack, SendGrid, Twilio, npm, OpenAI, Anthropic, Mailgun keys & tokens
- Private keys, JWTs, Google service-account blocks
- Hardcoded passwords/secrets and credentialed DB/URL connection strings
- `eval`, `Function`, `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, shell exec, SQL concatenation
- Committed `.env`, `.git`, SSH keys, `.htpasswd`, backup files
- Known-vulnerable npm / PyPI / Composer / RubyGems dependencies (OSV.dev)
# Secuityfor_vibecoder
