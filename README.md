# SentryScan — Website Tester

A full-stack web app to test any website across four dimensions — UI health, API behavior, security, and live JavaScript rendering — plus a source-code scanner. Three modes:

1. **Test a website** (URL) — runs four suites and merges the results:
   - **UI / health**: page load time & size, HTTP status, broken links & missing resources (verified with real HEAD/GET requests), missing `<title>`/viewport/charset/`lang`/`<h1>`, images missing `alt`, insecure form submission, and blank/broken-page detection.
   - **Security**: HTTPS enforcement, security headers, TLS certificate health, cookie flags, CORS, clickjacking, mixed content, exposed files (`.env`, `.git`, backups, `phpinfo`).
   - **Vulnerabilities & OWASP**: non-destructive vulnerability checks of the class used by baseline DAST tools, each mapped to an OWASP Top 10 (2021) category — see the table below.
   - **Render (JavaScript)**: a real headless Chromium loads the page and captures console errors, uncaught exceptions, failed network requests, and verifies content actually renders after scripts run.
2. **Test an API** (URL) — reachability, status code, response time, JSON validity, content-type, CORS, supported methods (OPTIONS), auth behavior, and HTTPS.
3. **Scan source code** (upload) — leaked API keys & secrets, private keys, hardcoded passwords, dangerous code patterns (`eval`, `innerHTML`, SQL concatenation, command execution), committed sensitive files, and **known-vulnerable dependencies** checked live against the [OSV.dev](https://osv.dev) advisory database (npm, PyPI, Composer, RubyGems).
4. **Learn & roadmap** — an in-app reference: the penetration-testing methodology, the full OWASP Top 10 (2021) with what SentryScan automates vs. what to test manually, a security-engineer career roadmap, and curated **legal practice targets** (one click loads them into the testers) plus guided learning paths (OWASP, PortSwigger Web Academy, TryHackMe, Hack The Box).

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
  - `POST /api/test/website` — `{ "url": "example.com", "render": true }` (UI + security + render)
  - `POST /api/test/api` — `{ "url": "https://api.example.com/endpoint" }`
  - `POST /api/scan/files` — multipart upload (`.zip` or loose files)
- **Frontend** (`public/`): single-page UI with a score gauge, per-category summary cards, severity + category filters, and per-finding remediation.

### Scanner modules

| File | Responsibility |
|------|----------------|
| `src/scanners/uiScanner.js` | UI/health: load, broken links/resources, structure, accessibility, forms |
| `src/scanners/apiScanner.js` | API: status, timing, JSON validity, CORS, methods, auth, HTTPS |
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

## Safety & scope

SentryScan is a **non-intrusive** auditor. The URL scanner issues only ordinary `GET` requests — the same a browser makes — and never attempts exploits. Scans of `localhost` and private/internal network addresses are blocked (SSRF protection). The code scanner analyzes files in memory and only contacts OSV.dev to check dependency versions. No scan results are persisted.

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
