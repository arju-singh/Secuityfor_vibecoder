// Live render / JavaScript tester using a headless Chromium (Playwright).
// Captures console errors, uncaught exceptions, failed network requests, and
// verifies the page actually renders content after JS executes.
import { finding, normalizeUrl } from './util.js';

let chromiumModule = null;
async function loadChromium() {
  if (chromiumModule) return chromiumModule;
  const mod = await import('playwright'); // throws if not installed
  chromiumModule = mod.chromium;
  return chromiumModule;
}

export async function scanRender(input, opts = {}) {
  const u = normalizeUrl(input);
  const findings = [];
  const meta = { target: u.href };
  const authHeaders = opts.authHeaders || null;

  let chromium;
  try {
    chromium = await loadChromium();
  } catch {
    const err = new Error('Render testing requires Playwright. Install it with: npm install playwright && npx playwright install chromium');
    err.code = 'RENDER_UNAVAILABLE';
    throw err;
  }

  let browser;
  try {
    browser = await chromium.launch({ headless: true, timeout: 30000 });
  } catch (e) {
    const err = new Error('Chromium browser is not installed. Run: npx playwright install chromium');
    err.code = 'RENDER_UNAVAILABLE';
    throw err;
  }

  const consoleErrors = [];
  const pageErrors = [];
  const failedRequests = [];

  try {
    const context = await browser.newContext({
      userAgent: 'SentryScan/2.0 (+render-test)',
      ignoreHTTPSErrors: true,
      ...(authHeaders ? { extraHTTPHeaders: authHeaders } : {})
    });
    const page = await context.newPage();

    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text().slice(0, 300));
    });
    page.on('pageerror', (err) => pageErrors.push((err && err.message ? err.message : String(err)).slice(0, 300)));
    page.on('requestfailed', (req) => {
      const f = req.failure();
      failedRequests.push(`${req.method()} ${req.url().slice(0, 160)} — ${(f && f.errorText) || 'failed'}`);
    });
    page.on('response', (res) => {
      const s = res.status();
      if (s >= 400) failedRequests.push(`HTTP ${s} ${res.url().slice(0, 160)}`);
    });

    let mainStatus = null;
    const resp = await page.goto(u.href, { waitUntil: 'load', timeout: 25000 }).catch((e) => {
      findings.push(finding('high', 'Page failed to load in browser',
        `Navigation failed: ${e.message}`,
        'Check that the page loads in a real browser without fatal errors.', e.message));
      return null;
    });
    if (resp) mainStatus = resp.status();
    meta.status = mainStatus;

    // Allow client-side frameworks to render.
    await page.waitForTimeout(2500);

    const info = await page.evaluate(() => ({
      title: document.title,
      bodyTextLen: (document.body && document.body.innerText ? document.body.innerText.trim().length : 0),
      elementCount: document.querySelectorAll('body *').length,
      hasVisible: !!(document.body && document.body.getClientRects().length)
    }));
    meta.renderedTitle = info.title;
    meta.renderedElements = info.elementCount;
    meta.renderedTextLength = info.bodyTextLen;

    if (info.bodyTextLen < 20 && info.elementCount < 8) {
      findings.push(finding('high', 'Nothing rendered after JavaScript executed',
        'After loading and running scripts, the page shows almost no content. This usually means a fatal JS error or a failed data fetch.',
        'Open the browser console on the page and fix the errors preventing render.',
        `${info.elementCount} elements, ${info.bodyTextLen} chars`));
    }

    if (pageErrors.length) {
      findings.push(finding('high', `${pageErrors.length} uncaught JavaScript error(s)`,
        'The page threw uncaught exceptions while running, which can break functionality.',
        'Fix the runtime errors; uncaught exceptions often halt subsequent script execution.',
        [...new Set(pageErrors)].slice(0, 6).join('\n')));
    }
    if (consoleErrors.length) {
      findings.push(finding('medium', `${consoleErrors.length} console error(s)`,
        'The browser console logged errors during page load.',
        'Review and resolve console errors; they frequently signal broken features.',
        [...new Set(consoleErrors)].slice(0, 6).join('\n')));
    }
    if (failedRequests.length) {
      findings.push(finding('medium', `${failedRequests.length} failed network request(s)`,
        'One or more resources or API calls failed to load while rendering.',
        'Fix or remove the failing requests; missing assets/data break the UI.',
        [...new Set(failedRequests)].slice(0, 8).join('\n')));
    }

    if (!findings.length) {
      findings.push(finding('info', 'Page rendered cleanly',
        `Rendered ${info.elementCount} elements with no JS errors or failed requests.`,
        null, `title: "${info.title || ''}"`));
    }
  } finally {
    await browser.close().catch(() => {});
  }

  return { type: 'render', meta, findings };
}
