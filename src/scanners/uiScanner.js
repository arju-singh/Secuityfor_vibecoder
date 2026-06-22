// Website health / UI scanner. Fetches a page, inspects structure and quality,
// and verifies that linked resources and links actually resolve.
import * as cheerio from 'cheerio';
import { URL } from 'node:url';
import { finding, fetchWithTimeout, normalizeUrl, formatBytes } from './util.js';

const MAX_LINK_CHECKS = 40;

// Link checks answer "will this load for a visitor?", so request like a real
// browser — many sites (GitHub, Cloudflare-fronted) return 4xx to bot-like
// user-agents that a normal browser would never see.
const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
};

function resolve(base, href) {
  try { return new URL(href, base).href; } catch { return null; }
}

async function checkResolvable(urls, label) {
  const findings = [];
  const targets = [...new Set(urls)].slice(0, MAX_LINK_CHECKS);
  await Promise.allSettled(targets.map(async (url) => {
    try {
      let res = await fetchWithTimeout(url, { method: 'HEAD', timeout: 8000, redirect: 'follow', headers: BROWSER_HEADERS });
      // Some servers reject HEAD (or bot-like requests); retry with a GET.
      if (res.status === 405 || res.status === 501 || res.status === 400 || res.status === 403) {
        res = await fetchWithTimeout(url, { method: 'GET', timeout: 8000, redirect: 'follow', headers: { ...BROWSER_HEADERS, Range: 'bytes=0-0' } });
      }
      if (res.status === 401 || res.status === 403) {
        // Access-controlled, not broken — it loads for authorized users.
        findings.push(finding('info', `${label} requires authorization (HTTP ${res.status})`,
          `A ${label} returns HTTP ${res.status}; the resource exists but is access-controlled, so anonymous visitors cannot load it.`,
          `Confirm this is intentional; if the link is meant to be public, fix the access rules for ${url}.`,
          url));
      } else if (res.status >= 400) {
        findings.push(finding(
          res.status >= 500 ? 'high' : 'medium',
          `Broken ${label} (HTTP ${res.status})`,
          `A ${label} on the page returns HTTP ${res.status} and will not load for visitors.`,
          `Fix or remove the reference to ${url}.`,
          url));
      }
    } catch (e) {
      findings.push(finding('medium', `Unreachable ${label}`,
        `A ${label} could not be loaded (${e.name === 'AbortError' ? 'timeout' : e.message}).`,
        `Verify that ${url} is correct and reachable.`, url));
    }
  }));
  return findings;
}

export async function scanUi(input) {
  const u = normalizeUrl(input);
  const findings = [];
  const meta = { target: u.href };

  let res, html = '', elapsed = 0, bytes = 0;
  try {
    res = await fetchWithTimeout(u.href, { redirect: 'follow', timeout: 15000 });
    elapsed = res._elapsedMs || 0;
    meta.finalUrl = res.url;
    meta.status = res.status;
    const ctype = res.headers.get('content-type') || '';
    const body = await res.text();
    bytes = Buffer.byteLength(body);
    if (/text\/html|application\/xhtml/i.test(ctype)) html = body;
    meta.loadTimeMs = elapsed;
    meta.pageSize = formatBytes(bytes);
    meta.contentType = ctype.split(';')[0];
  } catch (e) {
    throw new Error(`Could not load ${u.href}: ${e.message}`);
  }

  // HTTP status
  if (res.status >= 400) {
    findings.push(finding(res.status >= 500 ? 'critical' : 'high',
      `Page returns HTTP ${res.status}`,
      'The main page does not return a successful response.',
      'Ensure the URL is correct and the server returns 2xx for this page.', String(res.status)));
  }

  // Load time / weight
  if (elapsed > 5000) {
    findings.push(finding('medium', `Slow page load (${(elapsed / 1000).toFixed(1)}s)`,
      'The page took over 5 seconds to respond, which harms usability and SEO.',
      'Optimize server response time, enable caching/CDN, and reduce payload size.', elapsed + 'ms'));
  } else if (elapsed > 2500) {
    findings.push(finding('low', `Elevated page load time (${(elapsed / 1000).toFixed(1)}s)`,
      'Response time is above the 2.5s "good" threshold.',
      'Investigate slow backend calls or large assets.', elapsed + 'ms'));
  }
  if (bytes > 3 * 1024 * 1024) {
    findings.push(finding('low', `Large HTML document (${formatBytes(bytes)})`,
      'The HTML payload is unusually large, slowing first paint.',
      'Reduce inline content and lazy-load below-the-fold markup.'));
  }

  if (!html) {
    findings.push(finding('info', 'Non-HTML response',
      `The response content-type is "${meta.contentType}", so UI checks were skipped.`,
      'If this should be a web page, ensure it returns text/html.'));
    return { type: 'ui', meta, findings };
  }

  const $ = cheerio.load(html);
  const base = meta.finalUrl || u.href;
  const isHttps = new URL(base).protocol === 'https:';

  // Empty / broken render heuristic
  const bodyText = $('body').text().replace(/\s+/g, ' ').trim();
  const elementCount = $('body *').length;
  if (bodyText.length < 30 && elementCount < 5) {
    findings.push(finding('high', 'Page appears blank or broken',
      'The page contains almost no visible content or elements when loaded without JavaScript.',
      'If the app is client-rendered, confirm it renders correctly (run the JS/render test); otherwise the page may be broken.',
      `${elementCount} elements, ${bodyText.length} chars of text`));
  }

  // Document structure
  const title = $('title').first().text().trim();
  if (!title) {
    findings.push(finding('medium', 'Missing or empty <title>',
      'The page has no title, hurting accessibility, bookmarks, and SEO.',
      'Add a descriptive <title> element.'));
  }
  if ($('meta[name="viewport"]').length === 0) {
    findings.push(finding('medium', 'Missing viewport meta tag',
      'Without a viewport meta tag the page will not be mobile-responsive.',
      'Add <meta name="viewport" content="width=device-width, initial-scale=1">.'));
  }
  if ($('meta[charset]').length === 0 && !/charset=/i.test($('meta[http-equiv="Content-Type"]').attr('content') || '')) {
    findings.push(finding('low', 'Missing charset declaration',
      'No character encoding is declared, which can cause text rendering issues.',
      'Add <meta charset="utf-8"> as the first element in <head>.'));
  }
  const lang = $('html').attr('lang');
  if (!lang) {
    findings.push(finding('low', 'Missing lang attribute on <html>',
      'Screen readers cannot determine the page language.',
      'Add a lang attribute, e.g. <html lang="en">.'));
  }
  const h1count = $('h1').length;
  if (h1count === 0) {
    findings.push(finding('low', 'No <h1> heading',
      'The page lacks a primary heading, weakening document structure and SEO.',
      'Add a single, descriptive <h1>.'));
  } else if (h1count > 1) {
    findings.push(finding('info', `Multiple <h1> headings (${h1count})`,
      'More than one top-level heading can confuse document outline and assistive tech.',
      'Prefer a single <h1> per page.'));
  }

  // Images without alt
  const imgs = $('img');
  let noAlt = 0;
  imgs.each((_, el) => { if ($(el).attr('alt') === undefined) noAlt++; });
  if (noAlt > 0) {
    findings.push(finding('low', `${noAlt} image(s) missing alt text`,
      'Images without alt attributes are inaccessible to screen readers.',
      'Add descriptive alt text (or alt="" for decorative images).', `${noAlt} of ${imgs.length} images`));
  }

  // Forms
  const forms = $('form');
  meta.forms = forms.length;
  forms.each((_, el) => {
    const action = $(el).attr('action') || '';
    if (/^http:\/\//i.test(action) || (isHttps && action && resolve(base, action) && new URL(resolve(base, action)).protocol === 'http:')) {
      findings.push(finding('high', 'Form submits over insecure HTTP',
        'A form posts to an http:// endpoint, exposing submitted data in transit.',
        'Submit all forms over HTTPS.', action));
    }
    const hasPassword = $(el).find('input[type="password"]').length > 0;
    if (hasPassword && !isHttps) {
      findings.push(finding('high', 'Password field on non-HTTPS page',
        'A password input is served over an insecure connection.',
        'Serve any page with credential inputs over HTTPS.'));
    }
  });

  // Collect resources & links for resolvability checks
  const resources = [];
  $('script[src]').each((_, el) => { const r = resolve(base, $(el).attr('src')); if (r && /^https?:/.test(r)) resources.push(r); });
  $('link[rel="stylesheet"][href]').each((_, el) => { const r = resolve(base, $(el).attr('href')); if (r && /^https?:/.test(r)) resources.push(r); });
  $('img[src]').each((_, el) => { const r = resolve(base, $(el).attr('src')); if (r && /^https?:/.test(r)) resources.push(r); });

  const links = [];
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    if (!href || /^(#|mailto:|tel:|javascript:|data:)/i.test(href)) return;
    const r = resolve(base, href);
    if (r && /^https?:/.test(r)) links.push(r);
  });
  meta.resourceCount = resources.length;
  meta.linkCount = links.length;

  const [resFindings, linkFindings] = await Promise.all([
    checkResolvable(resources, 'resource'),
    checkResolvable(links, 'link')
  ]);
  findings.push(...resFindings, ...linkFindings);

  return { type: 'ui', meta, findings };
}
