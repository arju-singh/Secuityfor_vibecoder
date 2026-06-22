// Site-quality audits: performance, accessibility (WCAG, static), and SEO.
// One fetch of the landing page feeds all three. These are static, read-only
// checks — no load/stress testing (that would be a DoS). For field performance
// and contrast/dynamic a11y, complement with Lighthouse / axe.
import * as cheerio from 'cheerio';
import { finding, fetchWithTimeout, normalizeUrl } from './util.js';

const cssEsc = (s) => String(s).replace(/["\\]/g, '\\$&');

export async function scanAudits(input) {
  const u = normalizeUrl(input);
  const meta = { target: u.href };
  let res, html = '', headers, ms = 0;
  try {
    res = await fetchWithTimeout(u.href, { redirect: 'follow', timeout: 15000 });
    ms = res._elapsedMs || 0;
    headers = res.headers;
    const ctype = headers.get('content-type') || '';
    const body = await res.text().catch(() => '');
    if (/text\/html|xhtml/i.test(ctype)) html = body.slice(0, 1_000_000);
    meta.finalUrl = res.url; meta.status = res.status; meta.ms = ms; meta.bytes = body.length;
  } catch (e) {
    throw new Error(`Could not load ${u.href}: ${e.message}`);
  }
  const $ = html ? cheerio.load(html) : null;
  return {
    meta,
    perf: perfFindings(headers, html, ms, $),
    a11y: $ ? a11yFindings($) : [],
    seo: await seoFindings($, u)
  };
}

function perfFindings(headers, html, ms, $) {
  const f = [];
  if (ms > 3000) f.push(finding('medium', `Slow server response (${ms} ms)`,
    'The server took over 3 seconds to start responding (TTFB), hurting UX and search ranking.',
    'Optimize backend/queries, add server-side caching and a CDN.', `${ms} ms TTFB`));
  else if (ms > 1000) f.push(finding('low', `Server response is slow (${ms} ms)`,
    'Time-to-first-byte over 1s is noticeable to users.',
    'Improve response time with caching, a CDN, or query tuning.', `${ms} ms TTFB`));

  const enc = headers.get('content-encoding') || '';
  if (html && !/gzip|br|deflate|zstd/i.test(enc)) f.push(finding('low', 'Response not compressed',
    'The HTML response is served without gzip/brotli compression, increasing transfer size and load time.',
    'Enable gzip or brotli compression at the server/CDN.', `content-encoding: ${enc || 'none'}`));

  if (!headers.get('cache-control') && !headers.get('etag') && !headers.get('last-modified')) {
    f.push(finding('info', 'No caching headers on the document',
      'No Cache-Control/ETag/Last-Modified, so browsers and proxies cannot cache or validate the response.',
      'Set appropriate Cache-Control / ETag headers.'));
  }
  if (html.length > 1_000_000) f.push(finding('low', `Large HTML document (${Math.round(html.length / 1024)} KB)`,
    'The HTML payload exceeds 1 MB, slowing first render.',
    'Reduce inline content and lazy-load below-the-fold sections.', `${Math.round(html.length / 1024)} KB`));

  if ($) {
    let blocking = 0;
    $('head script[src]').each((_, e) => {
      const s = $(e);
      if (s.attr('async') === undefined && s.attr('defer') === undefined) blocking++;
    });
    if (blocking >= 3) f.push(finding('low', `${blocking} render-blocking scripts in <head>`,
      'Synchronous scripts in the <head> block the page from rendering until they download and run.',
      'Add async/defer, or move non-critical scripts to the end of <body>.', `${blocking} scripts`));
    const refs = $('script[src]').length + $('link[rel="stylesheet"]').length + $('img').length;
    if (refs > 60) f.push(finding('info', `${refs} resource references on the page`,
      'A high number of scripts/styles/images increases requests and load time.',
      'Bundle and minify assets; lazy-load images.', `${refs} references`));
  }
  if (!f.length) f.push(finding('info', 'No major performance issues detected',
    `Document responded in ${ms} ms and is compressed/cacheable.`,
    'For field metrics (LCP/CLS/INP) run Lighthouse or WebPageTest.'));
  return f;
}

function a11yFindings($) {
  const f = [];
  let unlabeled = 0;
  $('input, select, textarea').each((_, e) => {
    const el = $(e);
    const type = (el.attr('type') || '').toLowerCase();
    if (['hidden', 'submit', 'button', 'image', 'reset'].includes(type)) return;
    const id = el.attr('id');
    const labelled = (id && $(`label[for="${cssEsc(id)}"]`).length) ||
      el.attr('aria-label') || el.attr('aria-labelledby') || el.attr('title') || el.parents('label').length;
    if (!labelled) unlabeled++;
  });
  if (unlabeled) f.push(finding('medium', `${unlabeled} form field(s) without an accessible label`,
    'Form fields with no <label>/aria-label cannot be understood by screen-reader users.',
    'Associate every field with a <label for=…> or an aria-label.', `${unlabeled} field(s)`));

  let emptyControls = 0;
  $('a, button').each((_, e) => {
    const el = $(e);
    const text = (el.text() || '').trim();
    const alt = el.attr('aria-label') || el.attr('title');
    const imgAlt = el.find('img[alt]').filter((_, i) => ($(i).attr('alt') || '').trim()).length;
    if (!text && !alt && !imgAlt) emptyControls++;
  });
  if (emptyControls) f.push(finding('medium', `${emptyControls} link(s)/button(s) with no accessible text`,
    'Controls with no text or aria-label are announced as blank, so users cannot tell what they do.',
    'Add visible text or an aria-label to every link and button.', `${emptyControls} control(s)`));

  const vp = ($('meta[name="viewport"]').attr('content') || '').toLowerCase();
  if (/user-scalable\s*=\s*no|maximum-scale\s*=\s*1(\.0)?(\b|,|;|$)/.test(vp)) {
    f.push(finding('medium', 'Pinch-zoom disabled',
      'The viewport meta disables zooming (user-scalable=no / maximum-scale=1), which blocks low-vision users from enlarging content.',
      'Allow zoom: remove user-scalable=no and maximum-scale.', vp));
  }
  const ids = {};
  $('[id]').each((_, e) => { const id = $(e).attr('id'); ids[id] = (ids[id] || 0) + 1; });
  const dups = Object.keys(ids).filter((k) => ids[k] > 1);
  if (dups.length) f.push(finding('low', `${dups.length} duplicate id attribute(s)`,
    'Duplicate IDs break <label for>, aria references, and in-page anchors.',
    'Make every id unique.', dups.slice(0, 6).join(', ')));

  const levels = [];
  $('h1, h2, h3, h4, h5, h6').each((_, e) => levels.push(Number(e.tagName[1])));
  if (levels.some((lvl, i) => i > 0 && lvl - levels[i - 1] > 1)) {
    f.push(finding('low', 'Skipped heading level',
      'Heading levels jump (e.g. h2 → h4), making the document outline confusing for assistive tech.',
      'Use sequential heading levels without skipping.'));
  }
  if (!f.length) f.push(finding('info', 'No major accessibility issues detected (static check)',
    'Static structural checks passed. This does not cover colour contrast or dynamic content.',
    'Run axe / Lighthouse and test with a real screen reader.'));
  return f;
}

async function seoFindings($, u) {
  const f = [];
  if ($) {
    const title = ($('title').text() || '').trim();
    if (title && (title.length < 10 || title.length > 60)) f.push(finding('low', `Title length not ideal (${title.length} chars)`,
      'Page titles around 10–60 characters render best in search results.',
      'Write a concise, descriptive 10–60 character <title>.', title.slice(0, 80)));

    const desc = ($('meta[name="description"]').attr('content') || '').trim();
    if (!desc) f.push(finding('low', 'Missing meta description',
      'No <meta name="description">, so search engines auto-generate the result snippet.',
      'Add a unique 50–160 character meta description.'));
    else if (desc.length < 50 || desc.length > 160) f.push(finding('info', `Meta description length not ideal (${desc.length} chars)`,
      'Descriptions around 50–160 characters display best in search results.',
      'Tune the meta description length.'));

    if (!$('link[rel="canonical"]').length) f.push(finding('info', 'No canonical link',
      'Without a canonical URL, duplicate-content variants can split ranking signals.',
      'Add <link rel="canonical" href="…">.'));

    const robotsMeta = ($('meta[name="robots"]').attr('content') || '').toLowerCase();
    if (/noindex/.test(robotsMeta)) f.push(finding('medium', 'Page set to noindex',
      'A robots meta tag instructs search engines not to index this page — confirm that is intended.',
      'Remove noindex if the page should appear in search.', robotsMeta));

    if (!$('meta[property="og:title"]').length && !$('meta[property="og:image"]').length) {
      f.push(finding('info', 'No Open Graph tags',
        'Missing og: tags produce poor link previews when shared on social/chat.',
        'Add Open Graph tags (og:title, og:description, og:image).'));
    }
  }
  await Promise.allSettled([
    (async () => {
      try {
        const r = await fetchWithTimeout(u.origin + '/robots.txt', { timeout: 6000, redirect: 'manual' });
        if (r.status !== 200) f.push(finding('info', 'No robots.txt',
          'No /robots.txt to guide crawlers or point to the sitemap.',
          'Add a robots.txt referencing your sitemap.'));
      } catch { /* ignore */ }
    })(),
    (async () => {
      try {
        const s = await fetchWithTimeout(u.origin + '/sitemap.xml', { timeout: 6000, redirect: 'manual' });
        if (s.status !== 200) f.push(finding('info', 'No sitemap.xml',
          'No /sitemap.xml found to help search engines discover your pages.',
          'Publish a sitemap.xml.'));
      } catch { /* ignore */ }
    })()
  ]);
  if (!f.length) f.push(finding('info', 'No major SEO issues detected',
    'Core SEO tags appear present.',
    'Validate with Google Search Console and Lighthouse SEO.'));
  return f;
}
