/* Privacy-respecting analytics loader. Loads a provider ONLY after cookie
   consent (see consent.js) and ONLY if the server reports one configured via
   /api/config. Supports Plausible (cookieless, default), GA4, or a custom
   script src. Exposes window.track(name, props) for event tracking. */
(() => {
  'use strict';
  let loaded = false;
  const consented = () => (typeof window.cookieConsent === 'function' && window.cookieConsent() === 'accepted');

  async function init() {
    if (loaded || !consented()) return;
    let cfg;
    try { cfg = await fetch('/api/config', { credentials: 'same-origin' }).then((r) => r.json()); } catch { return; }
    const a = cfg && cfg.analytics;
    if (!a || !a.provider) return; // nothing configured server-side
    loaded = true;

    if (a.provider === 'plausible' && a.domain) {
      const s = document.createElement('script');
      s.defer = true;
      s.setAttribute('data-domain', a.domain);
      s.src = a.src || 'https://plausible.io/js/script.js';
      document.head.appendChild(s);
      window.plausible = window.plausible || function () { (window.plausible.q = window.plausible.q || []).push(arguments); };
      window.track = (name, props) => window.plausible(name, props ? { props } : undefined);
    } else if (a.provider === 'ga4' && a.domain) {
      const id = a.domain; // GA4 Measurement ID, e.g. G-XXXXXXX
      const s = document.createElement('script');
      s.async = true;
      s.src = 'https://www.googletagmanager.com/gtag/js?id=' + encodeURIComponent(id);
      document.head.appendChild(s);
      window.dataLayer = window.dataLayer || [];
      window.gtag = function () { window.dataLayer.push(arguments); };
      window.gtag('js', new Date());
      window.gtag('config', id);
      window.track = (name, props) => window.gtag('event', name, props || {});
    } else if (a.src) {
      const s = document.createElement('script');
      s.async = true; s.src = a.src;
      document.head.appendChild(s);
      window.track = window.track || function () {};
    }

    // Initial page view (providers above also auto-track the first load).
    if (typeof window.track === 'function') window.track('pageview', { path: location.pathname });
  }

  window.addEventListener('cookie-consent', (e) => { if (e.detail === 'accepted') init(); });
  init(); // consent may already have been granted on a previous visit
})();
