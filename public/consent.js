/* GDPR cookie consent. The session cookie is essential and always set; this
   gates only optional analytics. Choice is stored in localStorage and broadcast
   via a 'cookie-consent' event so analytics.js loads only after opt-in. */
(() => {
  'use strict';
  const KEY = 'sentry_cookie_consent';
  const banner = document.getElementById('cookie-banner');
  const read = () => { try { return localStorage.getItem(KEY); } catch { return null; } };
  function set(v) {
    try { localStorage.setItem(KEY, v); } catch { /* private mode */ }
    window.dispatchEvent(new CustomEvent('cookie-consent', { detail: v }));
  }
  // Exposed so analytics.js can check the current choice.
  window.cookieConsent = read;

  if (!banner) return;
  if (!read()) banner.hidden = false; // first visit — ask
  const accept = document.getElementById('cookie-accept');
  const decline = document.getElementById('cookie-decline');
  if (accept) accept.addEventListener('click', () => { set('accepted'); banner.hidden = true; });
  if (decline) decline.addEventListener('click', () => { set('declined'); banner.hidden = true; });
})();
