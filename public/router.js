/* ============================================================================
   SentryScan — client-side page router.
   Turns the top-nav items into real, shareable pages (own URL each) while
   reusing one HTML document + the shared header/footer/scripts. Each route
   shows only its own sections; everything else is hidden. The server serves
   index.html for these paths (see server.js) so deep links / refresh work.
   ========================================================================== */
(() => {
  'use strict';

  // route → the section selectors it shows (in document order). Home holds the
  // scanner app; each nav item is its own focused page.
  const ROUTES = {
    '/':             ['.hero', '#risk', '#scanner', '#results', '.trust', '.marquee-wrap', '#voices'],
    '/coverage':     ['#features'],
    '/vapt':         ['#scanner', '#results'],
    '/how-it-works': ['#steps', '#how'],
    '/why-us':       ['#compare', '.trust', '#voices', '.marquee-wrap'],
    '/pricing':      ['#pricing'],
    '/faq':          ['#faq'],
    '/methodology':  ['#methodology']
  };
  // Every routable top-level section — hidden unless the active route lists it.
  const ALL = ['.hero', '#risk', '#features', '#scanner', '#results', '#steps', '#compare', '.trust', '.marquee-wrap', '#voices', '#pricing', '#faq', '#how', '#methodology'];
  const TITLES = {
    '/': 'SentryScan — Premium Web Security Scanner',
    '/coverage': 'Coverage — SentryScan',
    '/vapt': 'VAPT — SentryScan',
    '/how-it-works': 'How it works — SentryScan',
    '/why-us': 'Why us — SentryScan',
    '/pricing': 'Pricing — SentryScan',
    '/faq': 'FAQ — SentryScan',
    '/methodology': 'VAPT methodology — SentryScan'
  };
  // In-page hash anchors (CTAs, footer, logo) → [route, optional scroll target].
  const HASH = {
    scanner: ['/', 'scanner'], top: ['/', null], how: ['/how-it-works', null],
    features: ['/coverage', null], steps: ['/how-it-works', 'steps'],
    compare: ['/why-us', null], pricing: ['/pricing', null], faq: ['/faq', null]
  };

  const norm = (p) => { p = String(p || '/').replace(/\/+$/, ''); return p === '' ? '/' : p; };
  const routeOf = (p) => (ROUTES[norm(p)] ? norm(p) : '/');

  function apply(route, scrollTarget, reveal) {
    route = routeOf(route);
    const show = new Set(ROUTES[route]);
    ALL.forEach((sel) => document.querySelectorAll(sel).forEach((el) =>
      el.classList.toggle('route-hidden', !show.has(sel))));

    // The section that leads a route drops the big inter-section top margin, so a
    // routed page doesn't open with a large empty gap under the sticky header.
    document.querySelectorAll('.route-lead').forEach((el) => el.classList.remove('route-lead'));
    const lead = document.querySelector(ROUTES[route][0]);
    if (lead) lead.classList.add('route-lead');
    // Sub-pages (everything but the home landing) get a tighter top so they don't
    // open under a tall hero-sized gap.
    document.body.classList.toggle('route-sub', route !== '/');

    // On client navigation the scroll-reveal observer (ui.js) won't re-fire for a
    // section that was hidden, so its .reveal children would stay faded. Force
    // them visible. On the very first load we skip this and let ui.js animate.
    if (reveal) {
      ROUTES[route].forEach((sel) => document.querySelectorAll(sel).forEach((sec) =>
        sec.querySelectorAll('.reveal').forEach((el) => el.classList.add('in'))));
    }

    // VAPT is a focused page: inside #scanner, hide the tab bar and pin the VAPT
    // panel. Any other route that shows #scanner restores the normal tabbed app.
    const vapt = route === '/vapt';
    document.body.classList.toggle('route-vapt', vapt);
    const vp = document.getElementById('panel-vapt');
    if (vapt) {
      document.querySelectorAll('#scanner .panel').forEach((p) => p.classList.remove('active'));
      if (vp) vp.classList.add('active');
    } else if (vp && vp.classList.contains('active')) {
      vp.classList.remove('active');
      document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
      const w = document.getElementById('panel-website'); if (w) w.classList.add('active');
      const wt = document.querySelector('.tab[data-tab="website"]'); if (wt) wt.classList.add('active');
    }

    document.querySelectorAll('#primary-nav a[data-route]').forEach((a) =>
      a.classList.toggle('nav-active', norm(a.getAttribute('href')) === route));
    if (TITLES[route]) document.title = TITLES[route];

    if (scrollTarget) {
      const t = document.getElementById(scrollTarget);
      if (t) { t.scrollIntoView({ behavior: 'smooth', block: 'start' }); return; }
    }
    window.scrollTo(0, 0);
  }

  function go(route, scrollTarget, push) {
    route = routeOf(route);
    if (push !== false) history.pushState({}, '', route);
    apply(route, scrollTarget, true);
  }

  document.addEventListener('click', (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const a = e.target.closest('a');
    if (!a || a.target === '_blank' || a.hasAttribute('download')) return;
    const href = a.getAttribute('href');
    if (!href) return;
    if (a.hasAttribute('data-route') || ROUTES[norm(href)]) { e.preventDefault(); go(href); return; }
    if (href.charAt(0) === '#') {
      const key = href.slice(1);
      if (HASH[key]) { e.preventDefault(); go(HASH[key][0], HASH[key][1]); }
    }
  });

  window.addEventListener('popstate', () => apply(routeOf(location.pathname), null, true));
  // On first load, force-reveal a deep-linked sub-page (its scroll-reveal wouldn't
  // fire since it's already in view) but let the home landing animate in.
  const initial = routeOf(location.pathname);
  apply(initial, null, initial !== '/');
})();
