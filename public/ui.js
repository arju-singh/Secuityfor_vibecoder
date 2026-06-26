/* ============================================================================
   SentryScan — UI motion layer (presentation only).
   Independent of app.js: scroll reveals, animated counters, scroll progress,
   parallax, and pointer tilt. All effects degrade gracefully and honor
   prefers-reduced-motion.
   ========================================================================== */
(() => {
  'use strict';
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---- Mobile nav toggle -------------------------------------------------- */
  const navToggle = document.querySelector('.nav-toggle');
  if (navToggle) {
    const setOpen = (open) => {
      document.body.classList.toggle('nav-open', open);
      navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    };
    navToggle.addEventListener('click', () =>
      setOpen(!document.body.classList.contains('nav-open')));
    document.querySelectorAll('#primary-nav a').forEach((a) =>
      a.addEventListener('click', () => setOpen(false)));
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') setOpen(false);
    });
    // Reset when leaving the mobile breakpoint.
    matchMedia('(min-width: 881px)').addEventListener('change', (e) => {
      if (e.matches) setOpen(false);
    });
  }

  /* ---- Scroll progress bar ------------------------------------------------ */
  const bar = document.getElementById('scroll-bar');
  if (bar) {
    let ticking = false;
    const update = () => {
      const h = document.documentElement;
      const max = h.scrollHeight - h.clientHeight;
      const pct = max > 0 ? (h.scrollTop / max) * 100 : 0;
      bar.style.width = pct.toFixed(2) + '%';
      ticking = false;
    };
    addEventListener('scroll', () => {
      if (!ticking) { requestAnimationFrame(update); ticking = true; }
    }, { passive: true });
    update();
  }

  /* ---- Animated counters -------------------------------------------------- */
  const animateCount = (el) => {
    const target = parseFloat(el.dataset.count);
    if (Number.isNaN(target)) return;
    const prefix = el.dataset.prefix || '';
    const suffix = el.dataset.suffix || '';
    if (reduced || target === 0) { el.textContent = prefix + target + suffix; return; }
    const dur = 1100;
    let start = null;
    const tick = (t) => {
      if (start === null) start = t;
      const p = Math.min((t - start) / dur, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = prefix + Math.round(target * eased) + suffix;
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  };

  /* ---- Scroll reveal ------------------------------------------------------ */
  const revealEls = Array.from(document.querySelectorAll('.reveal'));
  // Stagger siblings within the same parent for a cascade effect.
  const seen = new Map();
  revealEls.forEach((el) => {
    const key = el.parentElement;
    const i = (seen.get(key) || 0);
    seen.set(key, i + 1);
    el.style.setProperty('--reveal-delay', (i % 6) * 70 + 'ms');
  });

  const onReveal = (el) => {
    el.classList.add('in');
    el.querySelectorAll('[data-count]').forEach(animateCount);
    if (el.matches('[data-count]')) animateCount(el);
  };

  if (reduced || !('IntersectionObserver' in window)) {
    revealEls.forEach(onReveal);
  } else {
    const io = new IntersectionObserver((entries, obs) => {
      entries.forEach((e) => {
        if (e.isIntersecting) { onReveal(e.target); obs.unobserve(e.target); }
      });
    }, { threshold: 0.16, rootMargin: '0px 0px -8% 0px' });
    revealEls.forEach((el) => io.observe(el));
  }

  if (reduced) return; // skip continuous-motion effects below

  /* ---- Pointer tilt (bold: depth pop + cursor glare) ---------------------- */
  const tiltEls = document.querySelectorAll('[data-tilt]');
  const MAX = 13;
  tiltEls.forEach((el) => {
    let raf = null, rx = 0, ry = 0, mx = 50, my = 50;
    const apply = () => {
      el.style.transform =
        `perspective(820px) rotateX(${rx.toFixed(2)}deg) rotateY(${ry.toFixed(2)}deg) translateZ(34px) scale(1.018)`;
      el.style.setProperty('--mx', mx.toFixed(1) + '%');
      el.style.setProperty('--my', my.toFixed(1) + '%');
      raf = null;
    };
    el.addEventListener('pointermove', (ev) => {
      const r = el.getBoundingClientRect();
      const px = (ev.clientX - r.left) / r.width - 0.5;
      const py = (ev.clientY - r.top) / r.height - 0.5;
      ry = px * MAX * 2;
      rx = -py * MAX * 2;
      mx = (px + 0.5) * 100;
      my = (py + 0.5) * 100;
      el.classList.add('tilting');
      if (!raf) raf = requestAnimationFrame(apply);
    });
    el.addEventListener('pointerleave', () => {
      el.classList.remove('tilting');
      el.style.transform = '';
    });
  });

  /* ---- Whole-hero mouse parallax (layers move at different depths) -------- */
  const hero = document.querySelector('.hero');
  const heroCopy = document.querySelector('.hero-copy');
  const heroVisual = document.querySelector('.hero-visual');
  if (hero && (heroCopy || heroVisual)) {
    let raf = null, mx = 0, my = 0;
    const apply = () => {
      if (heroCopy) heroCopy.style.transform =
        `translate3d(${(mx * 12).toFixed(1)}px, ${(my * 9).toFixed(1)}px, 0) rotateY(${(mx * 2.4).toFixed(2)}deg) rotateX(${(-my * 2.4).toFixed(2)}deg)`;
      if (heroVisual) heroVisual.style.transform =
        `translate3d(${(mx * 26).toFixed(1)}px, ${(my * 18).toFixed(1)}px, 0) rotateY(${(mx * 3.4).toFixed(2)}deg) rotateX(${(-my * 3.4).toFixed(2)}deg)`;
      raf = null;
    };
    hero.addEventListener('pointermove', (ev) => {
      const r = hero.getBoundingClientRect();
      mx = (ev.clientX - r.left) / r.width - 0.5;
      my = (ev.clientY - r.top) / r.height - 0.5;
      if (!raf) raf = requestAnimationFrame(apply);
    });
    hero.addEventListener('pointerleave', () => {
      if (heroCopy) heroCopy.style.transform = '';
      if (heroVisual) heroVisual.style.transform = '';
    });
  }

  /* ---- Scroll-linked 3D tilt of the feature grid ------------------------- */
  const grid = document.querySelector('.feature-grid');
  const featSection = document.getElementById('features');
  if (grid && featSection) {
    let ticking = false;
    const update = () => {
      const r = featSection.getBoundingClientRect();
      const vh = window.innerHeight || 800;
      const center = r.top + r.height / 2;
      const prog = (center - vh / 2) / vh;            // ~ -1 (below) .. 1 (above)
      const gx = Math.max(-9, Math.min(9, prog * 13)); // tilt the whole plane as it passes
      grid.style.setProperty('--grid-rx', gx.toFixed(2) + 'deg');
      ticking = false;
    };
    addEventListener('scroll', () => {
      if (!ticking) { requestAnimationFrame(update); ticking = true; }
    }, { passive: true });
    update();
  }

  /* ---- Background + orb depth parallax on scroll -------------------------- */
  const orbs = document.querySelectorAll('.hv-orb');
  const gridBg = document.querySelector('.bg-grid'); // aurora keeps its own drift animation
  let ticking = false;
  const onScroll = () => {
    const y = window.scrollY;
    orbs.forEach((o, i) => {
      const depth = (i + 1) * 0.12;
      o.style.transform = `translate3d(0, ${(-y * depth).toFixed(1)}px, 0)`;
    });
    if (gridBg) gridBg.style.transform = `translate3d(0, ${(y * 0.16).toFixed(1)}px, 0)`;
    ticking = false;
  };
  addEventListener('scroll', () => {
    if (!ticking) { requestAnimationFrame(onScroll); ticking = true; }
  }, { passive: true });
})();
