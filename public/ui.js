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

  /* ---- Pointer tilt ------------------------------------------------------- */
  const tiltEls = document.querySelectorAll('[data-tilt]');
  const MAX = 7;
  tiltEls.forEach((el) => {
    let raf = null, rx = 0, ry = 0;
    const apply = () => {
      el.style.transform = `perspective(900px) rotateX(${rx}deg) rotateY(${ry}deg)`;
      raf = null;
    };
    el.addEventListener('pointermove', (ev) => {
      const r = el.getBoundingClientRect();
      const px = (ev.clientX - r.left) / r.width - 0.5;
      const py = (ev.clientY - r.top) / r.height - 0.5;
      ry = px * MAX * 2;
      rx = -py * MAX * 2;
      if (!raf) raf = requestAnimationFrame(apply);
    });
    el.addEventListener('pointerleave', () => {
      rx = ry = 0;
      el.style.transform = '';
    });
  });

  /* ---- Hero parallax (subtle) -------------------------------------------- */
  const orbs = document.querySelectorAll('.hv-orb');
  if (orbs.length) {
    let ticking = false;
    const move = () => {
      const y = window.scrollY;
      orbs.forEach((o, i) => {
        const depth = (i + 1) * 0.06;
        o.style.transform = `translate3d(0, ${(-y * depth).toFixed(1)}px, 0)`;
      });
      ticking = false;
    };
    addEventListener('scroll', () => {
      if (!ticking) { requestAnimationFrame(move); ticking = true; }
    }, { passive: true });
  }
})();
