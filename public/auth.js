/* SentryScan auth UI — talks to /api/auth/* with cookie sessions.
   The JWT lives in an httpOnly cookie, so this script never sees the token;
   it uses /api/auth/session to know whether a session is active. Also wires
   forgot-password, Google sign-in, and the Stripe billing portal, gated on
   what /api/config reports as configured on this server. */
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const modal = $('auth-modal');
  if (!modal) return;

  const signinBtn = $('nav-signin');
  const account = $('nav-account');
  const emailLabel = $('nav-email');
  const logoutBtn = $('nav-logout');
  const billingBtn = $('nav-billing');
  const form = $('auth-form');
  const emailInput = $('auth-email');
  const pwInput = $('auth-password');
  const submit = $('auth-submit');
  const errEl = $('auth-err');
  const noteEl = $('auth-note');
  const titleEl = $('auth-title');
  const subEl = $('auth-sub');
  const switchEl = $('auth-switch');
  const toggleBtn = $('auth-toggle');
  const forgotBtn = $('auth-forgot');
  const forgotRow = document.querySelector('.auth-forgot-row');
  const googleBtn = $('auth-google');
  const orDiv = $('auth-or');

  let mode = 'login'; // or 'register'
  let cfg = {};
  const api = (path, body) => fetch('/api/auth/' + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin', body: JSON.stringify(body)
  });

  function showError(msg) { clearNote(); errEl.textContent = msg; errEl.hidden = false; }
  function clearError() { errEl.hidden = true; errEl.textContent = ''; }
  function showNote(msg) { clearError(); if (!noteEl) return; noteEl.textContent = msg; noteEl.hidden = false; }
  function clearNote() { if (noteEl) { noteEl.hidden = true; noteEl.textContent = ''; } }

  function openModal() { clearError(); clearNote(); modal.hidden = false; document.body.style.overflow = 'hidden'; emailInput.focus(); }
  function closeModal() { modal.hidden = true; document.body.style.overflow = ''; }

  function setMode(m) {
    mode = m;
    const login = m === 'login';
    titleEl.textContent = login ? 'Sign in' : 'Create account';
    subEl.textContent = login ? 'Welcome back — sign in to your SentryScan account.' : 'Create a SentryScan account. Use a strong, unique password (8+ characters).';
    submit.textContent = login ? 'Sign in' : 'Create account';
    pwInput.autocomplete = login ? 'current-password' : 'new-password';
    if (forgotRow) forgotRow.hidden = !login; // forgot-password only in login mode
    switchEl.innerHTML = login
      ? 'New here? <button type="button" class="link-btn" id="auth-toggle">Create an account</button>'
      : 'Have an account? <button type="button" class="link-btn" id="auth-toggle">Sign in</button>';
    $('auth-toggle').addEventListener('click', () => setMode(login ? 'register' : 'login'));
    clearError(); clearNote();
  }

  let currentUser = null;
  // Billing visibility depends on BOTH the user's plan and the server config,
  // which load independently — recompute it whenever either becomes available.
  function applyBilling() {
    if (billingBtn) billingBtn.hidden = !(cfg.billingEnabled && currentUser && currentUser.plan && currentUser.plan !== 'free');
  }
  function signedIn(user) {
    currentUser = user;
    if (signinBtn) signinBtn.hidden = true;
    if (account) { account.hidden = false; emailLabel.textContent = user.email; }
    applyBilling();
    publishAuth(user);
  }
  function signedOut() {
    currentUser = null;
    if (signinBtn) signinBtn.hidden = false;
    if (account) account.hidden = true;
    if (billingBtn) billingBtn.hidden = true;
    publishAuth(null);
  }

  // Publish auth state for the rest of the app (app.js gates scanning on it and
  // loads the dashboard). A body data-attr + a custom event + a small global.
  function publishAuth(user) {
    document.body.dataset.authed = user ? 'true' : 'false';
    window.SentryAuth = { authed: !!user, user: user || null, open: openModal };
    document.dispatchEvent(new CustomEvent('sentry-auth', { detail: { authed: !!user, user: user || null } }));
  }
  // Default state until the session probe resolves.
  window.SentryAuth = { authed: false, user: null, open: openModal };
  document.body.dataset.authed = 'false';

  // Wire up.
  if (signinBtn) signinBtn.addEventListener('click', openModal);
  modal.querySelectorAll('[data-auth-close]').forEach((el) => el.addEventListener('click', closeModal));
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !modal.hidden) closeModal(); });
  if (toggleBtn) toggleBtn.addEventListener('click', () => setMode('register'));

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearError(); clearNote();
    const email = emailInput.value.trim();
    const password = pwInput.value;
    if (!email || password.length < 8) { showError('Enter a valid email and a password of at least 8 characters.'); return; }
    submit.disabled = true;
    try {
      const res = await api(mode === 'login' ? 'login' : 'register', { email, password });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok) { showError(data.error || 'Something went wrong. Please try again.'); return; }
      signedIn(data.user);
      if (mode === 'register' && data.user && data.user.emailVerified === false) {
        showNote(data.emailSent ? 'Account created — check your email to verify your address.' : 'Account created. (Email verification is not configured on this server.)');
        form.reset();
      } else {
        closeModal();
        form.reset();
      }
    } catch {
      showError('Network error. Please try again.');
    } finally {
      submit.disabled = false;
    }
  });

  // Forgot password — always reports success (no account enumeration).
  if (forgotBtn) forgotBtn.addEventListener('click', async () => {
    const email = emailInput.value.trim();
    if (!email) { showError('Enter your email above first, then click “Forgot password?”.'); return; }
    forgotBtn.disabled = true;
    try {
      await api('forgot', { email });
      showNote('If an account exists for that email, a password-reset link is on its way.');
    } catch {
      showError('Network error. Please try again.');
    } finally {
      forgotBtn.disabled = false;
    }
  });

  // Google sign-in — full-page redirect to the OAuth start endpoint.
  if (googleBtn) googleBtn.addEventListener('click', () => { window.location.href = '/api/auth/google'; });

  if (logoutBtn) logoutBtn.addEventListener('click', async () => {
    try { await api('logout', {}); } catch { /* ignore */ }
    signedOut();
  });

  // Manage subscription — open the Stripe customer portal.
  if (billingBtn) billingBtn.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/billing/portal', { method: 'POST', credentials: 'same-origin' });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.url) { window.location.href = data.url; return; }
      alert(data.error || 'Could not open the billing portal.');
    } catch { alert('Network error opening the billing portal.'); }
  });

  // Pricing → Stripe Checkout. Requires login; redirects to Stripe's hosted page.
  document.querySelectorAll('.price-cta[data-plan]').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      const plan = btn.dataset.plan;
      const sess = await fetch('/api/auth/session', { credentials: 'same-origin' }).then((r) => r.json()).catch(() => ({}));
      if (!sess.authenticated) { setMode('register'); openModal(); return; }
      try {
        const res = await fetch('/api/billing/checkout', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin', body: JSON.stringify({ plan })
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok && data.url) { window.location.href = data.url; return; }
        alert(data.error || 'Checkout is unavailable right now.');
      } catch { alert('Network error starting checkout.'); }
    });
  });

  // Surface OAuth / verification / billing redirect results, then clean the URL.
  function handleRedirectFlags() {
    const p = new URLSearchParams(location.search);
    const messages = {
      'verify=success': 'Email verified — thanks!',
      'verify=invalid': 'That verification link is invalid or has expired.',
      'login=success': 'Signed in with Google.',
      'login=google_error': 'Google sign-in failed. Please try again.',
      'login=google_unavailable': 'Google sign-in is not configured on this server.',
      'billing=success': 'Subscription active — thank you!',
      'billing=cancel': 'Checkout canceled.'
    };
    for (const [k, msg] of Object.entries(messages)) {
      const [key, val] = k.split('=');
      if (p.get(key) === val) {
        // Lightweight, dependency-free notice.
        try { console.info('[SentryScan] ' + msg); } catch { /* noop */ }
        if (key === 'verify' || key === 'login') { openModal(); showNote(msg); }
        break;
      }
    }
    if ([...p.keys()].some((k) => ['verify', 'login', 'billing'].includes(k))) {
      const url = location.pathname + location.hash;
      try { history.replaceState(null, '', url); } catch { /* noop */ }
    }
  }

  // Load server feature flags and restore the session IN PARALLEL — the session
  // probe must not wait on (or be blocked by) a slow /api/config, or a returning
  // signed-in user gets treated as anonymous during the probe window.
  fetch('/api/config', { credentials: 'same-origin' })
    .then((r) => (r.ok ? r.json() : null))
    .then((c) => {
      cfg = c || {};
      if (cfg.googleEnabled && googleBtn) { googleBtn.hidden = false; if (orDiv) orDiv.hidden = false; }
      applyBilling(); // config may arrive after the session — re-evaluate the button
    })
    .catch(() => {});

  fetch('/api/auth/session', { credentials: 'same-origin' })
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => { if (d && d.authenticated) signedIn(d.user); else signedOut(); })
    .catch(() => signedOut())
    .finally(handleRedirectFlags);
})();
