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
  const planBadge = $('nav-plan');
  const planReminder = $('plan-reminder');
  const billingOffNote = $('billing-off-note');
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
    const paid = currentUser && currentUser.plan && currentUser.plan !== 'free';
    if (billingBtn) billingBtn.hidden = !(cfg.billingEnabled && paid);
    renderPlanBadge();
    renderPlanReminder();
    applyBillingButtons();
  }
  // Small header pill: "Pro · until 7 Aug" for a paid plan, "Free" otherwise.
  function renderPlanBadge() {
    if (!planBadge) return;
    if (!currentUser) { planBadge.hidden = true; return; }
    const plan = (currentUser.plan || 'free');
    const nice = plan.charAt(0).toUpperCase() + plan.slice(1);
    let text = nice;
    if (plan !== 'free' && currentUser.planExpiresAt) {
      const d = new Date(currentUser.planExpiresAt);
      if (!isNaN(d)) text += ' · until ' + d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
    }
    planBadge.textContent = text;
    planBadge.classList.toggle('is-paid', plan !== 'free');
    planBadge.title = plan === 'free' ? 'Free plan — upgrade to unlock VAPT, GitHub scans, analytics and more.'
      : `${nice} plan${currentUser.planExpiresAt ? ' · active until ' + new Date(currentUser.planExpiresAt).toLocaleDateString() : ''}`;
    planBadge.hidden = false;
  }
  // Banner nudging a paid user to renew when their plan lapses within 7 days.
  // (One-time model: the plan ends on planExpiresAt unless they buy again.)
  function renderPlanReminder() {
    if (!planReminder) return;
    const u = currentUser;
    if (!u || !u.plan || u.plan === 'free' || !u.planExpiresAt) { planReminder.hidden = true; return; }
    const days = Math.ceil((new Date(u.planExpiresAt) - Date.now()) / 86400000);
    if (isNaN(days) || days < 0 || days > 7) { planReminder.hidden = true; return; }
    // Dismissible per-expiry, per-session (re-nudges next visit / after renewal).
    try { if (sessionStorage.getItem('ss-reminder-dismissed') === u.planExpiresAt) { planReminder.hidden = true; return; } } catch { /* noop */ }
    const nice = u.plan.charAt(0).toUpperCase() + u.plan.slice(1);
    const msg = days <= 0 ? `Your ${nice} plan expires today.` : `Your ${nice} plan expires in ${days} day${days === 1 ? '' : 's'} — renew to keep premium features.`;
    planReminder.textContent = '';
    const span = document.createElement('span'); span.textContent = '⏳ ' + msg;
    const renew = document.createElement('button'); renew.type = 'button'; renew.className = 'pr-renew'; renew.textContent = 'Renew';
    renew.addEventListener('click', () => { const el = document.getElementById('pricing'); if (el) el.scrollIntoView({ behavior: 'smooth' }); });
    const x = document.createElement('button'); x.type = 'button'; x.className = 'pr-x'; x.setAttribute('aria-label', 'Dismiss'); x.textContent = '×';
    x.addEventListener('click', () => { try { sessionStorage.setItem('ss-reminder-dismissed', u.planExpiresAt); } catch { /* noop */ } planReminder.hidden = true; });
    planReminder.append(span, renew, x);
    planReminder.hidden = false;
  }
  // Disable the pricing CTAs (they're <a>, so we gate via class + a handler guard)
  // and surface a note when the server reports billing isn't configured.
  function applyBillingButtons() {
    const off = cfg && cfg.billingEnabled === false;
    document.querySelectorAll('.price-cta[data-plan]').forEach((btn) => {
      btn.classList.toggle('is-disabled', off);
      if (off) btn.setAttribute('aria-disabled', 'true'); else btn.removeAttribute('aria-disabled');
      btn.title = off ? 'Online payments are being set up — checkout is temporarily unavailable.' : '';
    });
    if (billingOffNote) billingOffNote.hidden = !off;
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
    if (planBadge) planBadge.hidden = true;
    if (planReminder) planReminder.hidden = true;
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

  // Manage plan — jump to pricing (renew / upgrade). Razorpay is a modal flow,
  // so there's no hosted portal; the pricing section is where users re-purchase.
  if (billingBtn) billingBtn.addEventListener('click', (e) => {
    e.preventDefault();
    try { history.replaceState(null, '', '/#pricing'); } catch { /* noop */ }
    const el = document.getElementById('pricing');
    if (el) el.scrollIntoView({ behavior: 'smooth' });
  });

  // Pricing → Razorpay Checkout. Requires login. Creates an order server-side,
  // opens the hosted modal, then verifies the signed result server-side before
  // the plan is granted (the browser never self-reports success).
  document.querySelectorAll('.price-cta[data-plan]').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      if (btn.classList.contains('is-disabled') || cfg.billingEnabled === false) {
        alert('Online payments are being set up — checkout is temporarily unavailable. Please check back shortly.');
        return;
      }
      const plan = btn.dataset.plan;
      const sess = await fetch('/api/auth/session', { credentials: 'same-origin' }).then((r) => r.json()).catch(() => ({}));
      if (!sess.authenticated) { setMode('register'); openModal(); return; }
      if (typeof window.Razorpay === 'undefined') { alert('The payment library failed to load. Check your connection and try again.'); return; }
      const orig = btn.textContent;
      btn.setAttribute('disabled', 'true'); btn.textContent = 'Starting…';
      try {
        const res = await fetch('/api/billing/order', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin', body: JSON.stringify({ plan })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.orderId) { alert(data.error || 'Checkout is unavailable right now.'); return; }
        const rzp = new window.Razorpay({
          key: data.keyId,
          order_id: data.orderId,
          amount: data.amount,
          currency: data.currency,
          name: data.name || 'SentryScan',
          description: `${data.label} plan — monthly`,
          prefill: { email: data.email },
          theme: { color: '#5b8bff' },
          handler: async (resp) => {
            try {
              const v = await fetch('/api/billing/verify', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin', body: JSON.stringify({
                  razorpay_order_id: resp.razorpay_order_id,
                  razorpay_payment_id: resp.razorpay_payment_id,
                  razorpay_signature: resp.razorpay_signature,
                  plan
                })
              }).then((r) => r.json()).catch(() => ({}));
              if (v.ok) {
                const s = await fetch('/api/auth/session', { credentials: 'same-origin' }).then((r) => r.json()).catch(() => ({}));
                if (s && s.user) signedIn(s.user);
                alert(`You're on ${plan.charAt(0).toUpperCase() + plan.slice(1)} — your plan is active. Thank you!`);
              } else {
                alert(v.error || 'We could not verify the payment. If you were charged, contact support with your payment id.');
              }
            } catch { alert('Payment verification failed. If you were charged, contact support.'); }
          }
        });
        rzp.on('payment.failed', (r) => { alert('Payment failed: ' + ((r.error && r.error.description) || 'please try again.')); });
        rzp.open();
      } catch { alert('Network error starting checkout.'); }
      finally { btn.removeAttribute('disabled'); btn.textContent = orig; }
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
