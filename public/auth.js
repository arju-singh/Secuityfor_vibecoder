/* SentryScan auth UI — talks to /api/auth/* with cookie sessions.
   The JWT lives in an httpOnly cookie, so this script never sees the token;
   it uses /api/auth/me to know whether a session is active. */
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const modal = $('auth-modal');
  if (!modal) return;

  const signinBtn = $('nav-signin');
  const account = $('nav-account');
  const emailLabel = $('nav-email');
  const logoutBtn = $('nav-logout');
  const form = $('auth-form');
  const emailInput = $('auth-email');
  const pwInput = $('auth-password');
  const submit = $('auth-submit');
  const errEl = $('auth-err');
  const titleEl = $('auth-title');
  const subEl = $('auth-sub');
  const switchEl = $('auth-switch');
  const toggleBtn = $('auth-toggle');

  let mode = 'login'; // or 'register'
  const api = (path, body) => fetch('/api/auth/' + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin', body: JSON.stringify(body)
  });

  function showError(msg) { errEl.textContent = msg; errEl.hidden = false; }
  function clearError() { errEl.hidden = true; errEl.textContent = ''; }

  function openModal() { clearError(); modal.hidden = false; document.body.style.overflow = 'hidden'; emailInput.focus(); }
  function closeModal() { modal.hidden = true; document.body.style.overflow = ''; }

  function setMode(m) {
    mode = m;
    const login = m === 'login';
    titleEl.textContent = login ? 'Sign in' : 'Create account';
    subEl.textContent = login ? 'Welcome back — sign in to your SentryScan account.' : 'Create a SentryScan account. Use a strong, unique password (8+ characters).';
    submit.textContent = login ? 'Sign in' : 'Create account';
    pwInput.autocomplete = login ? 'current-password' : 'new-password';
    switchEl.innerHTML = login
      ? 'New here? <button type="button" class="link-btn" id="auth-toggle">Create an account</button>'
      : 'Have an account? <button type="button" class="link-btn" id="auth-toggle">Sign in</button>';
    $('auth-toggle').addEventListener('click', () => setMode(login ? 'register' : 'login'));
    clearError();
  }

  function signedIn(email) {
    if (signinBtn) signinBtn.hidden = true;
    if (account) { account.hidden = false; emailLabel.textContent = email; }
  }
  function signedOut() {
    if (signinBtn) signinBtn.hidden = false;
    if (account) account.hidden = true;
  }

  // Wire up.
  if (signinBtn) signinBtn.addEventListener('click', openModal);
  modal.querySelectorAll('[data-auth-close]').forEach((el) => el.addEventListener('click', closeModal));
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !modal.hidden) closeModal(); });
  if (toggleBtn) toggleBtn.addEventListener('click', () => setMode('register'));

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearError();
    const email = emailInput.value.trim();
    const password = pwInput.value;
    if (!email || password.length < 8) { showError('Enter a valid email and a password of at least 8 characters.'); return; }
    submit.disabled = true;
    try {
      const res = await api(mode === 'login' ? 'login' : 'register', { email, password });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok) { showError(data.error || 'Something went wrong. Please try again.'); return; }
      signedIn(data.user.email);
      closeModal();
      form.reset();
    } catch {
      showError('Network error. Please try again.');
    } finally {
      submit.disabled = false;
    }
  });

  if (logoutBtn) logoutBtn.addEventListener('click', async () => {
    try { await api('logout', {}); } catch { /* ignore */ }
    signedOut();
  });

  // Restore session on load (always-200 probe, so no console noise when logged out).
  fetch('/api/auth/session', { credentials: 'same-origin' })
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => { if (d && d.authenticated) signedIn(d.user.email); })
    .catch(() => {});
})();
