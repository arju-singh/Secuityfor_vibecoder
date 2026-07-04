// Transactional email. Provider-agnostic but ships a zero-dependency Resend
// (https://resend.com) integration over their REST API via fetch — no SDK to
// install. Activates when RESEND_API_KEY is set; otherwise it logs the message
// to the console so verification/reset flows still work end-to-end in local dev
// (you'll see the link in the server output). Swap the fetch block for SendGrid/
// SES if you prefer — keep the sendMail(...) signature.
const RESEND_API_KEY = process.env.RESEND_API_KEY;
// Resend's shared sandbox sender works without domain verification for testing;
// set EMAIL_FROM to a verified domain address before going live.
const EMAIL_FROM = process.env.EMAIL_FROM || 'SentryScan <onboarding@resend.dev>';

export function isEmailConfigured() { return !!RESEND_API_KEY; }

export async function sendMail({ to, subject, html, text }) {
  if (!RESEND_API_KEY) {
    console.log(`\n[email:dev] (RESEND_API_KEY unset — not actually sent)\n  to:      ${to}\n  subject: ${subject}\n  body:    ${text || html}\n`);
    return { dev: true };
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: EMAIL_FROM, to, subject, html, text }),
    signal: AbortSignal.timeout(15000)
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`Email send failed (${res.status}): ${detail.slice(0, 200)}`);
  }
  return res.json();
}

// Small helpers to build the two transactional emails consistently.
export function verificationEmail(link) {
  return {
    subject: 'Verify your SentryScan email',
    text: `Welcome to SentryScan. Confirm your email address:\n${link}\n\nThis link expires in 24 hours. If you didn't sign up, ignore this email.`,
    html: `<p>Welcome to <strong>SentryScan</strong>. Confirm your email address:</p><p><a href="${link}">Verify my email</a></p><p style="color:#888">This link expires in 24 hours. If you didn't sign up, ignore this email.</p>`
  };
}
export function resetEmail(link) {
  return {
    subject: 'Reset your SentryScan password',
    text: `Someone requested a password reset for your SentryScan account.\nReset it here (expires in 1 hour):\n${link}\n\nIf this wasn't you, ignore this email — your password is unchanged.`,
    html: `<p>Someone requested a password reset for your <strong>SentryScan</strong> account.</p><p><a href="${link}">Reset my password</a></p><p style="color:#888">This link expires in 1 hour. If this wasn't you, ignore this email — your password is unchanged.</p>`
  };
}
