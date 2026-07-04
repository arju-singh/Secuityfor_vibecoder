// Google OAuth 2.0 (authorization-code flow), dependency-free via fetch.
// Activates when GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set; otherwise the
// "Continue with Google" button is hidden and the endpoints report not-configured.
//
// Setup: create an OAuth client at https://console.cloud.google.com/apis/credentials
// (type "Web application"), add your authorized redirect URI
// (e.g. https://YOUR-DOMAIN/api/auth/google/callback and the localhost equivalent),
// then set GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET. The redirect URI is derived
// from the incoming request host, so it works in dev and prod without extra config.
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

export function isGoogleConfigured() { return !!(CLIENT_ID && CLIENT_SECRET); }

export function getAuthUrl(state, redirectUri) {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email',
    state,
    access_type: 'online',
    prompt: 'select_account'
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
}

// Exchange the auth code for tokens and return { email, verified }. The id_token
// comes straight from Google's token endpoint over TLS, so its email claim is
// trusted without re-verifying the signature locally.
export async function exchangeCode(code, redirectUri) {
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    }),
    signal: AbortSignal.timeout(15000)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.id_token) throw new Error('Google token exchange failed.');
  const part = data.id_token.split('.')[1];
  const claims = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  if (!claims.email) throw new Error('Google account did not return an email.');
  return { email: String(claims.email).toLowerCase(), verified: !!claims.email_verified };
}
