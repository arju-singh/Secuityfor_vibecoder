# Deploying SentryScan

The app is container-ready (`Dockerfile`, `Procfile`) and ships a Render
blueprint (`render.yaml`). Below is the fastest path plus what any host needs.

## Recommended: Render (one-click blueprint)

1. Push is already done — the repo is at
   `github.com/arju-singh/Secuityfor_vibecoder` (`main`).
2. In Render: **New → Blueprint**, connect this repo. Render reads `render.yaml`,
   builds the `Dockerfile`, and creates the web service + a 1 GB persistent disk
   at `/app/data` (keeps accounts/scan history across redeploys).
3. When prompted, fill the secrets you want (all optional except none are
   strictly required — the app runs with just the generated `JWT_SECRET`):
   - `APP_URL` — set to your Render URL after the first deploy
     (e.g. `https://sentryscan.onrender.com`), then redeploy.
   - Stripe / Resend / Google OAuth / `SCHEDULER_TOKEN` — only if you use them.
4. Deploy. Every future `git push` to `main` auto-redeploys.

> The persistent disk requires a **paid** instance (Starter+). On the free tier,
> remove the `disk:` block from `render.yaml` — but then `data/*.json` (accounts,
> saved scans) resets on each redeploy. For production, move `src/auth/store.js`
> and the `src/projects/*` stores to a real database.

## Required environment variables (any host)

| Var | Needed? | Notes |
|-----|---------|-------|
| `JWT_SECRET` | **Yes** | Long random string. Sessions reset if it changes. |
| `NODE_ENV=production` | Yes | |
| `REQUIRE_AUTH=1` | Recommended | Require an account to scan. |
| `SENTRYSCAN_ALLOW_LOCAL=0` | Recommended | Keep SSRF protection on in prod. |
| `TRUST_PROXY=true` | If behind a proxy/LB | Correct client IPs for rate limiting. |
| `APP_URL` | If using email/OAuth | Public base URL of the deploy. |
| Stripe / Resend / Google / `SCHEDULER_TOKEN` | Optional | Enable billing, email, OAuth, cron. See `.env.example`. |

## Other hosts

- **Docker anywhere:** `docker build -t sentryscan . && docker run -p 3000:3000 --env-file .env sentryscan`
  (image is based on the Playwright base so the render/JS scanner works).
- **Railway / Fly / Heroku:** use the same `Dockerfile`; set the env vars above.
  Fly: `flyctl launch` then `fly secrets set JWT_SECRET=...`.

## Before real client traffic

- **Serve over HTTPS/TLS** (Render/Railway/Fly give you this automatically on
  their domains). The "your data is safe" copy is only true over HTTPS.
- Set a real `APP_URL` and, if using Stripe, register the webhook endpoint
  `https://YOUR-DOMAIN/api/billing/webhook` and copy its signing secret into
  `STRIPE_WEBHOOK_SECRET`.
