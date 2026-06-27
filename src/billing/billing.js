// Stripe billing (test-mode ready). Uses hosted Stripe Checkout, so card data
// never touches this server (PCI scope stays with Stripe). The webhook — verified
// by signature — is the ONLY source of truth for a paid plan; the browser is
// never trusted to report payment success.
//
// Activates only when STRIPE_SECRET_KEY is set; otherwise endpoints report
// "not configured" and nothing breaks. Use Stripe TEST keys until you go live.
import Stripe from 'stripe';

const KEY = process.env.STRIPE_SECRET_KEY;
const stripe = KEY ? new Stripe(KEY) : null;

const PRICES = { pro: process.env.STRIPE_PRICE_PRO, team: process.env.STRIPE_PRICE_TEAM };

export function isConfigured() { return !!stripe; }

export async function createCheckoutSession(email, plan, origin) {
  if (!stripe) { const e = new Error('Billing is not configured on this server.'); e.status = 503; throw e; }
  const price = PRICES[plan];
  if (!price) { const e = new Error(`Plan "${plan}" is not available for checkout.`); e.status = 400; throw e; }
  return stripe.checkout.sessions.create({
    mode: 'subscription',
    line_items: [{ price, quantity: 1 }],
    customer_email: email,
    client_reference_id: email,
    success_url: `${origin}/?billing=success`,
    cancel_url: `${origin}/?billing=cancel`,
    metadata: { email, plan }
  });
}

// Verify + parse a webhook. Throws on a bad/forged signature.
export function constructEvent(rawBody, signature) {
  if (!stripe) { const e = new Error('Billing is not configured.'); e.status = 503; throw e; }
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) { const e = new Error('STRIPE_WEBHOOK_SECRET is not set.'); e.status = 503; throw e; }
  return stripe.webhooks.constructEvent(rawBody, signature, secret);
}

// Map a verified event to a { email, plan } change, or null if we don't act on it.
export function planChangeFromEvent(event) {
  const o = event.data && event.data.object;
  if (!o) return null;
  switch (event.type) {
    case 'checkout.session.completed':
      return { email: (o.metadata && o.metadata.email) || o.customer_email, plan: (o.metadata && o.metadata.plan) || 'pro' };
    case 'customer.subscription.deleted':
      return { email: o.metadata && o.metadata.email, plan: 'free' };
    default:
      return null;
  }
}
