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

// Open the Stripe-hosted customer billing portal, where users self-serve
// upgrade / downgrade / cancel. Requires the Stripe customer id we persist from
// the checkout webhook.
export async function createPortalSession(customerId, returnUrl) {
  if (!stripe) { const e = new Error('Billing is not configured on this server.'); e.status = 503; throw e; }
  if (!customerId) { const e = new Error('No billing account found yet — subscribe first.'); e.status = 400; throw e; }
  return stripe.billingPortal.sessions.create({ customer: customerId, return_url: returnUrl });
}

// Verify + parse a webhook. Throws on a bad/forged signature.
export function constructEvent(rawBody, signature) {
  if (!stripe) { const e = new Error('Billing is not configured.'); e.status = 503; throw e; }
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) { const e = new Error('STRIPE_WEBHOOK_SECRET is not set.'); e.status = 503; throw e; }
  return stripe.webhooks.constructEvent(rawBody, signature, secret);
}

// Reverse the { plan -> priceId } map so a subscription's active price can be
// resolved back to the plan name. Skips unset prices so an unconfigured plan
// never matches an empty/undefined price id.
function planForPriceId(priceId) {
  if (!priceId) return null;
  for (const [plan, id] of Object.entries(PRICES)) {
    if (id && id === priceId) return plan;
  }
  return null;
}

// Pull the active price id out of a subscription object (Checkout stores it under
// items.data[]). Guards every hop so a partial object can't throw.
function activePriceId(sub) {
  const item = sub && sub.items && Array.isArray(sub.items.data) && sub.items.data[0];
  return (item && item.price && item.price.id) || null;
}

// Map a verified event to a { email, plan } change, or null if we don't act on it.
export function planChangeFromEvent(event) {
  const o = event.data && event.data.object;
  if (!o) return null;
  switch (event.type) {
    case 'checkout.session.completed':
      return { email: (o.metadata && o.metadata.email) || o.customer_email, plan: (o.metadata && o.metadata.plan) || 'pro', customerId: o.customer || null };
    // A user upgrading/downgrading in the Stripe customer portal fires an
    // `updated` event (not a fresh checkout). Resolve the new plan from the
    // subscription's active price; a canceled/unpaid subscription drops to free.
    case 'customer.subscription.updated': {
      const status = o.status;
      if (status && status !== 'active' && status !== 'trialing') {
        // past_due / unpaid / canceled / incomplete_expired → revoke the paid plan.
        return { email: o.metadata && o.metadata.email, plan: 'free', customerId: o.customer || null };
      }
      const plan = planForPriceId(activePriceId(o));
      if (!plan) return null; // unknown price — leave the plan untouched
      return { email: o.metadata && o.metadata.email, plan, customerId: o.customer || null };
    }
    case 'customer.subscription.deleted':
      return { email: o.metadata && o.metadata.email, plan: 'free', customerId: o.customer || null };
    default:
      return null;
  }
}
