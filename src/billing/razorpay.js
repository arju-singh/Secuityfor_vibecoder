// Razorpay billing (live-ready). Uses Razorpay Orders + Checkout: the browser
// opens the hosted Checkout modal (card data never touches this server, so PCI
// scope stays with Razorpay), and the ONLY thing that grants a paid plan is a
// signature we verify server-side with the secret key — the browser is never
// trusted to self-report a successful payment.
//
// Activates only when RAZORPAY_KEY_ID + RAZORPAY_KEY_SECRET are set; otherwise
// every endpoint reports "not configured" and nothing breaks.
//
// Model: each purchase is a one-time Order that grants the tier for PERIOD_DAYS
// (30). This works with just the API key pair — no Subscriptions/eMandate setup
// required — and the plan auto-expires to free unless renewed. (A true
// auto-renew subscription can be layered on later via Razorpay Subscriptions.)
import crypto from 'node:crypto';

const KEY_ID = process.env.RAZORPAY_KEY_ID || '';
const KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET || '';
const API = 'https://api.razorpay.com/v1';

export const PERIOD_DAYS = Number(process.env.RAZORPAY_PERIOD_DAYS) || 30;

// The paid catalog. `amount` is in paise (Razorpay's unit): ₹599 = 59900.
export const PLANS = {
  starter:  { key: 'starter',  label: 'Starter',  amount: 59900,  inr: 599 },
  pro:      { key: 'pro',      label: 'Pro',      amount: 89900,  inr: 899 },
  business: { key: 'business', label: 'Business', amount: 199900, inr: 1999 }
};

// Capability tiers — cumulative. A gate checks planHasCap(plan, 'vapt') etc.
// Kept in ONE place so the whole freemium boundary is auditable at a glance.
const FREE_CAPS      = ['website', 'api', 'export_basic', 'history'];
const STARTER_CAPS   = [...FREE_CAPS, 'code', 'authscan', 'export_csv'];
const PRO_CAPS       = [...STARTER_CAPS, 'vapt', 'github', 'fuzz', 'analytics', 'export_integrations'];
const BUSINESS_CAPS  = [...PRO_CAPS, 'schedule'];
const CAPS = { free: FREE_CAPS, starter: STARTER_CAPS, pro: PRO_CAPS, business: BUSINESS_CAPS };
const RANK = { free: 0, starter: 1, pro: 2, business: 3 };

export function isConfigured() { return !!(KEY_ID && KEY_SECRET); }
export function publicKeyId() { return KEY_ID; }
export function isValidPlan(plan) { return Object.prototype.hasOwnProperty.call(PLANS, plan); }

// True if `plan` includes capability `cap`. Unknown plans are treated as free.
export function planHasCap(plan, cap) {
  return (CAPS[plan] || CAPS.free).includes(cap);
}
export function planRank(plan) { return RANK[plan] || 0; }

// Resolve a user's *effective* plan, downgrading to free once the paid period
// has lapsed. All gating and display should go through this, not raw user.plan.
export function effectivePlan(user) {
  if (!user || !user.plan || user.plan === 'free') return 'free';
  if (user.planExpiresAt && Date.now() > Date.parse(user.planExpiresAt)) return 'free';
  return isValidPlan(user.plan) ? user.plan : 'free';
}

// Public plan catalog for the pricing UI (no secrets).
export function catalog() {
  return Object.values(PLANS).map((p) => ({ key: p.key, label: p.label, inr: p.inr, amount: p.amount }));
}

function authHeader() {
  return 'Basic ' + Buffer.from(`${KEY_ID}:${KEY_SECRET}`).toString('base64');
}

// Create a Razorpay Order for a plan. The email+plan ride along in `notes` so the
// webhook (and our own verify step) can map the payment back to the account.
export async function createOrder(plan, email) {
  if (!isConfigured()) { const e = new Error('Billing is not configured on this server.'); e.status = 503; throw e; }
  const p = PLANS[plan];
  if (!p) { const e = new Error(`Plan "${plan}" is not available.`); e.status = 400; throw e; }
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 12000);
  let res, data;
  try {
    res = await fetch(`${API}/orders`, {
      method: 'POST',
      signal: ctrl.signal,
      headers: { Authorization: authHeader(), 'Content-Type': 'application/json' },
      body: JSON.stringify({
        amount: p.amount,
        currency: 'INR',
        receipt: `ss_${plan}_${Date.now()}`,
        notes: { email: String(email || ''), plan }
      })
    });
    data = await res.json().catch(() => ({}));
  } catch (e) {
    const err = new Error('Could not reach the payment gateway. Please try again.'); err.status = 502; throw err;
  } finally { clearTimeout(t); }
  if (!res.ok || !data.id) {
    const err = new Error(data?.error?.description || 'Could not create a payment order.'); err.status = 502; throw err;
  }
  return { orderId: data.id, amount: data.amount, currency: data.currency, plan: p.key, label: p.label, keyId: KEY_ID };
}

// Fetch an order from Razorpay — the AUTHORITATIVE source of what was purchased.
// Used at verify time so the granted plan comes from the order (server-created),
// never from the browser (which could otherwise claim a higher tier than it paid
// for — the payment signature only binds order_id|payment_id, not the plan).
export async function fetchOrder(orderId) {
  if (!isConfigured()) { const e = new Error('Billing is not configured.'); e.status = 503; throw e; }
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 12000);
  let res, data;
  try {
    res = await fetch(`${API}/orders/${encodeURIComponent(orderId)}`, {
      signal: ctrl.signal, headers: { Authorization: authHeader() }
    });
    data = await res.json().catch(() => ({}));
  } catch { const e = new Error('Could not reach the payment gateway.'); e.status = 502; throw e; }
  finally { clearTimeout(t); }
  if (!res.ok || !data.id) { const e = new Error('Order not found.'); e.status = 400; throw e; }
  return data;
}

// Resolve the plan an order was created for, validating amount + notes so a
// tampered/mismatched order can't grant a plan. Returns { plan, email } or throws.
export function planFromOrder(order) {
  const plan = order?.notes?.plan;
  if (!isValidPlan(plan)) { const e = new Error('This order is not tied to a known plan.'); e.status = 400; throw e; }
  if (order.amount !== PLANS[plan].amount) { const e = new Error('Order amount does not match the plan.'); e.status = 400; throw e; }
  return { plan, email: order?.notes?.email || null };
}

// Verify the Checkout callback signature: HMAC_SHA256(order_id|payment_id, key_secret).
// Only Razorpay + this server know key_secret, so a browser can't forge it.
export function verifyPaymentSignature(orderId, paymentId, signature) {
  if (!KEY_SECRET || !orderId || !paymentId || !signature) return false;
  const expected = crypto.createHmac('sha256', KEY_SECRET).update(`${orderId}|${paymentId}`).digest('hex');
  return timingSafeEqualHex(expected, signature);
}

// Verify a Razorpay webhook: HMAC_SHA256(rawBody, webhook_secret) == X-Razorpay-Signature.
export function verifyWebhookSignature(rawBody, signature) {
  if (!WEBHOOK_SECRET || !rawBody || !signature) return false;
  const expected = crypto.createHmac('sha256', WEBHOOK_SECRET).update(rawBody).digest('hex');
  return timingSafeEqualHex(expected, signature);
}
export function isWebhookConfigured() { return !!WEBHOOK_SECRET; }

// Map a verified webhook event to a { email, plan } grant, or null. We act on a
// captured payment and read the plan/email we stamped into the order notes.
export function planGrantFromEvent(event) {
  if (!event || typeof event !== 'object') return null;
  if (event.event === 'payment.captured' || event.event === 'order.paid') {
    const payment = event.payload?.payment?.entity;
    const order = event.payload?.order?.entity;
    const notes = payment?.notes || order?.notes || {};
    const plan = notes.plan;
    const email = notes.email;
    if (email && isValidPlan(plan)) return { email, plan };
  }
  return null;
}

// The ISO timestamp a freshly-purchased plan should expire at.
export function expiryFromNow() {
  return new Date(Date.now() + PERIOD_DAYS * 24 * 60 * 60 * 1000).toISOString();
}

function timingSafeEqualHex(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}
