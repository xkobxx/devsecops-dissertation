// api/stripe-webhook.js
//
// Vercel serverless function: on a paid Stripe invoice (first payment AND
// every monthly renewal both fire `invoice.paid`), signs a license key with
// the same Ed25519 scheme as scripts/issue_license.py and emails it to the
// customer. No database -- see issueLicenseKey() for why this is safely
// idempotent against Stripe's automatic webhook retries.
//
// Required environment variables (set as Vercel project secrets -- never
// commit these):
//   STRIPE_SECRET_KEY        Stripe API key
//   STRIPE_WEBHOOK_SECRET    from the webhook endpoint's settings in the
//                            Stripe dashboard (Developers > Webhooks)
//   LICENSE_PRIVATE_KEY_PEM  the *contents* of license_signing_key.pem --
//                            this is the one piece of the current design
//                            that has to leave your laptop to automate
//                            issuance. Treat it as seriously as the file
//                            itself: if this secret leaks, rotate the
//                            keypair and re-issue every outstanding license.
//   RESEND_API_KEY           resend.com API key for sending the email
//   RESEND_FROM_ADDRESS      e.g. "DevSecOps Trust Gate <billing@yourdomain.com>"

import Stripe from 'stripe';
import crypto from 'node:crypto';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Stripe's signature check needs the exact raw request bytes -- Vercel's
// default JSON body parser would re-serialize the body first and break it.
export const config = { api: { bodyParser: false } };

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// Mirrors issue_license.py's json.dumps(payload, separators=(',', ':'),
// sort_keys=True) exactly -- the signature only verifies if both sides
// serialize the payload identically, byte for byte.
function canonicalJSON(obj) {
  const sorted = Object.keys(obj).sort().reduce((acc, k) => {
    acc[k] = obj[k];
    return acc;
  }, {});
  return JSON.stringify(sorted);
}

export function issueLicenseKey({ customer, plan, expiresISO }) {
  const payload = { customer, plan, expires: expiresISO };
  const payloadBytes = Buffer.from(canonicalJSON(payload), 'utf8');

  const privateKey = crypto.createPrivateKey(process.env.LICENSE_PRIVATE_KEY_PEM);
  const signature = crypto.sign(null, payloadBytes, privateKey); // Ed25519 needs no hash algorithm arg

  return `${payloadBytes.toString('base64url')}.${signature.toString('base64url')}`;
}

async function sendLicenseEmail(toEmail, licenseKey, expiresISO) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: process.env.RESEND_FROM_ADDRESS,
      to: toEmail,
      subject: 'Your DevSecOps Trust Gate license key',
      text: `Thanks for subscribing -- renews ${expiresISO}.\n\n` +
        `Add this as a repo secret (e.g. TRUST_GATE_LICENSE) and reference it in your workflow:\n\n  license-key: \${{ secrets.TRUST_GATE_LICENSE }}\n\n` +
        `Your key:\n${licenseKey}\n\nQuestions? Just reply to this email.`,
    }),
  });
  if (!res.ok) throw new Error(`Resend API error: ${res.status} ${await res.text()}`);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const rawBody = await readRawBody(req);

  let event;
  try {
    // This is the one thing standing between "real Stripe payment" and
    // "anyone on the internet POSTs a fake success event and gets a free
    // license" -- constructEvent rejects anything not signed with your
    // webhook secret.
    event = stripe.webhooks.constructEvent(rawBody, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type !== 'invoice.paid') {
    return res.status(200).json({ received: true, skipped: event.type });
  }

  const invoice = event.data.object;
  const email = invoice.customer_email;
  const name = invoice.customer_name || email;

  if (!email) {
    console.error('No customer email on invoice', invoice.id);
    return res.status(200).json({ received: true, error: 'no email on invoice' });
  }

  // +3 days of grace past the actual billing period end, so a slightly
  // delayed renewal payment or webhook retry doesn't lock a paying
  // customer out right at the boundary.
  const expiresISO = new Date((invoice.period_end + 3 * 86400) * 1000).toISOString().slice(0, 10);

  // Deterministic: period_end comes from Stripe's own invoice, not
  // Date.now(). If this event gets redelivered (Stripe retries on
  // timeout/non-2xx), the payload -- and therefore the signature and the
  // whole license key string -- comes out byte-for-byte identical every
  // time. That's what makes this safe without a database: "issuing twice"
  // just re-signs and re-sends the *same* key, which is a harmless no-op.
  const licenseKey = issueLicenseKey({ customer: name, plan: 'pro', expiresISO });

  try {
    await sendLicenseEmail(email, licenseKey, expiresISO);
  } catch (err) {
    // Non-2xx tells Stripe to retry -- safe to retry thanks to the
    // determinism above.
    console.error('Failed to send license email:', err);
    return res.status(500).json({ error: 'email send failed' });
  }

  return res.status(200).json({ received: true, issued_to: email, expires: expiresISO });
}
