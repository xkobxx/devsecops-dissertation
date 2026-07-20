# License issuance webhook (sketch, not deployed)

Automates what `scripts/issue_license.py` does manually today: on a paid Stripe
invoice, sign a license key and email it to the customer. See
`api/stripe-webhook.js` for the implementation and inline comments.

**Not deployed yet.** This is a sketch to review before committing to the
infra/security tradeoff it requires (see the main README's licensing section).

## Setup (when ready to deploy)

1. `cd webhook && npm install`
2. Deploy to Vercel (`vercel deploy` or via the dashboard), as its own project
   -- separate from anything else, so its secrets stay scoped to just this.
3. Set these as Vercel project environment variables (Settings > Environment
   Variables), never in code or committed anywhere:
   - `STRIPE_SECRET_KEY`
   - `STRIPE_WEBHOOK_SECRET` (from step 4)
   - `LICENSE_PRIVATE_KEY_PEM` -- paste the full contents of
     `license_signing_key.pem`. This is the sensitive step: a copy of the
     private key now lives in Vercel's secret store, not just your laptop.
   - `RESEND_API_KEY`, `RESEND_FROM_ADDRESS`
4. In the Stripe dashboard: Developers > Webhooks > Add endpoint, pointing at
   `https://<your-vercel-deployment>/api/stripe-webhook`, subscribed to the
   `invoice.paid` event only. Stripe gives you the signing secret for step 3
   at this point.
5. Test with Stripe CLI's `stripe trigger invoice.paid` against the deployed
   URL before trusting it with a real customer.

## Why `invoice.paid` and not `checkout.session.completed`

Stripe fires `invoice.paid` for the first payment of a subscription *and*
every monthly renewal -- one event type covers both issuance and renewal,
so there's no separate renewal code path to keep in sync.

## Why no database

`issueLicenseKey()` derives the license's `expires` field from the invoice's
own `period_end` timestamp, not `Date.now()`. Same invoice → same payload →
same Ed25519 signature → byte-identical license key, every time. Stripe
retries webhooks that don't return 2xx quickly; because re-running this
function for the same event reproduces the exact same key, a retry just
re-sends the same email instead of risking a duplicate/conflicting key.
