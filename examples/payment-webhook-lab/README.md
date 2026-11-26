# Payment webhook signature lab

This local example demonstrates why webhook signatures should be compared with a constant-time function.

- vulnerable/webhook.py uses ordinary string equality for a received and expected signature.
- hardened/webhook.py uses hmac.compare_digest.

Run from the repository root:

    python -m aegisforge scan examples/payment-webhook-lab/vulnerable
    python -m aegisforge scan examples/payment-webhook-lab/hardened --fail-on none

The vulnerable fixture is intentionally unsafe and is only an offline teaching example. Do not connect it to a real payment processor or production webhook.
