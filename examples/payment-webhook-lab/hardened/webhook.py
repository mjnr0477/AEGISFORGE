"""Illustrative hardened signature comparison."""

import hmac

def verify_webhook(received_signature: str, expected_signature: str) -> bool:
    return hmac.compare_digest(received_signature, expected_signature)
