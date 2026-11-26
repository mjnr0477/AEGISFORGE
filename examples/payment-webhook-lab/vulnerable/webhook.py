"""Intentionally vulnerable example. Never use in production."""

def verify_webhook(received_signature: str, expected_signature: str) -> bool:
    # Ordinary equality can leak timing information.
    return received_signature == expected_signature
