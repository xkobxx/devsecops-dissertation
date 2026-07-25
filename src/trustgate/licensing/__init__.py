"""Offline Trust Gate licence verification."""

import base64
import json
from datetime import date
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PUBLIC_KEY_B64 = "LFw2bgxOekg9imtXy754NGh6NJQQlbAWOLujqq656wA"


def b64u_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def verify(
    license_key: str,
    public_key_b64: str = PUBLIC_KEY_B64,
) -> tuple[bool, str, dict[str, Any] | None]:
    """Verify a signed licence locally without contacting a remote service."""
    if not license_key:
        return False, "no license key provided", None

    try:
        payload_b64, signature_b64 = license_key.strip().split(".")
        payload_bytes = b64u_decode(payload_b64)
        signature = b64u_decode(signature_b64)
    except Exception:
        return False, "malformed license key", None

    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64u_decode(public_key_b64))
        public_key.verify(signature, payload_bytes)
    except InvalidSignature:
        return False, "invalid signature", None
    except Exception as error:
        return False, f"could not verify: {error}", None

    try:
        payload = json.loads(payload_bytes)
    except ValueError:
        return False, "malformed payload", None

    expires = payload.get("expires")
    try:
        expired = not expires or date.fromisoformat(expires) < date.today()
    except (TypeError, ValueError):
        return False, f"malformed expiry date ({expires!r})", payload
    if expired:
        return False, f"license expired ({expires})", payload

    return True, "valid", payload


__all__ = ["PUBLIC_KEY_B64", "b64u_decode", "verify"]
