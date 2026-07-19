"""
verify_license.py

Runtime tool bundled with the Action: verifies a license key offline (no
network call, no server to maintain) against the public key below, and
exits 0 only if the key is present, correctly signed, and not expired.
Missing or invalid keys are NOT treated as errors -- the caller (action.yml)
uses this exit code purely to decide whether to run the paid confidence-
scoring step; everything else keeps working either way (free tier).

The public key is safe to publish -- it can only verify signatures, not
create them. The matching private key lives only in issue_license.py's
output (license_signing_key.pem), which is gitignored and never committed.
"""

import argparse
import base64
import json
import sys
from datetime import date

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PUBLIC_KEY_B64 = 'LFw2bgxOekg9imtXy754NGh6NJQQlbAWOLujqq656wA'


def b64u_decode(s):
    padding = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def verify(license_key, public_key_b64=PUBLIC_KEY_B64):
    """Return (valid: bool, reason: str, payload: dict | None)."""
    if not license_key:
        return False, 'no license key provided', None

    try:
        payload_b64, sig_b64 = license_key.strip().split('.')
        payload_bytes = b64u_decode(payload_b64)
        signature = b64u_decode(sig_b64)
    except (ValueError, Exception):
        return False, 'malformed license key', None

    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64u_decode(public_key_b64))
        public_key.verify(signature, payload_bytes)
    except InvalidSignature:
        return False, 'invalid signature', None
    except Exception as e:
        return False, f'could not verify: {e}', None

    try:
        payload = json.loads(payload_bytes)
    except ValueError:
        return False, 'malformed payload', None

    expires = payload.get('expires')
    try:
        expired = not expires or date.fromisoformat(expires) < date.today()
    except (TypeError, ValueError):
        return False, f"malformed expiry date ({expires!r})", payload
    if expired:
        return False, f"license expired ({expires})", payload

    return True, 'valid', payload


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Verify a license key offline.')
    parser.add_argument('--license-key', default='', help='License key to verify (empty = free tier)')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    valid, reason, payload = verify(args.license_key)

    if valid:
        print(f"License valid: {payload['customer']} ({payload['plan']}, expires {payload['expires']})")
        sys.exit(0)

    if not args.license_key:
        print("No license key provided -- running free tier.")
    else:
        print(f"License key not valid ({reason}) -- falling back to free tier.")
    sys.exit(1)


if __name__ == '__main__':
    main()
