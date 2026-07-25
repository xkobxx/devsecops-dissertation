"""
Trust Gate seller-side licence issuer.

Seller-side tool -- run locally, never inside the Action. Generates the
signing keypair and issues license keys for paying customers.

License keys are self-contained (no server call needed to verify them):
  <base64url(payload JSON)>.<base64url(Ed25519 signature)>
where payload is {"customer": ..., "plan": ..., "expires": "YYYY-MM-DD"}.

This is an offline design on purpose: no database, no hosted service to run
or keep up for a v1 side project. The trade-off is real -- a key can't be
revoked once issued, only left to expire -- which is fine for a flat
month-to-month plan (just don't issue keys with far-future expiry) but is
a known limitation.

Usage:
  python scripts/issue_license.py generate-keypair
  python scripts/issue_license.py issue --customer "Acme Inc" --plan pro --days 32
"""

import argparse
import base64
from datetime import date, timedelta
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

PRIVATE_KEY_PATH = Path('license_signing_key.pem')


def b64u_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def cmd_generate_keypair(args):
    private_key_path = Path(args.private_key_path)
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with private_key_path.open('wb') as f:
        f.write(pem)
    os.chmod(private_key_path, 0o600)

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_b64 = b64u_encode(public_bytes)

    print(f"Private signing key written to {private_key_path} -- keep this secret, never commit it.")
    print("Public key (paste into scripts/verify_license.py's PUBLIC_KEY_B64 constant):")
    print(f"  {public_b64}")


def cmd_issue(args):
    with Path(args.private_key_path).open('rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    expires = (date.today() + timedelta(days=args.days)).isoformat()
    payload = {'customer': args.customer, 'plan': args.plan, 'expires': expires}
    payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')

    signature = private_key.sign(payload_bytes)
    license_key = f"{b64u_encode(payload_bytes)}.{b64u_encode(signature)}"

    print(f"Issued license for {args.customer} ({args.plan}, expires {expires}):")
    print(license_key)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Seller-side license key tooling.')
    sub = parser.add_subparsers(dest='command', required=True)

    generate = sub.add_parser('generate-keypair', help='Generate the signing keypair (one-time setup).')
    generate.add_argument(
        '--private-key-path',
        default=str(PRIVATE_KEY_PATH),
        help=f'Private key output path (default: {PRIVATE_KEY_PATH})',
    )

    issue = sub.add_parser('issue', help='Issue a signed license key for a customer.')
    issue.add_argument('--customer', required=True)
    issue.add_argument('--plan', default='pro')
    issue.add_argument('--days', type=int, default=32, help='Validity period in days (default: 32, a bit over a month)')
    issue.add_argument(
        '--private-key-path',
        default=str(PRIVATE_KEY_PATH),
        help=f'Private key input path (default: {PRIVATE_KEY_PATH})',
    )

    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.command == 'generate-keypair':
        cmd_generate_keypair(args)
    elif args.command == 'issue':
        cmd_issue(args)


if __name__ == '__main__':
    main()
