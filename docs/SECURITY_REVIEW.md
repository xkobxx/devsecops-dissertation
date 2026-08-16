# Internal security review

## Threat model

Trust Gate operates in CI pipelines and developer workstations. The primary
threat actors are:

1. **Malicious scanner output** — crafted SARIF or JSON designed to exploit
   parsers, inject HTML, or traverse paths.
2. **Untrusted pull requests** — PRs from forks that attempt to exfiltrate
   secrets or bypass gates via workflow manipulation.
3. **Supply chain attacks** — dependency confusion, compromised scanner
   binaries, or tampered threat intelligence feeds.

### Mitigations

- All parsers treat input as untrusted. SARIF is validated against schema.
- File stores reject symlinks to prevent path traversal.
- Local deployment mode (default) makes no network calls.
- Resource limits prevent scanner processes from consuming unbounded memory/CPU.

## Cryptographic usage

- **Ed25519** for licence signature verification (offline, no MITM surface).
- **SHA-256** for finding fingerprints (deterministic, not security-critical).
- No custom cryptography. All crypto uses the `cryptography` library.

## Licence verification

- Offline Ed25519 verification. No licence server calls.
- Invalid licence degrades to community edition. Never hides findings.
- Key rotation via versioned public keys in code.

## Workflow security

- Documented in `docs/security/WORKFLOW_SECURITY.md`.
- GitHub Actions use `pull_request_target` only where necessary.
- Secrets are never logged or included in PR comments.
- SARIF upload uses GitHub's built-in token, not PATs.

## Parser trust boundaries

- All scanner output is parsed as untrusted JSON.
- SARIF validation occurs before any field extraction.
- HTML report generation escapes all user-controlled content.
- Finding descriptions are never rendered as raw HTML.

## Report rendering

- HTML reports use Jinja2 autoescaping.
- No JavaScript in reports (static HTML only).
- No external resource loading.

## External network calls

- Local mode: zero network calls (enforced by deployment config).
- Hybrid mode: only approved metadata fields, never source code.
- Full mode: all features enabled but telemetry still requires consent.

## Secret handling

- No secrets stored in code or configuration files.
- Scanner API keys passed via environment variables only.
- Redaction config strips source code from hybrid-mode uploads.

## Update mechanisms

- Package updates via pip (standard Python ecosystem).
- No auto-update mechanism. Users control update timing.
- Schema versions enable backward-compatible migrations.

## Self-hosted deployment

- Docker container runs as non-root user.
- No persistent state required (stateless scanning).
- Volume mounts for vulnerability databases (read-only).
- Network mode `none` available for air-gapped operation.
