# Licensing architecture

## Open source components

The following Trust Gate components are open source (MIT):

- Core scanner adapters (`trustgate.adapters`)
- SARIF generation (`trustgate.sarif`)
- Severity normalisation (`trustgate.severity`)
- Fingerprinting (`trustgate.fingerprints`)
- Basic severity gate (`trustgate.aggregation`)
- Local HTML reporting (`trustgate.reporting`)
- CLI framework (`trustgate.cli`)

## Proprietary components

The following features require a valid licence:

- Standard and custom policy packs
- EPSS/KEV threat enrichment
- Cross-scanner deduplication
- Evidence-based prioritisation
- Multi-repository dashboard
- Central policy management
- External integrations
- Organisation calibration
- SSO/SCIM/RBAC

## Safety invariants

1. **Licensing failure cannot produce an incorrect clean result.** If licence
   verification fails, the gate returns a non-zero exit code with a clear
   message — it never silently passes.

2. **Users can always access their raw security findings.** Scanner output,
   SARIF files, and basic reports are never gated behind a licence.

3. **Paid feature failure cannot suppress a real vulnerability.** If an
   enrichment or prioritisation feature fails, findings are shown without
   enrichment rather than hidden.

## Licence verification

- Ed25519 signature verification (offline, no network required)
- Graceful offline validation with cached licence state
- Key rotation supported via versioned public keys
- Revocation via expiry dates (no CRL infrastructure needed)

## Subscription lifecycle

| State | Behaviour |
|-------|-----------|
| Valid | All edition features enabled |
| Expired | Degrades to community edition, findings still accessible |
| Invalid signature | Degrades to community edition with warning |
| Missing key | Community edition, no warning |

## Scanner licence compatibility

Every bundled scanner's licence is documented in `THIRD_PARTY_NOTICES.md`.
Trust Gate does not bundle scanner binaries — it invokes them as external
processes. Scanner output is processed but not redistributed.
