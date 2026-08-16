# TrustGate Security Model

## Local-First by Default

TrustGate runs entirely on the local machine. All scanning, policy evaluation,
and reporting happen in-process with no network calls. The CLI never phones home,
resolves remote endpoints, or transmits telemetry unless the operator explicitly
configures a deployment mode that requires it.

## No Data Exfiltration

Scan findings, SARIF reports, and policy decisions remain on the local filesystem.
Nothing leaves the machine unless the operator opts into hybrid or cloud mode and
configures a destination endpoint. There are no implicit uploads, no background
sync, and no anonymous usage reporting.

## Deployment Modes

| Mode | Default | Network | What leaves the machine |
|--------|---------|---------|------------------------------------------|
| Local | Yes | None | Nothing |
| Hybrid | No | Egress to configured dashboard | Redacted summaries (no source code, no secrets, no raw findings) |
| Cloud | No | Full | Complete findings, metadata, and policy results sent to configured endpoint |

**Local** is the default and requires zero configuration. Hybrid and cloud modes
must be explicitly enabled in the project configuration and require a valid
endpoint URL. Mode selection is logged at startup so operators can audit which
mode was active for any given run.

## Supply Chain Protection

- **SBOM generation**: Produces CycloneDX and SPDX software bills of materials
  from project dependency manifests.
- **VEX documents**: Generates Vulnerability Exploitability eXchange statements
  so downstream consumers can distinguish exploitable vulnerabilities from
  false positives.

Both outputs are written to the local filesystem and follow the same
exfiltration rules as scan findings.

## Symlink Rejection

All file-store operations reject symbolic links before reading or writing. This
prevents path-traversal attacks where a symlink could redirect output to an
arbitrary location or trick the scanner into reading files outside the project
tree. Symlink checks run before any I/O and raise a hard error on detection.

## Input Validation

- **SARIF schema validation**: Incoming SARIF files are validated against the
  OASIS SARIF 2.1.0 JSON schema before processing. Malformed or non-conformant
  files are rejected with a clear error message.
- **Policy schema validation**: Policy definitions are validated against
  TrustGate's policy JSON schema at load time. Invalid policies never reach the
  evaluation engine.

Validation failures are fatal by default. The `--warn` flag downgrades them to
warnings for development workflows, but this is not recommended for CI/CD.

## Least-Privilege Design

- The CLI requires only read access to source files and write access to its
  output directory. It never requests elevated permissions.
- Subprocess execution is limited to explicitly configured tool integrations
  (e.g., external scanners). No shell expansion is performed on user-supplied
  arguments.
- Temporary files are created in a dedicated directory with restrictive
  permissions (mode 0700) and cleaned up on exit.
- Configuration files are validated and loaded read-only; the CLI never writes
  back to its own configuration.
