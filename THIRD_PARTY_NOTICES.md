# Third-party notices

Trust Gate uses the following third-party components. Scanner binaries
are invoked as external processes and are not bundled or redistributed.

## Python dependencies

| Package | Licence | Usage |
|---------|---------|-------|
| cryptography | Apache-2.0 / BSD-3-Clause | Ed25519 licence verification |
| pyyaml | MIT | Policy and configuration parsing |
| jsonschema | MIT | Schema validation |
| jinja2 | BSD-3-Clause | HTML report templating |

## Scanner compatibility

Trust Gate invokes the following scanners. Users must comply with each
scanner's own licence terms.

| Scanner | Licence | Category |
|---------|---------|----------|
| Bandit | Apache-2.0 | SAST (Python) |
| Semgrep | LGPL-2.1 | SAST (multi-language) |
| Trivy | Apache-2.0 | Container/SCA |
| Grype | Apache-2.0 | SCA |
| Checkov | Apache-2.0 | IaC |
| KICS | Apache-2.0 | IaC |
| Gitleaks | MIT | Secrets |
| TruffleHog | AGPL-3.0 | Secrets |
| ZAP | Apache-2.0 | DAST |
| Nuclei | MIT | DAST |
| Gosec | Apache-2.0 | SAST (Go) |
| Brakeman | MIT | SAST (Ruby) |
| SpotBugs | LGPL-2.1 | SAST (Java) |
| ESLint | MIT | SAST (JavaScript) |
| Hadolint | GPL-3.0 | Container |
| pip-audit | Apache-2.0 | SCA (Python) |
| OSV-Scanner | Apache-2.0 | SCA |
| Syft | Apache-2.0 | SBOM |
| CodeQL | Commercial | SAST (multi-language) |

## Notice

This file is maintained as part of the Trust Gate release process.
Scanner licence information is verified at each release.
