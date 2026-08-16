# TrustGate Example Configurations

Working configuration examples for common project types and deployment scenarios.

## Language / Framework Examples

| Directory | Description |
|-----------|-------------|
| [python-flask/](python-flask/) | Flask app with Bandit, Semgrep, and pip-audit |
| [python-django/](python-django/) | Django app with Django-specific Semgrep rules |
| [nodejs/](nodejs/) | Node.js app with eslint-security and osv-scanner |
| [typescript/](typescript/) | TypeScript app with eslint-security and Semgrep |
| [java/](java/) | Java app with SpotBugs and Grype |
| [go/](go/) | Go app with gosec and osv-scanner |

## Infrastructure Examples

| Directory | Description |
|-----------|-------------|
| [docker/](docker/) | Dockerfile and container image scanning with Hadolint and Trivy |
| [terraform/](terraform/) | Terraform IaC scanning with Checkov and Trivy |
| [kubernetes/](kubernetes/) | Kubernetes manifest scanning with Checkov and Trivy |

## Advanced Examples

| Directory | Description |
|-----------|-------------|
| [monorepo/](monorepo/) | Multi-target monorepo with per-path scanner configuration |
| [authenticated-dast/](authenticated-dast/) | Authenticated DAST scanning with ZAP against an OpenAPI spec |
| [offline-mode/](offline-mode/) | Fully offline operation with cached threat feeds |
| [custom-policy/](custom-policy/) | Custom policy-as-code with inheritance and repo overrides |
| [self-hosted/](self-hosted/) | Self-hosted deployment via Docker Compose |

## Validation

All examples are validated in CI. Run the check locally:

```bash
./ci-validation.sh
```
