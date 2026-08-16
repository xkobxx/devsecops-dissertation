# Configuration Reference

## CLI Subcommands

| Subcommand     | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| `aggregate`    | Aggregate scanner reports and evaluate the severity gate     |
| `decide`       | Evaluate findings with an explainable contextual policy      |
| `report`       | Generate a static HTML report from normalised findings       |
| `baseline`     | Create or compare a default-branch finding baseline          |
| `suppression`  | Create, lint, apply, or revalidate finding suppressions      |
| `remediate`    | List, apply, or roll back deterministic source remediations  |
| `policy`       | Validate, test, explain, or simulate policy-as-code          |
| `evidence`     | Generate or verify reproducible audit-evidence manifests     |
| `threat-intel` | Enrich a canonical scan run with cached or live threat metadata (`enrich`) |
| `schema`       | _(reserved)_ Schema validation utilities                     |

Run `trustgate <subcommand> --help` for full option details.

## Environment Variables

| Variable              | Purpose                          | Default                  |
| --------------------- | -------------------------------- | ------------------------ |
| `TRUSTGATE_CONFIG`    | Path to configuration file       | `./trustgate.yaml`       |
| `TRUSTGATE_CACHE_DIR` | Directory for cached data        | `~/.cache/trustgate`     |
| `TRUSTGATE_LOG_LEVEL` | Logging verbosity                | `WARNING`                |
| `TRUSTGATE_TARGET`    | Repository or artifact to scan   | _(required by workflow)_ |
| `TRUSTGATE_FAIL_ON`   | Minimum severity that fails gate | _(required by workflow)_ |

## Configuration File

TrustGate reads a YAML configuration file for persistent settings.

### Search Order

1. Path in `TRUSTGATE_CONFIG` (if set)
2. `./trustgate.yaml`
3. `./.trustgate.yaml`
4. `~/.config/trustgate/config.yaml`

The first file found wins; later paths are not merged.

### Example `trustgate.yaml`

```yaml
# trustgate.yaml
target: .
fail_on: high

severity_basis: cvss
scanner_failure_policy: warn

scanners:
  timeout: 300
  optional:
    - trivy
    - semgrep

policy:
  path: .trustgate/policy.rego

baseline:
  path: .trustgate/baseline.json

reporting:
  format: html
  output: reports/dashboard.html

cache:
  dir: ~/.cache/trustgate

logging:
  level: INFO
```
