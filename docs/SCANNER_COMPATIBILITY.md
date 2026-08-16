# Scanner compatibility

TrustGate ships built-in adapters for the scanners listed below. Any tool
that produces SARIF 2.1.0 output can also be imported through the generic
SARIF adapter.

## Supported scanners

| Scanner | Type | Native adapter | SARIF import |
|---------|------|:--------------:|:------------:|
| Bandit | SAST (Python) | Yes | Yes |
| Semgrep | SAST (multi-language) | Yes | Yes |
| Gosec | SAST (Go) | Yes | Yes |
| Brakeman | SAST (Ruby) | Yes | Yes |
| SpotBugs | SAST (Java) | Yes | -- |
| ESLint Security | SAST (JS/TS) | Yes | -- |
| Trivy | SCA / Container / IaC | Yes | Yes |
| Grype | SCA | Yes | Yes |
| pip-audit | SCA (Python) | Yes | -- |
| OSV-Scanner | SCA | Yes | Yes |
| Checkov | IaC | Yes | Yes |
| Hadolint | IaC (Dockerfile) | Yes | -- |
| KICS | IaC | -- | Yes |
| Gitleaks | Secrets | Yes | Yes |
| TruffleHog | Secrets | Yes | Yes |
| ZAP | DAST | Yes | -- |
| Nuclei | DAST | -- | Yes |
| CodeQL | SAST (multi-language) | -- | Yes |
| Syft | SBOM | Yes | -- |

**Native adapter** -- TrustGate parses the scanner's own JSON/XML output
directly, normalises severities, and produces canonical findings.

**SARIF import** -- TrustGate reads the scanner's SARIF 2.1.0 output via the
generic SARIF adapter (`codeql-sarif`). Any scanner not listed above can use
this path as long as it emits valid SARIF.

## Generic SARIF import

Import a SARIF report from any scanner:

```bash
# Place the SARIF file in the reports directory and aggregate
trustgate aggregate --reports-dir reports/

# Or point at a specific file via adapter options
trustgate aggregate --reports-dir reports/ \
  --scanner codeql-sarif --option sarif=path/to/report.sarif
```

The SARIF adapter accepts files ending in `.sarif` or `.sarif.json`.

## Adding a custom scanner adapter

Adapters subclass `trustgate.adapters.ScannerAdapter` and register through
the `trustgate.adapters` entry-point group. The minimum contract is:

```python
from trustgate.adapters import ScannerAdapter, AdapterMetadata

class MyAdapter(ScannerAdapter):
    def metadata(self) -> AdapterMetadata: ...
    def is_applicable(self, repository_context) -> bool: ...
    def execute(self, target, context): ...
    def parse(self, report, context): ...
```

Register the adapter in `pyproject.toml`:

```toml
[project.entry-points."trustgate.adapters"]
my-scanner = "my_package.adapter:MyAdapter"
```

See [docs/ADAPTER_SDK.md](ADAPTER_SDK.md) for the full lifecycle contract,
health validation, fingerprinting, and severity-normalisation details.
