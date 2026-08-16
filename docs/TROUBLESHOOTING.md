# Troubleshooting

Practical fixes for common TrustGate issues.

## Common Errors

| Symptom | Cause | Fix |
|---|---|---|
| `Scanner not found: <name>` | Scanner binary missing or not on `PATH` | Install the scanner and confirm with `which <name>` |
| Policy evaluation exits non-zero | Malformed or contradictory policy YAML | Validate with `trustgate policy --test` |
| `SARIF parse error` / schema mismatch | Report does not conform to SARIF 2.1.0 | Validate with `trustgate schema --validate report.sarif` |
| Aggregation returns zero findings | Wrong directory path or unsupported file format | Verify the path exists and contains `.sarif` / `.json` files |
| `PermissionError` on file store | Insufficient filesystem permissions | Check read/write access: `ls -la ~/.trustgate/` |
| `FileNotFoundError` for config | Config file path incorrect or missing | Run `trustgate init` or pass `--config path/to/config.yaml` |

## Scanner Not Found

TrustGate shells out to external scanners. Each scanner must be installed independently and available on your `PATH`.

```bash
# Confirm the scanner is reachable
which semgrep        # or trivy, bandit, etc.

# If missing, install it (example: semgrep)
pip install semgrep
```

## Policy Evaluation Failures

Dry-run your policy file before applying it to a real scan:

```bash
trustgate policy --test
```

Common mistakes: indentation errors in YAML, referencing undefined severity levels, or conflicting allow/deny rules.

## SARIF Parsing Errors

Validate a report against the SARIF 2.1.0 schema:

```bash
trustgate schema --validate report.sarif
```

If validation fails, check that the producing scanner outputs SARIF 2.1.0 (not an older draft) and that the file is valid JSON.

## Empty Aggregation Results

```bash
# Confirm the directory contains reports
ls benchmarks/corpora/*.sarif

# Run aggregation with debug logging to see which files are loaded
trustgate --log-level debug aggregate benchmarks/corpora/
```

Supported input formats: `.sarif`, `.json`. Other extensions are silently skipped.

## Permission Errors

TrustGate stores data under `~/.trustgate/` by default. Ensure the current user owns that directory:

```bash
ls -la ~/.trustgate/
# Fix ownership if needed
chmod -R u+rw ~/.trustgate/
```

## Debug Logging

Enable verbose output to diagnose any issue:

```bash
# Flag form
trustgate --log-level debug <subcommand>

# Environment variable form
TRUSTGATE_LOG_LEVEL=debug trustgate <subcommand>
```

## Getting Help

```bash
# Top-level help
trustgate --help

# Subcommand-specific help
trustgate <subcommand> --help

# Examples
trustgate policy --help
trustgate schema --help
```
