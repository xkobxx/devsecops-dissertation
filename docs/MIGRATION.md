# Migration to Trust Gate

The product name is now **Trust Gate**. The repository slug and existing
`xkobxx/devsecops-dissertation@v1.0.0` Action reference remain available during
the migration.

## Existing GitHub Action users

No input has been removed. Existing `target`, `fail-on`, and `license-key` inputs
remain recognized, and `findings-path` remains the output name. The Action also
exposes `policy-result-path`. Set the optional `redact-sensitive-content` input
to `true` to publish sanitized scanner-report views. Original reports remain
available as a separate raw-evidence artifact. That artifact inherits the
repository's normal GitHub Actions artifact permissions and must be treated as
sensitive.

Severity gates use canonical `normalised` severity by default. Integrations that
must preserve a scanner-native policy can set `severity-basis: original`; the
selected basis is recorded in policy-result metadata.

The Python scripts invoked by `action.yml` are now thin wrappers around modules
under `src/trustgate/`. Existing script paths remain valid:

- `scripts/aggregate_results.py`
- `scripts/generate_report.py`
- `scripts/issue_license.py`
- `scripts/score_findings.py`
- `scripts/verify_license.py`

The current release remains evaluation-only while later roadmap phases are
implemented. Scanner crashes, missing reports, malformed reports, and invalid
adapter findings are now represented by fail-closed scanner-health states.

## JSON output migration

The historical `findings.json` filename is retained, but its root is now the
version `1.0.0` canonical scan-run document:

- `total` moved to `summary.total_findings`;
- `scanner_results` moved to `scanners`;
- scanner `version` is now `scanner_version`;
- findings use `scanner`, `normalised_severity`, `start_line`, and the complete
  canonical field set;
- the original `findings` array remains at the root.

The policy decision is separately available as `policy-result.json`.
Python integrations can migrate saved unversioned files with
`trustgate.schema.migrate_scan_run`. See `docs/SCHEMAS.md`.

Canonical findings with an older identity can be upgraded explicitly with
`trustgate.schema.migrate_fingerprint`. The previous value is retained as audit
evidence; see `docs/FINGERPRINTS.md`.

## CLI users

Install the package and use:

```bash
python -m pip install --editable .
trustgate --help
trustgate aggregate --help
trustgate report --help
```

`scripts/aggregate_results.py` remains a compatibility entry point, but new local
integrations should use `trustgate aggregate`.

## Research fixture path

The deliberately vulnerable Flask fixture moved from:

```text
test_app/
```

to:

```text
benchmarks/fixtures/python/flask_vulnerable/
```

Historical committed findings still contain their original `test_app/` paths and
have not been rewritten.

## Product and research documentation

- Product status and limitations: `README.md`
- Implementation status: `docs/ROADMAP_STATUS.md`
- Historical research methodology: `docs/research/README.md`
- Benchmark fixtures: `benchmarks/`

## Version transition

The installable package is currently `0.1.0`. Historical Git tags named `v1.0.0`
predate the product/research separation and do not represent production
readiness. See `docs/VERSIONING.md`.
