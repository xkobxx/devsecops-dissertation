# Test Gap Analysis

Audit date: 2026-07-24
Audited commit: `a780add`

## Executive summary

Automated test discovery currently reports:

```text
Ran 0 tests in 0.000s
NO TESTS RAN
```

All Python files byte-compile and all checked JSON files parse, but these are
syntax/data checks, not behavioural tests. The repository contains benchmark
fixtures, five committed experiment runs, scanner reports, and a deliberately
vulnerable application; none is connected to a test runner.

The highest-priority missing test is already a confirmed failure:

```text
Aggregated 0 total findings.
Security gate passed.
```

This was produced by running the aggregator against an empty reports directory.
It violates the roadmap requirement that missing required reports cannot become a
clean gate.

## Existing test-like assets

| Asset | What it provides | Why it is not an automated test |
|---|---|---|
| `test_app/app.py` | Six deliberately vulnerable Python patterns | No assertions or runner integration |
| `test_app/seeded_vulnerabilities.json` | Hand-labelled ground truth | Used for metrics, not behavioural acceptance |
| `reports/*_report.json` | Real scanner outputs | Not organized as versioned parser fixtures |
| `results/run_1` through `run_5` | Historical aggregated outputs | Byte-identical; no pass/fail assertions |
| `confidence_table.json` | Expected scoring lookup | Generated from one run; no regression test |
| `.zap/rules.tsv` | ZAP configuration | Empty and unvalidated |
| GitHub workflow | End-to-end-ish execution | No failure injection; multiple failures are ignored |

## Module coverage gaps

| Component | Required behaviours without tests | Priority |
|---|---|---|
| `aggregate_results.py` | Missing/malformed/stale reports, every parser shape, unknown severity, output paths, all thresholds, scanner failure versus findings exit | Critical |
| `action.yml` | Input validation, path traversal, command injection, scanner timeouts, report production, failure policy, output contract | Critical |
| `.github/workflows/devsecops.yml` | Least privilege, untrusted PR behaviour, artifact absence, gate enforcement, Pages separation | Critical |
| `verify_license.py` | Valid, malformed, expired, future, wrong-key and corrupt payload cases | High |
| `score_findings.py` | Licence enforcement, sample maturity, missing rule, conservative bound, non-destructive output | Critical |
| `build_confidence_table.py` | Matching correctness, ambiguous matches, sample sizes, reproducibility, schema | Critical |
| `generate_report.py` | Escaping, malformed findings, offline rendering, accurate metrics, missing input, accessibility | High |
| `calculate_metrics.py` | Missing runs, duplicate runs, matching collisions, intervals, zero denominators | Critical |
| `record_run.py` | Unknown scenario, missing/corrupt log, matching correctness, atomic writes | Medium |
| `issue_license.py` | Key permissions, deterministic format, key mismatch, invalid days, non-overwrite behaviour | High |
| `visualise_results.py` | Reads generated metrics, deterministic images, missing inputs | Medium |
| `webhook/api/stripe-webhook.js` | Signature rejection, event filtering, missing email, retry/idempotency, Resend failure, secret absence | High |

## Scanner parser fixture gaps

Each current scanner requires fixtures and assertions for:

- clean successful report;
- successful report with findings;
- scanner process crash;
- timeout;
- missing report;
- empty file;
- malformed JSON;
- valid JSON with wrong top-level type;
- valid but incompatible schema version;
- unknown severity;
- malicious strings, paths and very large fields;
- partial/truncated report;
- stale report from another commit;
- scanner version mismatch.

Bandit, Semgrep, pip-audit, Trivy, and Gitleaks need a shared adapter contract test.
ZAP needs the same coverage when it becomes part of the product flow.

## Roadmap Phase 1 acceptance tests

The following tests should be written before implementing scanner-health logic:

1. required scanner success with zero findings yields `PASSED`;
2. required scanner success with findings yields `FINDINGS_DETECTED`;
3. missing expected report yields `FAILED_SCANNER`;
4. malformed report yields `FAILED_SCANNER` or `PARTIAL`;
5. timeout yields `TIMED_OUT`;
6. non-applicable optional scanner yields `SKIPPED_NOT_APPLICABLE`;
7. cancellation yields `CANCELLED`;
8. findings-specific scanner exit codes are not treated as crashes;
9. crash-specific exit codes cannot become zero findings;
10. `scanner-failure-policy=fail` blocks by default;
11. `warn` preserves an explicitly incomplete coverage result;
12. `ignore` remains visible in structured output and logs;
13. raw reports are not overwritten by normalization;
14. `target` cannot escape the workspace through `..`, symlinks, or absolute paths;
15. malicious `target` and `fail-on` values cannot execute shell code.

## Recommended test structure

```text
tests/
├── unit/
│   ├── adapters/
│   ├── aggregation/
│   ├── findings/
│   ├── licensing/
│   ├── reporting/
│   └── scoring/
├── integration/
│   ├── adapters/
│   ├── action/
│   └── workflow/
├── fixtures/
│   ├── bandit/
│   ├── semgrep/
│   ├── pip_audit/
│   ├── trivy/
│   ├── gitleaks/
│   └── repositories/
├── security/
└── end_to_end/
```

Use `pytest` with temporary directories and subprocess boundaries for CLI and
scanner execution tests. Parser tests should never need a network or installed
scanner. Integration tests may use explicitly pinned scanner versions.

## Test-data requirements

- Copy representative committed scanner reports into named fixtures only after
  removing repository/user metadata.
- Record scanner name, exact version, report schema, generation command and
  expected health state alongside every fixture.
- Keep deliberately vulnerable benchmarks under `benchmarks/`, separate from
  production tests.
- Add clean counterparts and safe lookalikes for every vulnerable fixture.
- Do not use the five identical run files as independent confidence samples.
- Include malicious and resource-boundary fixtures without executing unsafe
  payloads.

## Release and CI gaps

There is currently no automated:

- unit, integration, security, or end-to-end test job;
- coverage measurement or threshold;
- linting, formatting, type checking, JSON Schema validation, or Action linting;
- dependency lock/hash verification;
- documentation example test;
- reproducibility check;
- benchmark consistency check;
- SARIF, SBOM, VEX, signing, or provenance verification.

The first CI test job should be read-only, run on pull requests, and have
`contents: read` only. Publishing and PR-writing jobs must remain separate.

## Initial quality gates

Phase 1 should not be considered complete until:

- all scanner execution-state transitions have unit tests;
- all five existing parsers have clean, findings, missing, malformed, crash, and
  timeout coverage;
- empty required reports fail closed;
- security input tests cover command injection, path traversal and symlinks;
- core tests run in a clean environment from outside the repository working
  directory;
- Python test coverage is measured, with a ratcheting threshold that reaches the
  roadmap's 90% target for decision and policy modules;
- the composite Action has an integration fixture proving its output and exit
  contract.

## Completion assessment

- [x] All existing test-like assets are inventoried.
- [x] Zero automated tests is verified.
- [x] Critical behavioural gaps are mapped by component.
- [x] Scanner fixture requirements are defined.
- [x] Phase 1 acceptance tests and the target test structure are defined.
