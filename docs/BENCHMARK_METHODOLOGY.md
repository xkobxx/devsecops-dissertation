# Benchmark methodology

Trust Gate benchmark methodology version `1.0.0` has one publication source:
`benchmarks/manifests/flask-vulnerable-v1.json`. The manifest binds every input
to a semantic version and SHA-256 digest:

- dataset and fixture version;
- ground-truth version;
- scanner configuration version;
- scanner ruleset version;
- adjudication record version;
- each result artifact, exact 40-character commit, timestamp, and scanner
  version; and
- matching and confidence calculation versions.

`trustgate benchmark --write` recalculates the metrics and confidence artifacts,
then replaces the generated Markdown block in the root README, benchmark README,
and research document. `trustgate benchmark --check` recalculates everything in
memory and fails if any artifact, hash, table, or generated consumer differs.
The release workflow runs the check before publishing.

## Repository structure

```text
benchmarks/
├── blind/           public evaluation fixtures with committed labels withheld
├── configurations/  versioned scanner commands, rules, and matching policy
├── corpora/          multilingual fixture and case contracts
├── datasets/        versioned dataset descriptors
├── fixtures/        deliberately vulnerable source and dependency fixtures
├── ground_truth/    versioned labels and manual adjudications
├── labelling/       independent-review rules and templates
├── manifests/       the complete source-of-truth publication record
├── partitions/      public, blind, private-commitment, and tuning boundaries
├── reports/         generated metrics, confidence data, and charts
└── results/         immutable recorded scanner outputs and raw evidence
```

The five historical Flask results are byte-identical. The manifest preserves
all five as provenance, but only the first is statistically independent. A
manifest that marks the same artifact hash independent twice is rejected.

## Explainable ground-truth matching

Line proximity is supporting evidence only and can never create a match.
Methodology version `1.0.0` supports:

1. explicit vulnerability ID;
2. scanner rule plus repository-relative file;
3. file, symbol, and CWE together;
4. file plus source and sink;
5. file plus normalized code-region hash; or
6. approved manual adjudication.

Every decision records its finding key, candidate IDs, selected ground-truth ID,
matched signals, and human-readable reason. Materially equivalent candidates in
dense files are marked ambiguous and excluded from every published metric until
an adjudication supplies reviewer identity, review timestamp, target label, and
reason. Rejected adjudications are retained as explainable unmatched findings.

Precision counts emitted findings whose identity is established. Recall counts
distinct expected ground-truth items detected per scanner. This counting basis
is stored in the generated artifact rather than being inferred by a report.

## Statistical method

Rule and scanner precision use a Beta-Binomial posterior:

```text
prior = Beta(1, 1)
posterior = Beta(1 + true_positives, 1 + false_positives)
displayed_estimate = posterior mean
gating_estimate = 95% lower credible bound
```

Each score carries true positives, false positives, sample size, prior,
methodology version, posterior mean, credible interval, conservative bound,
maturity, and decision tier. Small samples cannot become `High`:

| Maturity | Labelled sample size |
|---|---:|
| Experimental | `n < 5` |
| Directional | `5 <= n < 30` |
| Moderate | `30 <= n < 100` |
| Mature | `n >= 100` |
| Verified | `n >= 100` and independently reproduced |

Published tool metrics include precision, recall, F1, false positives, false
negatives, Brier score, expected calibration error, and calibration quality.
No true-negative count is invented for source scanners.

## Adding a run

A new run must be stored under `benchmarks/results/`, added to the manifest with
an exact source commit, timestamp, artifact SHA-256, scanner versions, and an
explicit independence decision. Update the dataset/configuration/rules version
whenever their content changes, refresh the corresponding manifest hash, then
run:

```bash
trustgate benchmark --write
trustgate benchmark --check
python -m unittest tests.unit.benchmarks
```

Publication must stop if any check fails.

The multilingual corpus uses the separate two-reviewer and partition workflow
described in [BENCHMARK_LABELLING.md](BENCHMARK_LABELLING.md). Its review
receipt must exist before future scanner results can be treated as labelled
evaluation evidence. Blind and private partitions are never matching or tuning
inputs.
