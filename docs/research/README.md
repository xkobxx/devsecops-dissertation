# Dissertation research methodology

> This document describes a historical dissertation experiment. Its fixture,
> results, and confidence table are not a current production benchmark and must
> not be presented as general scanner accuracy.

The confidence-scoring engine (the paid feature) and the dissertation's own precision/recall research share the same ground truth. This doc covers both.

## The Seeded Vulnerability Fixture

`benchmarks/fixtures/python/flask_vulnerable/app.py` has 6 deliberately seeded
vulnerabilities - a fully-enumerated ground truth used both for the dissertation's
precision/recall research and as the corpus behind the generated confidence
artifact. The versioned, machine-readable source of truth is
`benchmarks/ground_truth/flask-vulnerable-v1.json`; this document does not
duplicate its fields manually.

## Measuring Effectiveness

Five historical files record repeated executions against the same app. They are
byte-identical, so the benchmark manifest preserves all five for provenance but
marks only the first as statistically independent.

```bash
trustgate benchmark --write
trustgate benchmark --check
```

<!-- trustgate:benchmark-metrics:start -->
> Generated from the versioned benchmark manifest. Do not edit this block.

| Tool | Precision | Recall | F1 | Posterior precision | 95% credible interval | Conservative bound | Maturity | n |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| Bandit | 0.714 | 0.800 | 0.755 | 0.667 | 0.349–0.915 | 0.349 | Directional | 7 |
| Semgrep | 0.875 | 0.800 | 0.836 | 0.800 | 0.518–0.972 | 0.518 | Directional | 8 |

Methodology `1.0.0` uses a Beta(1, 1) prior. Displayed confidence is the posterior mean; decisions use the 95% lower credible bound.
4 byte-identical repeat run(s) are retained for provenance but excluded as independent statistical samples.
<!-- trustgate:benchmark-metrics:end -->

## How the confidence layer uses this

`benchmarks/reports/flask-vulnerable-v1.confidence.json` is generated from the
same canonical metrics artifact and computes a Beta-Binomial posterior per
`(tool, rule)`. Tools without relevant ground truth are excluded rather than
assigned a misleading zero precision.

**Honesty, up front:** today's corpus is one small fixture with six seeded
vulnerabilities. Per-rule sample sizes are tiny. Line proximity is supporting
evidence only; ambiguous matches are excluded until a recorded manual
adjudication resolves them.
