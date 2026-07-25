# Trust Gate benchmarks

This directory contains research datasets, ground truth, scanner configurations,
fixtures, results, reports, and manifests. It is separate from the production
Trust Gate package under `src/`.

Nothing under `benchmarks/fixtures/` is production application code. Fixtures may
be intentionally vulnerable, use unsafe dependencies, or expose insecure
behaviour for controlled scanner evaluation. Do not deploy them to a public or
production environment.

The current corpus is a single Python/Flask fixture. Its small size and repeated
historical runs are not statistically sufficient for production confidence
claims; see `docs/research/README.md` and
`docs/audits/TEST_GAP_ANALYSIS.md`.

The canonical manifest is
`benchmarks/manifests/flask-vulnerable-v1.json`. It binds dataset, ground-truth,
scanner-configuration, scanner-rule, result, commit, and calculation-method
versions by SHA-256. Run `trustgate benchmark --write` to regenerate every
consumer and `trustgate benchmark --check` before publication.

<!-- trustgate:benchmark-metrics:start -->
> Generated from the versioned benchmark manifest. Do not edit this block.

| Tool | Precision | Recall | F1 | Posterior precision | 95% credible interval | Conservative bound | Maturity | n |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| Bandit | 0.714 | 0.800 | 0.755 | 0.667 | 0.349–0.915 | 0.349 | Directional | 7 |
| Semgrep | 0.875 | 0.800 | 0.836 | 0.800 | 0.518–0.972 | 0.518 | Directional | 8 |

Methodology `1.0.0` uses a Beta(1, 1) prior. Displayed confidence is the posterior mean; decisions use the 95% lower credible bound.
4 byte-identical repeat run(s) are retained for provenance but excluded as independent statistical samples.
<!-- trustgate:benchmark-metrics:end -->
