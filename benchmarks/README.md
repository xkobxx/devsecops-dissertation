# Trust Gate benchmarks

This directory contains research datasets, ground truth, scanner configurations,
fixtures, results, reports, and manifests. It is separate from the production
Trust Gate package under `src/`.

Nothing under `benchmarks/fixtures/` is production application code. Fixtures may
be intentionally vulnerable, use unsafe dependencies, or expose insecure
behaviour for controlled scanner evaluation. Do not deploy them to a public or
production environment.

The fixture corpus now covers Python, JavaScript, TypeScript, Java, Go, Ruby,
C#, Terraform, Dockerfiles, and Kubernetes. It includes vulnerable/patched
pairs, safe lookalikes, cross-file, sanitised, reachable, unreachable,
test-only, and dependency-scope cases. The canonical contract is
`benchmarks/corpora/multilingual-v1.json`; validate it with
`trustgate benchmark --corpus-check`.

These new fixtures have not yet been independently reviewed or executed as a
cross-scanner benchmark. They do not change the published metrics below. The
published confidence evidence still comes from one Python/Flask fixture and
byte-identical historical runs, so it is not statistically sufficient for
production confidence claims. See `docs/MULTILINGUAL_BENCHMARK.md`,
`docs/research/README.md`, and `docs/audits/TEST_GAP_ANALYSIS.md`.

Two-reviewer records, disagreement adjudication, Cohen's kappa, uncertainty,
public-blind fixtures, private commitments, and rule-tuning leakage controls are
defined in `docs/BENCHMARK_LABELLING.md`. The machinery is complete, but real
review evidence is intentionally not fabricated or committed on behalf of human
reviewers.

The canonical historical metrics manifest is
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
