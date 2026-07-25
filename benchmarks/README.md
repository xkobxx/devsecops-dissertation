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
