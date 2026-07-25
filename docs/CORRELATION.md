# Finding deduplication, correlation, and corroboration

TrustGate consolidates canonical findings before a scan run is validated,
published, or evaluated by policy. The process is deterministic, preserves the
original scanner evidence, and treats agreement as finding-validity evidence
rather than proof of exploitability.

## Exact same-scanner deduplication

Exact repeats are grouped by normalized scanner name and the versioned finding
fingerprint. A consolidated issue retains:

- `occurrence_count`, including counts from previously consolidated inputs;
- every distinct file, line range, and symbol in `locations`;
- every content-addressed raw report in `raw_evidence_references`;
- every original ID in `source_finding_ids`;
- the union of canonical evidence objects;
- the earliest `first_seen` and latest `last_seen` values.

The input findings are defensively copied. No parser result or raw report is
modified.

## Cross-scanner correlation

Different scanners are correlated only when a conservative set of normalized
signals establishes a shared identity:

| Finding type | Required strong identity |
|---|---|
| Code | Same file plus a weighted semantic combination of CWE, symbol, source, sink, or nearby/identical code region |
| Dependency | Same normalized ecosystem/component and the same CVE |
| Infrastructure | Same non-empty infrastructure resource identity |
| Secret | Same non-empty secret fingerprint |

File or CWE equality alone is insufficient. Code regions must overlap, share a
region hash, or be within five lines, unless other semantic anchors meet the
threshold. A candidate must match every existing member of a cluster, preventing
transitive chains from joining unrelated endpoints.

Each issue records:

- `supporting_scanners` and `contradicting_scanners`;
- `agreement_strength`;
- `correlation_reason` and the exact `correlation_signals`;
- all source locations, IDs, evidence, and raw reports.

The Bandit/Semgrep SQL-injection acceptance fixture requires the same repository
file, CWE-89, and related code region. Distant SQL-injection reports with
different symbols, sources, and sinks remain separate.

## Evidence independence and rule ancestry

Two scanner names are not automatically two independent evidence sources.
`CorrelationConfig.rule_ancestry` maps `scanner:rule_id` to a shared source:

```python
from trustgate.correlation import CorrelationConfig

config = CorrelationConfig(
    rule_ancestry={
        "bandit:B608": "shared/sql-injection-rule",
        "semgrep:python.shared.sqli": "shared/sql-injection-rule",
    }
)
```

All scanners in one ancestry group contribute one independent source. Known
shared groups are published under `corroboration.shared_rule_ancestry`. Unknown
rules default to scanner-specific ancestry, which is explicit in
`independent_sources`.

`ScannerContradiction` attaches negative evidence to a source finding ID or
fingerprint. Canonical scan-run construction accepts both configuration and
contradictions:

```python
from trustgate.correlation import ScannerContradiction
from trustgate.schema import build_scan_run

scan_run = build_scan_run(
    target=".",
    findings=findings,
    scanner_results=scanner_results,
    correlation_config=config,
    contradictions=[
        ScannerContradiction(
            scanner="review-tool",
            finding_identity=findings[0]["fingerprint"],
            reason="The observed sanitizer blocks this flow.",
        )
    ],
)
```

## Corroboration confidence

Corroboration uses the existing Beta-Binomial implementation with a uniform
prior and a configurable confidence level (95% by default). The structured
`corroboration` object includes:

- independent supporting and contradicting evidence counts;
- displayed posterior estimate and conservative lower bound;
- the complete confidence interval and methodology version;
- independent sources and shared ancestry groups;
- DAST confirmations and human confirmations as separate collections.

A `corroboration` evidence item is added only when at least two independent
sources agree. Shared ancestry cannot create the uplift. Human confirmation is
recognized from `human_confirmation` or `manual_validation` evidence. DAST is
recorded from a DAST finding or explicit `dast_confirmation` evidence and is not
silently converted into exploit validation.

Independent agreement can increase `finding_validity_confidence` when a
versioned rule-reliability baseline exists. It does not populate
`exploitability_confidence`. Exploitability remains unscored unless separate
exploit validation, known-exploited status, or exploit-precondition evidence is
present.

## API

```python
from trustgate.correlation import (
    CorrelationConfig,
    correlate_findings,
    deduplicate_findings,
)

exact = deduplicate_findings(findings)
correlated = correlate_findings(exact, config=CorrelationConfig())
```

`correlate_findings` performs exact deduplication itself, so callers normally
pass raw canonical parser results directly.
