# Release notes

## v1.0.0 (unreleased)

### Features

- **Local-first security gate** — all scanning and policy evaluation runs
  locally with zero network calls in default mode.
- **Multi-scanner support** — 19 scanner adapters (SAST, SCA, container,
  IaC, secrets, DAST, SBOM) with generic SARIF import.
- **Evidence-based prioritisation** — Bayesian confidence scoring with
  EPSS, KEV, and reachability enrichment.
- **Policy-as-code** — YAML policies with severity gates, scanner
  requirements, baseline comparison, and custom rules.
- **Finding lifecycle** — suppressions with expiry and revalidation,
  baseline-aware gating, cross-scanner deduplication.
- **Deterministic remediation** — source-level fixes with rollback and
  verification.
- **Compliance mappings** — evidence reports for OWASP Top 10, ASVS,
  SAMM, NIST SSDF, CWE, PCI DSS, ISO 27001, SOC 2, Cyber Essentials.
- **Management plane** — multi-repository dashboard, organisation risk
  overview, MTTR tracking, scanner health monitoring.
- **Integrations** — Linear, Jira, Slack, Microsoft Teams, email,
  webhooks, SIEM export with ticket synchronisation.
- **Benchmark framework** — versioned benchmarks with regression
  detection and blind evaluation support.

### Known limitations

- Phase 17.2 (independent benchmark reviews) requires human reviewers.
- Phase 26.2 (external security audit) requires independent reviewers.
- DAST support is scope-bounded and requires explicit opt-in.
- Offline threat intelligence requires manual feed import.
