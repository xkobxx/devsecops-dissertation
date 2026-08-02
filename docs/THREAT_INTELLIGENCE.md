# Threat-intelligence enrichment

Trust Gate enriches canonical findings from five public, authoritative sources:

- [OSV API](https://google.github.io/osv.dev/api/)
- [GitHub global security advisories REST API](https://docs.github.com/en/rest/security-advisories/global-advisories)
- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
- [FIRST EPSS API](https://www.first.org/epss/api)
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

NVD is queried only when earlier responses have not supplied both a CVSS score
and vector. The resulting finding record preserves advisory IDs, CVSS score and
vector, EPSS probability and percentile, KEV status, known-exploitation date,
ransomware association, fixed versions, published and modified dates, and the
latest source timestamp. A missing value remains `null`; a failed lookup is not
converted into a negative result.

Threat feeds are evidence, not complete risk context. Every enrichment record
therefore sets `risk_context_complete` to `false` and includes the limitation
that local reachability, deployment, and environment evidence are still needed.

## Privacy and network modes

`metadata-only` is the default because it is the least invasive mode that can
enrich findings which already contain advisory IDs.

| Mode | Network behavior | Data that may be sent |
|---|---|---|
| `disabled` | No threat-feed request is made. | Nothing. Only the local cache is read. |
| `metadata-only` | Identifier lookups only. | CVE, GHSA, or OSV advisory IDs. |
| `full` | Identifier lookups plus OSV package matching when package metadata exists. | Advisory IDs and, for OSV only, dependency ecosystem, name, version, and PURL. |

Source files, source/sink values, code excerpts, raw scanner reports, file
paths, symbols, secrets, and repository content are never put into enrichment
requests in any mode. `sources[].identifiers_sent` records the exact metadata
disclosed for each network request. Tokens are read from `GITHUB_TOKEN` and
`NVD_API_KEY`; they are used only as request credentials and are never cached.

## Local cache and expiry

The default cache is `.trustgate/cache/threat-intelligence`, configurable with
`--cache-dir` or `--threat-cache-dir`. Entries use content-addressed filenames,
versioned JSON envelopes, atomic replacement, and explicit `fetched_at` and
`expires_at` timestamps.

| Source | Default TTL |
|---|---:|
| OSV | 24 hours |
| GitHub advisories | 24 hours |
| NVD | 24 hours |
| EPSS | 24 hours |
| CISA KEV | 6 hours |

Online modes reuse fresh entries and refresh expired entries. If refresh fails,
the expired entry remains usable but is labelled `stale-cache`. Disabled mode
uses both fresh and stale cache entries without attempting network access.
Cache misses, corrupt entries, provider errors, and stale data are retained in
the finding and summarized in `scan-run.summary.threat_data`.

Policy results copy the aggregate status into
`metadata.threat_data_status`, `metadata.threat_data_stale`, and
`metadata.threat_data_failures`. Their human-readable reason also warns when
stale threat data influenced the scan context.

## CLI workflows

Enrich an existing canonical scan run using advisory identifiers only:

```bash
trustgate enrich \
  --input reports/findings.json \
  --output reports/enriched-findings.json \
  --network-mode metadata-only
```

Run with no network access:

```bash
trustgate enrich \
  --input reports/findings.json \
  --output reports/enriched-findings.json \
  --cache-dir .trustgate/cache/threat-intelligence \
  --network-mode disabled
```

Enrich during report aggregation and ensure the subsequent policy result
contains the same freshness state:

```bash
trustgate aggregate \
  --reports-dir reports \
  --output reports/findings.json \
  --enrich-threats \
  --network-mode metadata-only
```

An offline scan remains functional when individual entries are missing: the
finding, scanner health, and severity gate are still produced, while the cache
miss is visible as unavailable threat context.
