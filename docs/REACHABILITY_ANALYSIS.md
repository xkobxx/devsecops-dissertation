# Reachability analysis

Trust Gate performs conservative, Python-first reachability analysis over a
canonical scan run. It combines three independent evidence layers:

1. dependency installation, import, vulnerable-symbol, scope, and deployment
   evidence;
2. static Python source-to-sink traces; and
3. optional runtime observations from DAST or controlled reproduction.

The analyzer is local-only. It reads the repository and caller-supplied JSON
files; it does not transmit source code or findings.

## Dependency reachability

Dependency findings receive a `dependency_reachability` object. Trust Gate
checks whether the package appears in a manifest, lock file, or scanner version
evidence; whether it is direct or transitive; its runtime or development scope;
whether Python code imports it; whether a configured vulnerable symbol is
called; and whether the package is listed in an explicit deployment inventory.

The status vocabulary is deliberately conservative:

| Status | Meaning |
|---|---|
| `CONFIRMED_REACHABLE` | The evidence includes an import-to-vulnerable-symbol call path and all required classification inputs. |
| `LIKELY_REACHABLE` | The package is present and imported, but a vulnerable-symbol call was not confirmed. |
| `NO_PATH_FOUND` | No static path was found in the analyzed files. This does not determine exploitability. |
| `NOT_ANALYSED` | Dependency analysis does not apply or was not run. |
| `ANALYSIS_INCOMPLETE` | One or more required inputs or parse results were unavailable. |
| `DYNAMIC_BEHAVIOUR_UNKNOWN` | Static analysis cannot resolve the relevant runtime behavior. This value is part of the public status contract; each result also exposes the uncertainty flag and limitations. |

Every analyzed dependency result includes the call-path steps actually examined,
the analyzed files, an `analysis_incomplete` flag, an explanation, and visible
limitations. “No path found” is never treated as evidence that a vulnerability
is not exploitable.

The vulnerable-symbol file maps normalized package names to symbols:

```json
{
  "urllib3": ["PoolManager.request"],
  "demo": ["danger"]
}
```

The deployment inventory is an explicit list of packages present in the shipped
artifact:

```json
{
  "packages": ["urllib3", "demo"]
}
```

An omitted symbol map or deployment inventory produces incomplete evidence; it
does not silently assume that a package or call is absent.

## Python source-to-sink analysis

The Python AST analyzer recognizes bounded sets of:

- request and process-input sources, including Flask-style request collections
  and `input()`;
- common validation, escaping, quoting, and sanitization calls;
- dangerous execution, template, deserialization, and database sinks;
- Flask- and FastAPI-style route decorators; and
- common authentication and authorization decorators.

For a supported finding, `source_to_sink_analysis` records the identified
source, sanitizers, sink, ordered evidence trace, framework route, authentication
requirement, detectable authorization checks, and path confidence. Both
intra-file and imported cross-file calls are traced. Unsupported file types are
marked `unsupported`; Python parse failures are marked `incomplete` and list the
affected files.

This is a bounded static analysis, not whole-program proof. Reflection,
metaprogramming, dynamic dispatch, generated code, native extensions, and
framework hooks can make results incomplete.

## Dynamic correlation

Runtime observations are matched conservatively: the endpoint must match a
detected source-code route, and either the tested parameter must match a static
source or the proof sink must match a static sink. A dynamic-evidence file is an
array, or an object with an `observations` array:

```json
[
  {
    "observation_id": "zap-search-1",
    "endpoint": "https://preview.example.test/search",
    "parameter": "q",
    "sink": "cursor.execute",
    "outcome": "confirmed",
    "authentication_state": "authenticated",
    "evidence": ["Database error reproduced with the controlled payload."]
  }
]
```

Supported outcomes are `confirmed`, `failed-reproduction`,
`blocked-authentication`, `inconclusive`, and `not-attempted`. Confirmation
increases priority and keeps both static and runtime evidence. Failed
reproduction is retained as an attempt, authentication blocking is distinct
from failed exploitation, and inconclusive evidence never suppresses the static
finding.

## CLI

Analyze an existing canonical scan run:

```bash
trustgate reachability \
  --input reports/findings.json \
  --output reports/reachability.json \
  --repository-root . \
  --vulnerable-symbols vulnerable-symbols.json \
  --deployment-inventory deployment.json \
  --dynamic-evidence dast-observations.json
```

Reachability can also run inside aggregation, before policy evaluation:

```bash
trustgate aggregate \
  --reports-dir reports \
  --output reports/findings.json \
  --analyse-reachability \
  --vulnerable-symbols vulnerable-symbols.json \
  --deployment-inventory deployment.json \
  --dynamic-evidence dast-observations.json
```

The scan-run summary reports analyzed dependency and source findings, found
source paths, unsupported or incomplete analyses, confirmed dependency paths,
and dynamic confirmations. The static HTML report renders dependency call-path,
source-to-sink, route, and runtime evidence for review.
