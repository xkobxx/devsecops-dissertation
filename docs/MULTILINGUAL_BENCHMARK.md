# Multilingual benchmark corpus

Trust Gate's Phase 17.1 corpus is a versioned set of deliberately unsafe and
safe scanner inputs. It covers application source, infrastructure as code,
container definitions, and Kubernetes manifests without treating fixture
presence as scanner-performance evidence.

The canonical corpus is
`benchmarks/corpora/multilingual-v1.json`. Validate it from the repository root:

```bash
trustgate benchmark \
  --corpus-check \
  --corpus benchmarks/corpora/multilingual-v1.json
```

The command fails if a fixture is missing, changed without a new digest,
symlinked, outside `benchmarks/fixtures`, too large, non-UTF-8, unreferenced, or
part of an incomplete or inconsistent case pair.

## Coverage

The corpus contains 27 cases across 28 immutable fixture files:

| Target | Languages or formats | Framework examples |
|---|---|---|
| Application source | Python, JavaScript, TypeScript, Java, Go, Ruby, C# | Flask, Express, Fastify, Spring Web, `net/http`, Sinatra, ASP.NET Core |
| Infrastructure as code | HCL | Terraform AWS |
| Containers | Dockerfile | OCI/Docker build definition |
| Orchestration | YAML | Kubernetes Deployment |

Every deliberately vulnerable case has a distinct patched equivalent with the
same language, target, CWE, and vulnerability class. The corpus additionally
contains:

- a safe credential-shaped lookalike;
- a cross-file Flask-to-SQLite flow;
- reachable and unreachable command-injection patterns;
- sanitised or parameterised patched flows;
- production and test-only code;
- production and development dependency declarations; and
- source, Terraform, Dockerfile, and Kubernetes targets.

The current vulnerability classes cover SQL injection, command injection, path
traversal, code injection, public cloud storage, container root execution, and
privileged Kubernetes workloads.

## Case contract

Each case records a stable ID, classification, vulnerability class, CWE,
language, framework, target, complete file set, optional pair, cross-file flag,
reachability state, code scope, dependency scope, and a bounded description.
The allowed classifications are:

- `vulnerable`: a deliberately unsafe pattern;
- `patched`: the distinct secure equivalent paired with that unsafe pattern;
- `safe_lookalike`: code or metadata that resembles a security signal but is
  not the corresponding vulnerability.

Reachability is recorded separately as `reachable`, `unreachable`, `sanitised`,
or `not_applicable`. Test and development scope do not erase a security pattern;
they preserve the context needed to measure whether a scanner and policy treat
it appropriately.

## Integrity and versioning

Every fixture is bound by SHA-256. The validator recomputes all hashes and
returns a canonical digest over the validated corpus. Changes require an
intentional corpus-version update and refreshed file digests. Case pairing is
bidirectional: vulnerable and patched cases must point to one another, share
their semantic identity, and reference different fixture files.

The validator hard-codes Phase 17.1's minimum coverage rather than trusting the
manifest to define a weaker requirement. Removing a required language, target,
classification, reachability state, code scope, dependency scope, framework
breadth, or cross-file case fails validation.

## Safety and claim boundary

Do not execute, build, apply, or deploy these fixtures. They intentionally
include command injection, SQL injection, path traversal, privileged workloads,
and public infrastructure settings. Scan them only in an isolated benchmark
environment without production credentials or cloud authority.

The two-reviewer, adjudication, agreement, blind-partition, and leakage-control
workflow is implemented and documented in
[BENCHMARK_LABELLING.md](BENCHMARK_LABELLING.md), but genuine independent
reviews have not yet been supplied. The corpus also has not yet been executed
as the automated cross-scanner suite planned for Phase 17.3. Therefore:

- the classifications are corpus assertions, not independently reviewed labels;
- no new precision, recall, runtime, or scanner-comparison claim is generated;
- the historical confidence table remains based only on the small Flask fixture;
  and
- a passing corpus check proves integrity and coverage, not detection quality.
