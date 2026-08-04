# Policy as code

Trust Gate policies are versioned JSON or YAML documents that evaluate canonical
saved findings without modifying them. Policy files are validated against
`schemas/policy.schema.json` before evaluation; unknown keys, malformed
expressions, unsupported actions, unresolved parents, and inheritance cycles
fail closed.

## Minimal policy

```yaml
schema_version: 1.0.0
version: 1
policy_id: service-release
policy_version: 2026.08.1
default_action: investigate
policies:
  - name: block-production-known-exploitation
    description: Block a KEV finding in production.
    action: block
    when:
      all:
        - environment: production
        - kev: true
  - name: fix-reachable-high
    action: fix_before_release
    when:
      all:
        - severity: [critical, high]
        - reachability: confirmed
```

Rules are ordered and the first matching rule selects the action. If none
matches, `default_action` is used. Expressions can recursively contain `any`,
`all`, and `not`. Leaf predicates support severity, CWE, CVE, EPSS, KEV,
reachability, environment, repository, branch, asset criticality, confidence
lower bound, finding status, introduced-in-pull-request status, fix
availability, scanner health, secret validation status, and suppression expiry.

EPSS and confidence values accept a number, meaning greater than or equal to
that threshold, or a comparison such as `">=0.80"`. Repository and branch
selectors support shell-style wildcards. Missing evidence remains `null`; it
does not satisfy a positive predicate. Every evaluated leaf records the actual
value and its evidence source.

`policy_version` is the policy author's immutable release identifier. Change it
whenever behavior changes. Simulations and explanations record both the policy
ID and version so a result can be reproduced from the same policy, saved scan
run, and runtime context.

## Inheritance and overrides

A policy can reference exact parent identities and versions. Paths are resolved
relative to the child file.

```yaml
extends:
  - path: ../organisation/base.policy.yml
    policy_id: organisation-base
    policy_version: 3.2.0
```

The referenced file must declare exactly that ID and version. Floating versions
are not resolved. Cycles and missing files are errors.

Rules are evaluated in this precedence order:

1. Matching `repository_overrides`, in declaration order.
2. The policy's local `policies`.
3. `organisation_defaults.policies`.
4. Inherited policies, in `extends` order.

A higher-precedence rule with the same name replaces a lower-precedence rule.
The default-action precedence is the first matching repository override, an
explicit local default, the organisation default, the first parent default,
and finally `investigate`.

```yaml
organisation_defaults:
  default_action: monitor
  policies:
    - name: record-low
      action: monitor
      when: {severity: low}

repository_overrides:
  - repositories: ["example/payment-*", "example/identity"]
    default_action: block
    policies:
      - name: block-critical-assets
        action: block
        when: {asset_criticality: critical}
```

## Commands

Validate the full inheritance graph and select any repository override:

```bash
trustgate policy validate \
  --policy policies/service.policy.yml \
  --repository example/payment-api
```

Simulate a policy against a stored canonical scan run:

```bash
trustgate policy simulate \
  --policy policies/service.policy.yml \
  --input reports/findings.json \
  --runtime-context policy-context.json
```

Explain one result, including every tested condition, actual value, match state,
and evidence source:

```bash
trustgate policy explain \
  --policy policies/service.policy.yml \
  --input reports/findings.json \
  --runtime-context policy-context.json \
  --finding-id finding-001
```

Runtime context is optional. A shared value applies to all findings and a
finding-specific value takes precedence:

```json
{
  "shared": {"environment": "production"},
  "findings": {
    "finding-001": {"introduced_in_pull_request": true}
  }
}
```

Run policy unit tests before deployment:

```bash
trustgate policy test \
  --policy policies/service.policy.yml \
  --input tests/fixtures/saved-scan.json \
  --runtime-context tests/fixtures/policy-context.json \
  --expectations policies/service.expectations.json
```

Expectation files are deliberately small and strict:

```json
{
  "version": 1,
  "tests": [
    {
      "name": "production high blocks",
      "finding_id": "finding-001",
      "expected_outcome": "BLOCK_IMMEDIATELY",
      "expected_policy": "block-production-high"
    }
  ]
}
```

An invalid expectation is an error, a mismatch exits with status 1, and invalid
policy or input data exits with status 2. Simulation output includes a canonical
SHA-256 digest. Identical policy, finding, and context inputs produce identical
evaluation and simulation digests.

Policy evaluation is decision support, not proof that a release is secure or
that an organisation complies with any legal, regulatory, or assurance
framework. Policy quality still depends on scanner coverage, evidence quality,
runtime context, and human review.

## Standard policy packs

The package includes ten versioned starting points:

| Pack alias | Intended starting point |
|---|---|
| `startup-baseline` | Pragmatic adoption for small teams |
| `high-assurance-baseline` | Conservative high-assurance release controls |
| `financial-services` | Critical financial-service workloads |
| `healthcare` | Critical healthcare workloads |
| `public-sector-supplier` | Software supplied to public-sector customers |
| `owasp-asvs-aligned` | Selected OWASP ASVS control themes |
| `nist-ssdf-aligned` | Selected NIST SSDF practices |
| `container-security` | Exploited and reachable container risks |
| `secret-protection` | Validated and uncertain secret findings |
| `supply-chain-security` | Exploited and reachable dependency risks |

Use `pack:<alias>` anywhere the CLI accepts `--policy`:

```bash
trustgate policy validate --policy pack:startup-baseline
trustgate policy simulate \
  --policy pack:supply-chain-security \
  --input reports/findings.json
```

Every installed pack contains its own README, policy test expectations, and
runtime-context fixture under `trustgate.policy.packs`. The automated suite
validates every rule document and runs every expectation against the shared
saved scan. These are examples to review and override, not turnkey compliance
profiles. Automated evidence does not guarantee compliance with any framework,
law, regulation, or contract.
