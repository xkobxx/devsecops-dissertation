# DAST safety

Trust Gate packages OWASP ZAP behind a fail-closed configuration and execution
boundary. DAST is disabled by default. Enabling it always requires an explicit
target, a non-global hostname allowlist, finite resource limits, and any
acknowledgements required by the selected target and scan mode.

Only scan systems you own or are authorized to test. Safe mode avoids active
attack jobs, but crawling and passive analysis still send requests and can
change application state when an endpoint has unsafe behavior.

## Modes

`dast-mode` controls discovery:

- `baseline` runs a bounded traditional spider followed by passive scanning.
- `api` imports a workspace-contained OpenAPI document followed by passive
  scanning.

`dast-scan-mode` controls attack behavior:

- `safe` is the default and never adds an active-scan job.
- `active` adds ZAP active scanning and is rejected unless
  `dast-active-scan-acknowledged: true` is supplied.

Authentication is orthogonal to discovery mode. `bearer`, `basic`, and custom
`header` authentication use ZAP header-based session management. The plan
contains only a reference to `TRUSTGATE_DAST_AUTH_SECRET`; the value is never
written to the plan or GitHub step outputs. Basic authentication expects the
secret input to contain the Base64-encoded `username:password` value.

## Target controls

Every target must match one of the comma-separated `dast-scope-hosts` entries.
Entries are exact hosts such as `preview.example.test`, or bounded wildcard
domains such as `*.preview.example.test`. A global `*`, URLs, paths, ports, and
partial wildcard expressions are rejected.

The generated HTTPSender gate checks every outbound request again and aborts an
attempt to contact a non-allowlisted host. This prevents a discovered link or
OpenAPI reference from silently widening scan scope.

Public targets require `dast-public-target-acknowledged: true`. Private or local
targets are rejected unless `dast-allow-private-target: true` is explicit.
Targets declared as `production` require a separate
`dast-production-scan-acknowledged: true`; production-like hostnames cannot be
mislabelled as preview or staging.

Preview environments are the default target class. A deployment job can pass
its preview URL directly, but the resulting hostname still has to be in the
explicit allowlist.

## Resource limits

The following bounds are mandatory and validated before ZAP starts:

| Control | Default | Accepted range | Enforcement |
|---|---:|---:|---|
| Requests per second | 5 | 1-100 | HTTPSender delay plus single-threaded spider/active-scan settings |
| Total requests | 500 | 1-100,000 | HTTPSender request counter aborts further requests |
| Maximum duration | 300 seconds | 1-3,600 | ZAP job durations plus Trust Gate subprocess timeout |

The sender gate, allowlist, authentication reference, and limits are embedded in
the generated Automation Framework plan so the configuration is inspectable and
reproducible.

## Composite Action

An opt-in preview baseline scan looks like:

```yaml
- uses: xkobxx/devsecops-dissertation@v1.0.0
  with:
    target: .
    dast-enabled: true
    dast-target-url: ${{ steps.deploy.outputs.preview-url }}
    dast-mode: baseline
    dast-scan-mode: safe
    dast-environment: preview
    dast-scope-hosts: pr-123.preview.example.test
    dast-rate-limit: 5
    dast-request-limit: 500
    dast-max-duration-seconds: 300
    dast-public-target-acknowledged: true
```

For API discovery, set `dast-mode: api` and provide a workspace-relative
`dast-openapi-path`. For authenticated scanning, set `dast-auth-type` and pass
`dast-auth-secret` from an approved GitHub secret. Do not expose target
credentials to workflows that execute untrusted pull-request code.

The Action runs the ZAP stable image by immutable multi-platform digest:

```text
ghcr.io/zaproxy/zaproxy@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2
```

When DAST is enabled, ZAP is required by the aggregate gate unless the caller
explicitly includes `zap` in `optional-scanners`.

## CLI

Generate and inspect a safe plan without executing it:

```bash
trustgate dast \
  --target-url https://pr-123.preview.example.test \
  --environment preview \
  --scope-host pr-123.preview.example.test \
  --public-target-acknowledged \
  --plan-output reports/dast-plan.yaml
```

Execution is a separate opt-in:

```bash
trustgate dast \
  --target-url https://pr-123.preview.example.test \
  --environment preview \
  --scope-host pr-123.preview.example.test \
  --public-target-acknowledged \
  --container-image ghcr.io/zaproxy/zaproxy@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2 \
  --execute
```

The container image must use a SHA-256 digest. Container plans and reports must
remain inside the mounted workspace. Authentication values are redacted from
captured stdout and stderr, the generated report uses ZAP's traditional JSON
template without request/response bodies, and the secret itself is never a
command argument.

## Limitations

- Header-based bearer, basic, and custom-header authentication are supported;
  form, browser, scripted, and multi-step login flows require a separately
  reviewed ZAP context and are not accepted by this interface.
- A scan can still trigger unsafe application behavior. Use disposable preview
  data and least-privilege test credentials.
- Redirect behavior is constrained by the outbound sender gate, but target-side
  DNS and infrastructure changes remain external controls.
- The Action requires a Linux runner with Docker.
