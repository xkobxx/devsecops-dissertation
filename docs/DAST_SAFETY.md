# DAST safety

Only scan systems you own or have written authorization to test.

## Safe defaults

TrustGate runs DAST in **passive-only mode** by default (`dast-scan-mode: safe`).
Active scanning (injection, fuzzing) is rejected unless
`dast-active-scan-acknowledged: true` is set explicitly. No destructive test
runs without opt-in.

## Resource bounds and rate limiting

Every scan enforces mandatory limits validated before ZAP starts.

| Control              | Default     | Range        |
|----------------------|------------:|-------------:|
| Requests per second  | 5           | 1 -- 100     |
| Total requests       | 500         | 1 -- 100,000 |
| Maximum duration     | 300 seconds | 1 -- 3,600   |

Exceeding any limit aborts the scan immediately via the HTTPSender gate.

## Scope restrictions

Targets must match an entry in `dast-scope-hosts`. Accepted formats:

- Exact host: `pr-42.preview.example.test`
- Bounded wildcard: `*.preview.example.test`

Global wildcards (`*`), bare URLs, paths, and ports are rejected. An outbound
sender gate re-checks every request at runtime and blocks any host not in the
allowlist.

## Authentication handling

TrustGate supports `bearer`, `basic`, and custom `header` authentication via ZAP
header-based session management. The plan references
`TRUSTGATE_DAST_AUTH_SECRET` by name only; the actual value is never written to
the plan, step outputs, or report. Basic auth expects a Base64-encoded
`username:password` string. Do not expose credentials to workflows that execute
untrusted pull-request code.

## When NOT to run DAST

- **Production without explicit approval** -- requires separate
  `dast-production-scan-acknowledged: true`.
- **Shared staging environments** -- crawling and passive analysis still send
  requests and can change application state on unsafe endpoints.
- **Third-party targets** -- scanning infrastructure you do not own is
  unauthorized access regardless of scan mode.
- **Workflows running untrusted PR code** -- auth secrets may leak.

Use disposable preview deployments with least-privilege test credentials.

## Example safe configuration

```yaml
trustgate dast:
  target-url: https://pr-123.preview.example.test
  environment: preview
  mode: baseline
  scan-mode: safe
  scope-hosts:
    - pr-123.preview.example.test
  rate-limit: 5
  request-limit: 500
  max-duration-seconds: 300
  public-target-acknowledged: true
  auth-type: bearer
  auth-secret: ${TRUSTGATE_DAST_AUTH_SECRET}
```

For API discovery, set `mode: api` and provide `openapi-path` pointing to a
workspace-relative OpenAPI document. To enable active scanning, add
`scan-mode: active` and `active-scan-acknowledged: true`.
