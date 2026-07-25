# Workflow security

Trust Gate separates scanning from publishing and applies permissions at the
smallest useful scope. The repository workflow is intentionally safe to run on
untrusted pull requests: scanner jobs receive a read-only `GITHUB_TOKEN`, no
repository secrets, and no publishing credentials.

## Permission model

| Scope | Event | Permissions | Executes repository code |
| --- | --- | --- | --- |
| Scan and gate jobs | `push` and `pull_request` to `main` | `contents: read` | Yes |
| Same-repository PR dashboard link | `pull_request` | `pull-requests: write` only | No |
| Reusable Pages publisher | trusted `push` to `main` only | `contents: read`, `pages: write`, `id-token: write` | No |
| Environment-gated release | canonical `v*.*.*` tag | `contents: write`, `id-token: write`, `attestations: write`, `artifact-metadata: write` | Yes, only after approval |

The scan workflow defaults to `contents: read`. A job-level permission block
replaces that default for the two write-capable jobs. Neither write-capable job
checks out the repository or runs a shell command from repository content.

## Untrusted pull requests

Pull-request scanner jobs process attacker-controlled files and must therefore
be treated as hostile execution contexts.

- The workflow uses `pull_request`, not `pull_request_target`.
- No `secrets.*` expression is referenced by the scan workflow.
- The licence key is not passed to the repository's own scan workflow.
- Pages and OIDC permissions are unavailable to pull-request jobs.
- The dashboard publisher is callable only when the triggering event is a
  successful push build.
- The PR-link job runs a pinned Action with a static script and does not check
  out pull-request code.
- The PR-link job is skipped for fork pull requests; it never requests a write
  token for an external contributor's branch.

Repository settings should keep Actions from approving pull requests or
creating releases unless a dedicated workflow explicitly needs that authority.
Environment protection rules for `github-pages` provide an additional
repository-side control.

## User-controlled Action inputs

Composite Action values are passed through environment variables before shell
expansion. GitHub expression values are not inserted directly into executable
shell syntax. Before installing or running scanners,
`scripts/validate_inputs.py action` validates and normalises every Action input:

- `target` must exist, use a relative path and remain inside
  `GITHUB_WORKSPACE` after symlink resolution;
- `fail-on`, `scanner-failure-policy` and `optional-scanners` use explicit
  allowlists;
- scanner timeouts must be finite, greater than zero and no more than one hour;
- artifact names use a conservative portable character set;
- licence input is bounded and cannot contain control characters, while
  cryptographic validity remains the licence verifier's responsibility.

The validator rejects shell metacharacters, option-like path segments, absolute
paths and traversal before emitting canonical step outputs. Scanner steps use
only those outputs, not the original path or policy values.

DAST configuration has a separate validation mode. Public targets require
HTTPS and reject credentials, local names, private/reserved IP addresses and
fragments. The repository's fixed localhost research target opts into
`--allow-private`; its ZAP rules file must still resolve to a real file inside
the workspace.

Never add a secret to the environment of a scanner step. Scanner processes may
parse attacker-controlled source, dependency manifests, configuration and
repository history. Secret-bearing work must execute later, through trusted
code under `${{ github.action_path }}`, with the smallest possible environment.

## Publishing boundary

`.github/workflows/publish-dashboard.yml` contains the Pages deployment. The
scan workflow may prepare and upload a Pages artifact, but it cannot deploy it.
Only a successful `push` run on `main` calls the publisher and receives Pages
and OIDC permissions. The publishing workflow performs no checkout and executes
no repository-provided shell script.

## Continuous Scorecard review

`.github/workflows/scorecard-analysis.yml` runs the official OpenSSF Scorecard
Action on trusted `main` pushes and weekly. Its workflow defaults to
`permissions: read-all`; only the analysis job receives `security-events:
write` and `id-token: write` for SARIF and authenticated result publication.
Checkout credentials are not persisted and every Action is pinned to a
verified commit SHA. The validation record is
[`docs/audits/OPENSSF_SCORECARD_REVIEW.md`](../audits/OPENSSF_SCORECARD_REVIEW.md).

## Release boundary

`.github/workflows/release.yml` runs only for semantic-version-shaped tags in
the canonical repository and enters the `release` environment before checking
out or executing repository code. Required reviewers must protect that
environment in repository settings.

A separate read-only job first queries the GitHub environment API and fails
unless the environment has at least one required reviewer. It performs no
checkout and receives no write permission. Only after that check succeeds does
the environment-gated release job validate that the tag, package version, and
tagged commit agree. It then creates deterministic archives, an exact-lock
CycloneDX SBOM, checksums, keyless Sigstore bundles, SLSA build provenance, and
an SBOM attestation. Only this environment-gated job receives release, OIDC, or
attestation write permissions. Checkout credentials are not persisted.

## Review checklist

Before changing a workflow:

1. Keep the top-level permission read-only.
2. Add write permission only to the single job that needs it.
3. Do not combine checkout or repository scripts with write credentials.
4. Pin every third-party Action to a full commit SHA.
5. Pass user-controlled values through `env`, then validate them.
6. Keep `pull_request_target` absent unless a documented design review proves
   that no pull-request code can execute.
7. Confirm untrusted jobs receive neither licence keys nor publishing tokens.
