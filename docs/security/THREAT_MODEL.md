# Trust Gate threat model

This threat model covers the composite Action, the repository's GitHub Actions
workflows, scanner execution, report aggregation and dashboard publishing.

## Security objectives

- A scanner crash, timeout or missing report must never look clean.
- Untrusted pull requests must not obtain a write-capable `GITHUB_TOKEN`,
  licence material, OIDC identity or Pages publishing authority.
- User-controlled inputs must not escape the workspace or become shell syntax.
- Published reports must be traceable to a trusted workflow run.
- Scanner output must be treated as untrusted data.

## Assets

- Repository contents and branch integrity.
- `GITHUB_TOKEN` and its job-specific permissions.
- Pages and OIDC publishing credentials.
- Commercial licence keys and private signing material.
- Scanner reports, execution metadata and the final gate decision.
- GitHub Actions artifacts and the published dashboard.

## Actors

- Maintainers who can merge code and change repository settings.
- Contributors whose pull-request branch and files are untrusted.
- A compromised dependency, scanner image or third-party Action.
- An attacker controlling Action input values or scanner report content.

## Trust boundaries

```text
untrusted repository/input
          |
          v
read-only scanner jobs -> untrusted reports -> fail-closed aggregator
          |                                      |
          | no secrets / no write token          v
          +------------------------------- dashboard artifact
                                                   |
                                      trusted push-only boundary
                                                   |
                                                   v
                                      isolated Pages publisher
```

The principal boundary is between jobs that check out and inspect repository
content and jobs that hold write authority. GitHub issues a `GITHUB_TOKEN` per
job, and Trust Gate limits each job's permissions so scan jobs remain read-only.
The Pages job runs in a reusable publishing workflow, performs no checkout and
is reachable only from a successful push build.

## Threats and controls

| Threat | Control |
| --- | --- |
| Pull-request code steals a token | Scan jobs have `contents: read`, receive no secrets and have no Pages/OIDC permission |
| Pull-request code publishes a dashboard | Publisher condition requires a successful `push`; publishing is isolated from scanning |
| Malicious expression becomes shell code | Inputs cross the shell boundary through environment variables, then allowlist and metacharacter validation produces canonical outputs |
| Path input scans or writes outside the workspace | Canonical resolution rejects absolute paths, traversal and symlinks that escape `GITHUB_WORKSPACE` |
| DAST input targets runner metadata or local services | Public mode requires HTTPS and rejects credentials, private/reserved IPs and local hostnames; local research use requires an explicit override |
| Malicious artifact name creates ambiguous output | Artifact names use a bounded portable allowlist before upload |
| Scanner crash becomes zero findings | Execution metadata, report presence and parser status are required by the gate |
| Compromised third-party dependency changes over time | Python hashes, Action SHAs and container digests are immutable |
| Malicious report injects dashboard content | Report data is untrusted; output encoding and schema work continue in later roadmap phases |
| Licence disclosure to a scanner | Licence values are absent from scanner environments and used only by trusted Action code |

## `pull_request_target` review

No workflow uses `pull_request_target`. Introducing it would cross the
read/write trust boundary and requires a new threat-model review. Such a
workflow must never check out, import or execute pull-request-controlled code.

## Residual risks

- A maintainer can merge malicious workflow changes; branch protection and
  required review are repository-setting controls.
- A pinned dependency can still contain a vulnerability; upgrade review,
  provenance and SBOM work continue in later roadmap phases.
- Repository-generated HTML is published after merge. Dashboard output
  encoding and content-security-policy hardening remain required.
- GitHub environment protection and organization policies are external to this
  repository and must be configured by an administrator.
