# OpenSSF Scorecard review

Review date: 2026-07-25
Repository: `github.com/xkobxx/devsecops-dissertation`
Tool: OpenSSF Scorecard 5.5.0 (`c395761df6afe1a69e476bc60a013a94bcbc153f`)

## Result

| Review target | Check | Score | Reason |
| --- | --- | ---: | --- |
| Hardened local source snapshot | Token-Permissions | 10 / 10 | GitHub workflow tokens follow principle of least privilege |
| Hardened local source snapshot | Dangerous-Workflow | 10 / 10 | No dangerous workflow patterns detected |
| Hardened local source snapshot | Pinned-Dependencies | 10 / 10 | All dependencies are pinned |
| Remote `main` baseline (`a780add87bf05b71dd6cb4ea649c58a098dcfe43`) | Token-Permissions | 10 / 10 | GitHub workflow tokens follow principle of least privilege |
| Remote `main` baseline | Dangerous-Workflow | 10 / 10 | No dangerous workflow patterns detected |
| Remote `main` baseline | Pinned-Dependencies | 0 / 10 | Dependency not pinned by hash detected |

The roadmap permission acceptance criterion passes on both the remote baseline
and the hardened worktree. The hardened worktree also resolves the dependency
pinning result. A published Scorecard API result is not yet available because
the repository did not previously contain a Scorecard publishing workflow.

## Method

The official `scorecard_5.5.0_darwin_arm64.tar.gz` release was downloaded from
`ossf/scorecard` and verified against the release's
`scorecard_checksums.txt`. The remote baseline used:

```text
scorecard --repo github.com/xkobxx/devsecops-dissertation \
  --checks Token-Permissions,Dangerous-Workflow,Pinned-Dependencies \
  --format json
```

The hardened review used `--local` against a source snapshot of the current
worktree. Ignored AppleDouble `._*` filesystem metadata was excluded because it
is not source and contains binary control bytes that the workflow parser
correctly rejects.

## Continuous review

`.github/workflows/scorecard-analysis.yml` now runs on pushes to `main` and on a
weekly schedule. It:

- defaults to `permissions: read-all`;
- grants only `security-events: write` and `id-token: write` to the analysis
  job;
- uses only the actions approved for Scorecard result publication;
- pins every Action to a verified full commit SHA;
- disables checkout credential persistence;
- publishes authenticated results and uploads SARIF to code scanning.

### Pinned workflow dependencies

| Dependency | Release | Commit SHA |
| --- | --- | --- |
| `actions/checkout` | `v7.0.0` | `9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0` |
| `ossf/scorecard-action` | `v2.4.4` | `2d1146689b8cda280b9bc96326124645441f03bc` |
| `actions/upload-artifact` | `v7.0.1` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| `github/codeql-action/upload-sarif` | `v4.36.2` | `8aad20d150bbac5944a9f9d289da16a4b0d87c1e` |

The first trusted `main` run will create the public API result. Until that run
completes, this document is the review evidence and no badge should claim a
published score.
