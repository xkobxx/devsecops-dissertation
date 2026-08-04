# Pull-request comments

Trust Gate publishes one concise pull-request summary for same-repository pull
requests. The comment complements the native `Trust Gate` Check Run; scanner
jobs do not post independent messages.

## Generate the comment

`trustgate pr-comment` validates and binds the scan run, policy result, and any
baseline evidence before writing bounded Markdown:

```bash
trustgate pr-comment \
  --input reports/findings.json \
  --policy-result reports/policy-result.json \
  --baseline-diff reports/baseline-diff.json \
  --baseline-gate reports/baseline-gate.json \
  --repository owner/repository \
  --commit "$GITHUB_SHA" \
  --artifact-url "$ARTIFACT_URL" \
  --output reports/pr-comment.md
```

The visible summary contains the release decision and total, new, blocking,
suppressed, and unscored counts. Finding and policy detail is inside collapsed
`details` blocks. At most ten new, blocking, or suppressed findings appear,
with links to the exact commit and line when a safe repository-relative
location exists. Longer result sets remain in the workflow artifacts.

The output is deterministic and capped below 32,768 bytes. Repository names,
commit revisions, document bindings, locations, and HTTPS links are validated;
Markdown-controlled values are escaped. The renderer deliberately excludes
finding titles, descriptions, source and sink expressions, evidence excerpts,
scanner logs, remediation text, suppression reasons, and approval identities.
It reports only whether remediation is available. This keeps secret material
and proprietary source excerpts out of the pull-request conversation.

## Single-comment update model

The repository workflow puts the generated Markdown in the
`unified-findings` artifact. A separate write-capable job downloads that file
without checking out or executing repository code. Its pinned GitHub Script
action:

1. requires the `<!-- trustgate-pr-summary -->` marker and the size bound;
2. paginates existing issue comments;
3. selects only a marker-bearing comment owned by `github-actions[bot]`;
4. updates that comment, or creates it when none exists.

Human-authored lookalike comments are never overwritten. Every rerun therefore
converges on one Trust Gate comment instead of adding scanner-by-scanner noise.
Workflow concurrency cancels an older in-progress run for the same pull request,
preventing simultaneous publishers from racing to create the initial comment.
The job has only `actions: read` and `pull-requests: write`, contains no
checkout or shell step, and is skipped for fork pull requests.

Composite Action consumers receive `pr-comment-path` as an output and artifact
but must choose whether to publish it. The composite Action itself does not
request pull-request write permission.
