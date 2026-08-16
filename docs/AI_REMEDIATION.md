# AI-assisted remediation

Trust Gate's AI remediation is an explicitly authorised patch workflow, not an
automatic claim that a vulnerability is fixed. A generated patch remains
`unverified` until formatting, type checking, unit tests, integration tests,
relevant security scanners, finding comparison, and scanner-health checks all
pass. Failed verification blocks publication.

## Safety state machine

The workflow has five content-bound states:

1. `ai-context` creates a bounded preview and does not contact a model.
2. `ai-propose` requires explicit opt-in and acknowledgement of the preview's
   exact context digest before invoking the configured model.
3. `ai-stage` creates a new branch in a separate Git worktree and applies the
   unverified patch there. The active checkout must be clean and is not changed.
4. `ai-verify` runs every verification class and compares canonical scans.
5. `ai-publish` accepts only an intact `verified` receipt, pushes the isolated
   branch, and invokes `gh pr create --draft`.

Every state has a canonical SHA-256 digest and binds to the preceding state.
Changing a context bundle, proposal, staged diff, or verification receipt
invalidates the next transition.

## Preview exactly what leaves the runner

Create a context request that selects repository-relative line ranges and one
published remediation rule. The finding file must be included. A range is
limited to 400 lines, the request to 20 ranges, and transmitted context to
65,536 UTF-8 bytes.

```json
{
  "schema_version": "1.0.0",
  "request_id": "ai-request-1",
  "finding_fingerprint": "v1:sha256:example",
  "scan_run_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "remediation_rule_id": "TG-PY-SQL-001",
  "framework": "python-sqlite3",
  "provider": {
    "mode": "local",
    "command": ["local-secure-code-model", "--json"]
  },
  "context": [
    {"path": "src/app.py", "start_line": 20, "end_line": 60}
  ],
  "redaction": {"enabled": true}
}
```

```bash
trustgate remediate ai-context \
  --root . \
  --input reports/findings.json \
  --request ai-context-request.json \
  --output reports/ai-remediation-context.json
```

The output identifies the destination, whether context leaves the runner, each
path and line range, original and transmitted digests, byte counts, redaction
counts, and the exact payload. Secret assignments, bearer tokens, AWS access
key IDs, and PEM private keys are redacted when enabled. Redaction reduces
accidental disclosure but is not a guarantee that arbitrary sensitive business
data has been found; the operator must review the preview.

Repository content is wrapped as untrusted data and the model is instructed not
to follow instructions embedded in source. Paths cannot escape the repository,
and symlinked context files are rejected.

## Local and remote models

Local mode executes the configured argument vector directly with JSON on
standard input. It never uses a shell. The model must return exactly:

```json
{"summary": "What the patch changes", "patch": "diff --git a/..."}
```

Remote mode requires an HTTPS endpoint, model name, and the name of an
environment variable containing its bearer token:

```json
{
  "mode": "remote",
  "endpoint": "https://models.example.com/v1/remediate",
  "model": "secure-code-model",
  "authorization_env": "MODEL_API_TOKEN"
}
```

Remote invocation requires both `--opt-in-ai-remediation` and
`--allow-remote-context`; redaction must be enabled. Tokens are read from the
environment and are not placed in the context or output receipts.

After reviewing `disclosure.context_digest`, explicitly authorise that payload:

```bash
trustgate remediate ai-propose \
  --context reports/ai-remediation-context.json \
  --opt-in-ai-remediation \
  --acknowledge-context-digest sha256:... \
  --output reports/ai-remediation-proposal.json
```

Add `--allow-remote-context` only for a reviewed remote destination. Model
responses are bounded to 256 KiB and must contain a Git unified diff.

## Isolated staging

The proposal may modify only files included in the reviewed context. It cannot
add, delete, rename, or escape to another file. Stage it on a new branch in a
nonexistent sibling worktree:

```bash
trustgate remediate ai-stage \
  --repository . \
  --proposal reports/ai-remediation-proposal.json \
  --worktree ../trustgate-ai-fix \
  --branch codex/ai-remediation-example \
  --output reports/ai-remediation-stage.json
```

Trust Gate uses `git apply --check` before applying the patch and records the
exact resulting worktree diff digest. The original checkout remains on its
current branch and unchanged.

## Mandatory verification

Verification configuration uses direct argument arrays, never shell command
strings. Every category is required and may contain multiple commands:

```json
{
  "schema_version": "1.0.0",
  "timeout_seconds": 300,
  "formatting": [["python", "-m", "ruff", "format", "--check", "."]],
  "type_checking": [["python", "-m", "mypy", "src"]],
  "unit_tests": [["python", "-m", "unittest", "discover", "-s", "tests/unit"]],
  "integration_tests": [["python", "-m", "unittest", "discover", "-s", "tests/integration"]],
  "security_scanners": [["trustgate", "aggregate", "--reports-dir", "reports", "--output", "reports/post-ai-scan.json"]],
  "post_scan_run": "reports/post-ai-scan.json"
}
```

```bash
trustgate remediate ai-verify \
  --stage reports/ai-remediation-stage.json \
  --proposal reports/ai-remediation-proposal.json \
  --before-scan reports/findings.json \
  --config ai-verification.json \
  --output reports/ai-remediation-verification.json
```

Trust Gate runs all configured commands even when one fails. It then requires a
schema-valid post-remediation scan, healthy required scanners, disappearance of
the original fingerprint, and no newly introduced `high` or `critical`
fingerprints. It also verifies that test or scanner commands did not alter the
staged diff. Any failure produces `verification_failed`, retains blockers and
command evidence, and states that the issue is not fixed.

## Draft pull request

Only a verified receipt can be published:

```bash
trustgate remediate ai-publish \
  --stage reports/ai-remediation-stage.json \
  --verification reports/ai-remediation-verification.json \
  --title "Parameterize user lookup query" \
  --body-file ai-pr-body.md \
  --output reports/ai-remediation-publication.json
```

Publication rechecks the branch and exact diff, commits only the staged files,
pushes the isolated branch to `origin`, and opens a draft PR. Human review and
normal repository branch protection still apply. Trust Gate never marks a
finding fixed solely because a model generated a patch.
