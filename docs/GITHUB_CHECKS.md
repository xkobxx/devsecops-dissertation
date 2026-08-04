# GitHub Checks integration

[GitHub Actions creates checks](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/collaborating-on-repositories-with-code-quality-features/about-status-checks)
for workflow jobs. Trust Gate uses that native check and writes a bounded
GitHub-flavoured Markdown summary through
[`GITHUB_STEP_SUMMARY`](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#adding-a-job-summary);
it does not create a second status or request `checks: write`.

The repository workflow gives the gate job the stable display name
`Trust Gate`. Its final enforcement step determines the Check Run conclusion,
so a failed security decision produces a failed required check. The workflow
runs for `pull_request`, `push`, and `merge_group` events to support protected
branches and merge queues.

## Summary contents

`trustgate checks` validates and binds the canonical scan run, policy result,
and optional baseline documents before publishing `reports/check-summary.md`:

```bash
trustgate checks \
  --input reports/findings.json \
  --policy-result reports/policy-result.json \
  --baseline-diff reports/baseline-diff.json \
  --baseline-gate reports/baseline-gate.json \
  --artifact-url "$ARTIFACT_URL" \
  --output reports/check-summary.md
```

The summary includes:

- the pass, warning, failure, or error release decision and reason;
- required and optional scanner health, state, finding count, and version;
- total, new, blocking, suppressed, and unscored finding counts;
- bounded tables for new, blocking, suppressed, and unscored findings;
- evidence explanations derived from severity, reachability, category, scanner,
  and remediation availability;
- policy identity, outcome, threshold, severity basis, scanner-failure policy,
  and waiver count;
- baseline transition counts and the differential gate result when supplied;
- a validated HTTPS link to the workflow's detailed artifacts.

Tables show at most ten findings per classification, and the complete summary
must remain below 65,536 bytes. User-controlled Markdown characters are escaped.
Descriptions, source/sink expressions, raw evidence excerpts, and scanner logs
are deliberately excluded. The artifact remains the authoritative place for
complete evidence.

When baseline documents are unavailable, the summary says that no comparison
was supplied instead of presenting zero changes. A policy result, baseline
difference, or baseline gate belonging to another scan run is rejected.

## Branch protection

Run the workflow once on the repository, then
[configure the protected branch](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
or ruleset to require the status check named exactly `Trust Gate`. Keep that
job name unique across workflows. GitHub can optionally pin the expected source
to the GitHub Actions app.

For consumers of the composite Action, give the caller job the same stable
name:

```yaml
jobs:
  trust-gate:
    name: Trust Gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: xkobxx/devsecops-dissertation@v1.0.0
```

Select `Trust Gate` under the branch rule's required status checks after the
job has completed successfully in the repository. Do not reuse that display
name for an informational or fail-open workflow, because duplicate check names
make branch-protection results ambiguous.
