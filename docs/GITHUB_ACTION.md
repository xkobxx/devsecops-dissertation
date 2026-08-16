# GitHub Action Integration

Run TrustGate as a security gate in your CI pipeline.

## Workflow Example

```yaml
# .github/workflows/security.yml
name: Security Gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: pip

      - name: Install TrustGate
        run: pip install trustgate

      - name: Run scanners
        run: |
          trustgate scan --tool bandit --output results/bandit.sarif .
          trustgate scan --tool semgrep --output results/semgrep.sarif .

      - name: Aggregate findings
        run: trustgate aggregate results/ --output aggregate.json

      - name: Security decision
        run: trustgate decide aggregate.json
```

## Exit Codes

`trustgate decide` uses exit codes to gate your pipeline:

| Code | Meaning            |
|------|--------------------|
| `0`  | Gate passed        |
| `1`  | Gate failed        |
| `2`  | Configuration error|

GitHub Actions treats any non-zero exit as a step failure, so the workflow stops automatically when the gate fails.

## Caching Dependencies

The `actions/setup-python` step above includes `cache: pip`, which caches downloaded packages between runs. For projects with a lockfile, point the cache at it:

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.11"
    cache: pip
    cache-dependency-path: requirements.lock
```

## Branch Protection

To enforce the gate on pull requests, add a branch protection rule requiring the `security-gate` job to pass before merging:

**Settings > Branches > Branch protection rules > Require status checks > `security-gate`**

## Fail-Open for Non-Blocking Scans

To run the gate without blocking the pipeline (advisory mode), append `|| true`:

```yaml
- name: Security decision (advisory)
  run: trustgate decide aggregate.json || true
```

Findings still appear in the build log but do not fail the workflow.
