# Scanner compatibility

This matrix records the scanner set locked for Trust Gate's Python-first
evaluation release. The supported baseline is GitHub-hosted Ubuntu with Python
3.11. Every Python package and transitive dependency is installed from
`requirements/scanners.lock` with hash verification.

| Scanner | Pinned version | Invocation | Findings exit contract | Supported target | Validation baseline |
| --- | --- | --- | --- | --- | --- |
| Bandit | 1.9.4 | Python package | `1` means findings | Python source | Python 3.11, Ubuntu |
| Semgrep | 1.165.0 | Python package | Findings are read from JSON; non-zero means execution failure without `--error` | Python ruleset `p/python` | Python 3.11, Ubuntu |
| pip-audit | 2.10.1 | Python package | `1` means vulnerabilities | pip requirements files | Python 3.11, Ubuntu |
| Trivy | 0.69.3 via Action 0.36.0 | GitHub Action at an immutable commit, scanner version set explicitly | Action outcome plus report presence; findings remain exit `0` | Repository configuration | GitHub-hosted Ubuntu |
| Gitleaks | 8.30.1 | OCI image at an immutable digest | Trust Gate sets `--exit-code 3` for leaks; `1` remains an execution error | Checked-out repository and history | Linux runner with Docker |
| ZAP Baseline Action | 0.12.0 | GitHub Action at an immutable commit | Action outcome plus report presence | HTTP endpoint | GitHub-hosted Ubuntu; research workflow only |

## Compatibility contract

- The composite Action requires a Linux runner because Trivy is a container
  Action and Gitleaks runs through Docker.
- Python 3.11 is the release baseline. Other Python versions are not claimed
  until the version matrix in roadmap Phase 12 is implemented.
- Bandit, Semgrep and pip-audit are installed together from the same lock to
  prevent resolver differences between scanner jobs.
- Trivy, Gitleaks and ZAP versions are independent of the host Python
  environment.
- Exit-code findings are accepted only when the expected report exists.
  Timeouts, unknown exit codes, missing reports and external Action failures
  produce scanner-failure evidence rather than zero findings.
- The ZAP job and the Docker Compose applications are research fixtures. They
  do not define the production gate's supported target matrix.

## Upgrade rule

A scanner version is supported only after its immutable reference is recorded
here, dependency-pin validation passes, the lock installs in a clean Python
3.11 environment, scanner version commands succeed, and the repository test
suite passes. The full procedure is in
[DEPENDENCY_UPDATES.md](DEPENDENCY_UPDATES.md).
