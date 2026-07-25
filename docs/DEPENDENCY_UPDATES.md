# Dependency update process

Dependabot checks Python, GitHub Actions and Docker dependencies each week.
Updates are reviewed and released deliberately; an automated pull request is
not evidence that a scanner combination is compatible.

## Python dependency upgrade

1. Update only the intended exact version in the relevant
   `requirements/*.in` file and, when applicable, `pyproject.toml`.
2. Regenerate all affected locks with the Python 3.11 baseline:

   ```bash
   uv pip compile requirements/runtime.in \
     --output-file requirements/runtime.lock \
     --generate-hashes --python-version 3.11
   uv pip compile requirements/development.in \
     --output-file requirements/development.lock \
     --generate-hashes --python-version 3.11
   uv pip compile requirements/scanners.in \
     --output-file requirements/scanners.lock \
     --generate-hashes --python-version 3.11
   ```

3. Install the changed lock in a new virtual environment with
   `python -m pip install --require-hashes -r <lock>`.
4. Record scanner-version changes in
   [SCANNER_COMPATIBILITY.md](SCANNER_COMPATIBILITY.md).

## Action or container upgrade

1. Resolve a GitHub Action release tag to its full 40-character commit SHA.
   Keep the release tag as an inline comment beside the SHA.
2. Resolve a container release tag to its registry manifest digest. Use the
   digest in automation and keep the version or resolution date as a comment.
3. Run `PYTHONPATH=src python scripts/verify_dependency_pins.py`.

## Required pre-release evidence

Every dependency update pull request must include:

- a clean, hash-verified installation of each changed Python lock;
- the full unit and integration test suite;
- successful dependency-pin validation;
- successful `--version` execution for each changed scanner;
- a test scan of the supported Python fixture when a scanner changes;
- a changelog entry when behavior or supported versions change.

Scanner upgrades are merged separately from feature changes so regressions can
be attributed and reverted cleanly.
