# Deliberately vulnerable Flask fixture

This application contains six intentional vulnerabilities used to evaluate
Bandit and Semgrep:

- hard-coded credentials;
- SQL injection;
- command injection;
- code injection through `eval`;
- unvalidated redirect; and
- path traversal.

The expected findings are recorded in `seeded_vulnerabilities.json`.

Safety rules:

- run only in an isolated local or CI environment;
- never expose the Flask development server publicly;
- never reuse the credentials or dependency set in a real application; and
- never treat this directory as Trust Gate production source.
