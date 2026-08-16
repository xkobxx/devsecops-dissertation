# Deterministic remediation

Trust Gate applies only narrow, documented source transformations whose
preconditions can be proven from the current file and an explicit,
content-bound request. It does not guess when syntax, framework, or intended
behaviour is ambiguous.

## Supported rules

| Rule ID | Framework | Deterministic change |
|---|---|---|
| `TG-PY-SQL-001` | Python with SQLite DB-API | Converts one `cursor.execute` f-string into a `?` query and value tuple. |
| `TG-PY-SHELL-001` | Python `subprocess` | Converts one static command to argv and removes `shell=True`. |
| `TG-PY-YAML-001` | Python with PyYAML | Replaces one unqualified `yaml.load(value)` with `yaml.safe_load(value)`. |
| `TG-PY-HASH-001` | Python `hashlib` | Replaces one security-purpose MD5 or SHA-1 constructor with SHA-256. |
| `TG-DEP-PY-001` | Python requirements | Upgrades one exact dependency pin, requiring new hashes for a hash-locked block. |
| `TG-DOCKER-USER-001` | Single-stage Dockerfile | Adds a numeric non-root `USER` before the sole final `CMD` or `ENTRYPOINT`. |
| `TG-PY-SECRET-001` | Python environment configuration | Replaces one module-level literal with `os.environ[...]`. |
| `TG-FLASK-HEADERS-001` | Flask | Adds one response hook with conservative CSP, permissions, referrer, frame, and MIME policies. |

Publish machine-readable contracts containing each rule's framework,
preconditions, transformation, required tests, rollback behaviour, and risk
notes:

```bash
trustgate remediate rules --output reports/remediation-rules.json
```

These rule IDs describe Trust Gate transformations, not broad aliases for
scanner rule IDs. A scanner finding must be mapped to one of these contracts
only after its exact syntax and framework preconditions are established.

## Plan contract

Every source file is bound by SHA-256 before transformation:

```json
{
  "schema_version": "1.0.0",
  "plan_id": "plan-security-fixes-42",
  "requests": [
    {
      "request_id": "unsafe-yaml-config",
      "rule_id": "TG-PY-YAML-001",
      "framework": "python-pyyaml",
      "path": "src/service/config.py",
      "expected_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      "parameters": {}
    }
  ]
}
```

Plans require unique request IDs and one request per file. Paths must resolve
beneath `--root`, cannot target the backup directory, and cannot be symlinks.
Python rules accept only `.py`; dependency rules accept `.in`, `.txt`, or
`.lock`; Docker rules accept `Dockerfile` or `Dockerfile.*`.

Each transformation requires exactly one supported target in its file.
Multiple candidates, stale digests, dynamic commands, shell operators, custom
YAML loaders, non-security hash uses, unpinned dependencies, unsupported
lockfile options, multi-stage Dockerfiles, dynamic secrets, or pre-existing
Flask response hooks fail without writing any source file.

## Apply and roll back

```bash
trustgate remediate apply \
  --root . \
  --plan remediation-plan.json \
  --backup-root .trustgate/remediation-backups \
  --receipt reports/remediation-receipt.json

trustgate remediate rollback \
  --root . \
  --receipt reports/remediation-receipt.json \
  --backup-root .trustgate/remediation-backups \
  --output reports/remediation-rollback.json
```

The engine parses and transforms every request in memory before creating a
backup or writing a source file. Backups are content-bound to the deterministic
transaction ID; directories use mode `0700` and files use mode `0600`.
Symlinked or escaping transaction paths are rejected. Source replacement is
atomic per file. If any write fails, already-written files are restored before
the command returns an error. If the CLI cannot persist its application
receipt, it also rolls the transaction back.

Rollback first verifies the receipt digest, each current after-digest, and each
backup before-digest. It refuses to overwrite code changed since remediation.
Verified original bytes and file modes are restored atomically. Backups are
retained so deletion remains an explicit operator decision.

## Rule-specific boundaries and risks

- SQL values can be bound, but table or column identifiers still need an
  application allowlist. Conversion and format-specifier f-strings are refused.
- Direct argv execution does not reproduce pipelines, redirection, globbing,
  expansion, or shell built-ins, so commands using those features are refused.
- `safe_load` intentionally stops constructing arbitrary Python objects.
- SHA-256 changes digest length and interoperability. It is not a password KDF;
  password storage needs Argon2, scrypt, bcrypt, or PBKDF2 as appropriate.
- Dependency upgrades can break APIs. Hashes prove selected distributions, not
  compatibility, so installation and regression tests remain mandatory.
- A numeric Docker user may lack write permission. Build and runtime smoke tests
  must establish required ownership before accepting the fix.
- Environment-backed secrets require deployment configuration. Removing a
  literal from the current source does not remove it from Git history or the
  protected rollback backup; revoke or rotate exposed credentials immediately.
- The Flask CSP is intentionally conservative and may block external scripts or
  styles. HSTS is not added automatically because TLS termination and subdomain
  policy cannot be inferred safely.

The receipt carries these risk notes and verification-test requirements for
every change. A transformation is an applied patch, not proof that the original
finding is fixed; callers must run the listed tests and relevant scanners.
