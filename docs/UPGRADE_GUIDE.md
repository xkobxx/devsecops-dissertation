# TrustGate Upgrade Guide

## Version Compatibility

TrustGate follows [Semantic Versioning](https://semver.org/). Given a version `MAJOR.MINOR.PATCH`:

- **MAJOR** -- breaking changes to CLI interface, schema format, or public API
- **MINOR** -- new features, new rules, deprecation warnings for upcoming removals
- **PATCH** -- bug fixes, rule-tuning updates, documentation corrections

| TrustGate Version | Python Requirement |
|---|---|
| 1.x | >= 3.10 |
| 0.x | >= 3.9 |

## Checking Your Current Version

```bash
trustgate --version
```

## Upgrading

Install the latest release:

```bash
pip install --upgrade trustgate
```

Pin to a specific version:

```bash
pip install trustgate==1.2.0
```

After upgrading, verify the installation:

```bash
trustgate --version
trustgate schema --validate
```

## Schema Version Migration

Major releases may ship updated schema versions. Run the built-in migration after upgrading:

```bash
trustgate schema --migrate
```

This updates local configuration and audit-evidence files to the current schema format. The original files are backed up with a `.bak` extension before any changes are applied.

To preview changes without writing them:

```bash
trustgate schema --migrate --dry-run
```

## Breaking Changes Policy

- Breaking changes occur **only** in major version bumps.
- Deprecated features emit warnings for at least **one full minor release cycle** before removal.
- The `trustgate schema --validate` command reports any incompatibilities with the current version.

Watch for deprecation warnings in CLI output after upgrading to a new minor version -- they signal changes coming in the next major release.

## Rollback Procedure

If an upgrade causes issues, pin the previous version:

```bash
pip install trustgate==1.1.0
```

Then revert any migrated schemas:

```bash
# Restore from the automatic backup
cp schemas/registry.json.bak schemas/registry.json
```

Re-validate after rollback:

```bash
trustgate schema --validate
```

## Changelog

The full changelog is maintained at [`CHANGELOG.md`](../CHANGELOG.md) in the repository root. Each release entry lists added features, fixed bugs, and any breaking changes with migration steps.
