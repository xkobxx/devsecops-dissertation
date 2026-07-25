# Versioning policy

Trust Gate uses Semantic Versioning for the installable package and release
artefacts.

## Version meaning

- **MAJOR**: incompatible CLI, configuration, Action input/output, policy, or
  supported schema changes.
- **MINOR**: backward-compatible features, scanners, commands, or schema
  additions.
- **PATCH**: backward-compatible fixes and documentation corrections.

During `0.x`, the product is under active development and may change rapidly.
Every breaking change still requires a migration note.

## Sources of version truth

These values must match:

- `pyproject.toml` project version;
- `src/trustgate/__init__.py` `__version__`;
- release tag;
- release notes; and
- generated artefact metadata.

`scripts/build_release.py` reads both version files from the tagged commit,
requires the tag to equal `v<version>`, and refuses to build when either source
or the tag disagrees.

Finding, scan-run, policy, fingerprint, benchmark-methodology, and evidence-bundle
schemas have their own explicit versions. A package version must not be used as a
substitute for a schema version.

## GitHub Action references

Readable release tags may be published for discovery. Production examples must
also provide the immutable commit SHA corresponding to the documented release.

## Historical tags

The existing `v1.0.0` and `v1.0.0-submission` tags belong to the dissertation-era
prototype. They do not satisfy the current roadmap's definition of a complete
Trust Gate release.
