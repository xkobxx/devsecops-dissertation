# Software bills of materials

Trust Gate generates the product's runtime software bill of materials in two
interoperable JSON formats from one immutable Git commit:

- CycloneDX 1.6 JSON: `trustgate-v<version>.cdx.json`
- SPDX 2.3 JSON: `trustgate-v<version>.spdx.json`

Both documents contain the Trust Gate application and every direct and
transitive dependency in `requirements/runtime.lock`. Each dependency includes
its exact version, SPDX licence expression, Package URL, and every SHA-256
distribution hash retained by the hash-locked requirements file. Dependency
relationships are reconstructed from the lockfile's `# via` metadata. Direct
dependencies are checked against `requirements/runtime.in`; missing packages or
version disagreement fails generation.

The hashes describe the approved package distributions in the lock, not files
inside an installed environment. CycloneDX records direct/transitive status as
the `trustgate:dependency:type` component property. SPDX records the same status
in each dependency package comment and represents the graph with `DEPENDS_ON`
relationships.

## Generate both formats

The ref must resolve to a commit whose package version matches the expected
semantic release tag:

```shell
trustgate sbom \
  --repository . \
  --ref v0.1.0 \
  --tag v0.1.0 \
  --output-directory reports/sbom
```

The command refuses to overwrite either output. Documents are written through
temporary files and atomically moved into place. Metadata, ordering, document
identifiers, timestamps, components, and relationships are derived from the
selected commit, so repeated generation from the same commit is byte-identical.

## Maintain the licence inventory

`requirements/runtime.licenses.json` is a reviewed companion to the generated
lockfile. Every entry is tied to an exact package version and records its source
metadata URL. SBOM generation fails closed when the inventory is malformed,
contains a package absent from the lock, disagrees with a locked version, or
omits a locked dependency.

When updating runtime dependencies:

1. Regenerate `requirements/runtime.lock` using the documented dependency
   update process.
2. Review licence metadata and upstream licence files for every changed
   package.
3. Update the exact version, SPDX expression, and source URL in
   `requirements/runtime.licenses.json`.
4. Run the supply-chain tests and generate both SBOM formats from the resulting
   commit.

Licence metadata is evidence for review, not legal advice. Ambiguous or custom
terms require human and, where appropriate, legal review before release.

## Release integration

`scripts/build_release.py` generates both documents before `SHA256SUMS`. The
release workflow includes both SBOMs in the checksum manifest, creates a keyless
Sigstore bundle for each, and publishes them as explicit release assets. The
CycloneDX document is additionally attached to the source archives through the
GitHub SBOM attestation step. See
[RELEASE_VERIFICATION.md](RELEASE_VERIFICATION.md) for consumer verification.
