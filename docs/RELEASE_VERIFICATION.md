# Release verification

Trust Gate release archives are generated from the tagged Git commit. The
release workflow creates both `tar.gz` and `zip` archives, records their SHA-256
digests, generates a CycloneDX SBOM from the exact runtime lock, and signs each
archive, the SBOM, and the checksum manifest with Sigstore's keyless GitHub
Actions identity. GitHub also publishes SLSA build provenance and a separate
SBOM attestation for the archives.

The historical `v1.0.0` and `v1.0.0-submission` tags predate this process and
must not be treated as signed Trust Gate product releases.

## Download one release

GitHub CLI users can download a release into a new directory:

```shell
VERSION=0.1.0
mkdir "trustgate-${VERSION}-release"
gh release download "v${VERSION}" \
  --repo xkobxx/devsecops-dissertation \
  --dir "trustgate-${VERSION}-release"
cd "trustgate-${VERSION}-release"
```

Do not mix files from different releases in the verification directory.

## Verify checksums

Download all files from one GitHub release into the same directory, then run:

```shell
sha256sum --check SHA256SUMS
```

Every archive and the SBOM must report `OK`. A missing file, extra filename, or
digest mismatch invalidates the release.

## Verify repository and workflow identity

Install Cosign 3.0.6 or a compatible later security release. Set `VERSION` to
the release version without the leading `v`, then verify every signed file:

```shell
VERSION=0.1.0
IDENTITY="https://github.com/xkobxx/devsecops-dissertation/.github/workflows/release.yml@refs/tags/v${VERSION}"
ISSUER="https://token.actions.githubusercontent.com"

for artifact in \
  "trustgate-${VERSION}.tar.gz" \
  "trustgate-${VERSION}.zip" \
  "trustgate-v${VERSION}.cdx.json" \
  SHA256SUMS
do
  cosign verify-blob "${artifact}" \
    --bundle "${artifact}.sigstore.json" \
    --certificate-identity "${IDENTITY}" \
    --certificate-oidc-issuer "${ISSUER}"
done
```

Verification succeeds only when the bundle covers the exact downloaded bytes
and the signing certificate identifies this repository's `release.yml`
workflow at the matching version tag. Do not weaken the identity to a broad
regular expression.

## Verify published attestations

The GitHub CLI verifies the attestation signature, repository identity, subject
digest, workflow, and source commit. Resolve the immutable commit behind the
official release tag:

```shell
EXPECTED_COMMIT="$(gh api "repos/xkobxx/devsecops-dissertation/commits/v${VERSION}" \
  --jq .sha)"
printf '%s\n' "${EXPECTED_COMMIT}"
```

Verify build provenance for each archive against that exact source and signer
commit:

```shell
for artifact in "trustgate-${VERSION}.tar.gz" "trustgate-${VERSION}.zip"
do
  gh attestation verify "${artifact}" \
    --repo xkobxx/devsecops-dissertation \
    --signer-repo xkobxx/devsecops-dissertation \
    --signer-workflow xkobxx/devsecops-dissertation/.github/workflows/release.yml \
    --source-ref "refs/tags/v${VERSION}" \
    --source-digest "${EXPECTED_COMMIT}" \
    --signer-digest "${EXPECTED_COMMIT}" \
    --deny-self-hosted-runners
done
```

Then require the separate CycloneDX SBOM predicate:

```shell
for artifact in "trustgate-${VERSION}.tar.gz" "trustgate-${VERSION}.zip"
do
  gh attestation verify "${artifact}" \
    --repo xkobxx/devsecops-dissertation \
    --signer-repo xkobxx/devsecops-dissertation \
    --signer-workflow xkobxx/devsecops-dissertation/.github/workflows/release.yml \
    --source-ref "refs/tags/v${VERSION}" \
    --source-digest "${EXPECTED_COMMIT}" \
    --signer-digest "${EXPECTED_COMMIT}" \
    --deny-self-hosted-runners \
    --predicate-type https://cyclonedx.org/bom
done
```

Both commands must succeed for both archives. The default provenance output
identifies the source commit and `release.yml` workflow that built the subjects;
the predicate-constrained check proves that the published CycloneDX document
was attached to those exact archive digests.

The repository and workflow constraints are deliberately redundant. Together
with the exact tag, source digest, and signer digest, they prevent an otherwise
valid attestation from a fork, a different workflow revision, or another
release from satisfying verification. Do not replace them with the broader
`--owner` option.

## Release boundary

The archives are created with `git archive` from the immutable commit referenced
by the release tag. Consequently ignored and untracked developer files,
databases, reports, and private signing keys cannot enter the archives.

The `release` GitHub environment must have required reviewers configured in the
repository settings. A tag must not be considered an approved release until its
environment-gated workflow run and all verification steps complete.

Before checking out the tagged source, the workflow queries the environment
configuration and requires a non-empty `required_reviewers` protection rule. A
missing or unprotected environment fails the workflow. Maintainers can audit
the rule with:

```shell
gh api repos/xkobxx/devsecops-dissertation/environments/release \
  --jq '.protection_rules[] | select(.type == "required_reviewers")'
```

Release publication names the versioned CycloneDX file explicitly. The SBOM is
also required by the checksum manifest and the SBOM-attestation step, both of
which run before `gh release create`. A missing SBOM therefore blocks release
publication instead of producing a partial release.
