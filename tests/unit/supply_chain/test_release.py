from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

from trustgate.supply_chain.release import (
    ReleaseError,
    build_release_archives,
    generate_cyclonedx_sbom,
    generate_checksums,
    sign_release_artifacts,
)


class ReleaseArtifactTests(unittest.TestCase):
    def _repository(self, root: Path, *, package_version: str = "0.1.0") -> None:
        package = root / "src" / "trustgate"
        package.mkdir(parents=True)
        (root / "pyproject.toml").write_text(
            f'[project]\nname = "trustgate"\nversion = "{package_version}"\n',
            encoding="utf-8",
        )
        (package / "__init__.py").write_text(
            f'__version__ = "{package_version}"\n',
            encoding="utf-8",
        )
        requirements = root / "requirements"
        requirements.mkdir()
        (requirements / "runtime.in").write_text(
            "cryptography==49.0.0\n",
            encoding="utf-8",
        )
        (requirements / "runtime.lock").write_text(
            """
cffi==2.1.0 \\
    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    # via cryptography
cryptography==49.0.0 \\
    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    # via -r requirements/runtime.in
pycparser==3.0 \\
    --hash=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    # via cffi
""".lstrip(),
            encoding="utf-8",
        )
        (root / "README.md").write_text("release fixture\n", encoding="utf-8")
        (root / ".gitignore").write_text("private-key.pem\n", encoding="utf-8")
        (root / "private-key.pem").write_text("never package me\n", encoding="utf-8")

        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(
            ["git", "config", "user.name", "Trust Gate tests"],
            cwd=root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "tests@trustgate.invalid"],
            cwd=root,
            check=True,
        )
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "release fixture"],
            cwd=root,
            check=True,
        )
        subprocess.run(["git", "tag", f"v{package_version}"], cwd=root, check=True)

    def test_builds_reproducible_versioned_archives_from_the_tagged_commit(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._repository(root)
            first = build_release_archives(
                repository=root,
                output_directory=root / "first",
                ref="v0.1.0",
                expected_tag="v0.1.0",
            )
            second = build_release_archives(
                repository=root,
                output_directory=root / "second",
                ref="v0.1.0",
                expected_tag="v0.1.0",
            )

            self.assertEqual(
                [path.name for path in first],
                ["trustgate-0.1.0.tar.gz", "trustgate-0.1.0.zip"],
            )
            self.assertEqual(
                [hashlib.sha256(path.read_bytes()).hexdigest() for path in first],
                [hashlib.sha256(path.read_bytes()).hexdigest() for path in second],
            )

            with tarfile.open(first[0], "r:gz") as archive:
                tar_names = archive.getnames()
            with zipfile.ZipFile(first[1]) as archive:
                zip_names = archive.namelist()

            self.assertTrue(
                all(
                    name == "trustgate-0.1.0"
                    or name.startswith("trustgate-0.1.0/")
                    for name in tar_names
                )
            )
            self.assertTrue(
                all(name.startswith("trustgate-0.1.0/") for name in zip_names)
            )
            self.assertFalse(any("private-key.pem" in name for name in tar_names))
            self.assertFalse(any("private-key.pem" in name for name in zip_names))

    def test_rejects_a_tag_that_does_not_match_both_version_sources(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._repository(root)

            with self.assertRaisesRegex(ReleaseError, "release tag v0.2.0"):
                build_release_archives(
                    repository=root,
                    output_directory=root / "release",
                    ref="v0.1.0",
                    expected_tag="v0.2.0",
                )

    def test_generates_a_sorted_sha256_manifest_for_every_archive(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            archive_b = root / "trustgate-0.1.0.zip"
            archive_a = root / "trustgate-0.1.0.tar.gz"
            archive_b.write_bytes(b"zip")
            archive_a.write_bytes(b"tar")

            manifest = generate_checksums(
                [archive_b, archive_a],
                root / "SHA256SUMS",
            )

            lines = manifest.read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                lines,
                [
                    f"{hashlib.sha256(b'tar').hexdigest()}  {archive_a.name}",
                    f"{hashlib.sha256(b'zip').hexdigest()}  {archive_b.name}",
                ],
            )

    def test_rejects_symlinked_release_inputs(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "outside.tar.gz"
            target.write_bytes(b"unexpected")
            link = root / "trustgate-0.1.0.tar.gz"
            link.symlink_to(target)

            with self.assertRaisesRegex(ReleaseError, "regular file"):
                generate_checksums([link], root / "SHA256SUMS")

    def test_generates_a_deterministic_cyclonedx_sbom_for_the_product(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._repository(root)
            first = generate_cyclonedx_sbom(
                repository=root,
                output=root / "first" / "trustgate-v0.1.0.cdx.json",
                ref="v0.1.0",
                expected_tag="v0.1.0",
            )
            second = generate_cyclonedx_sbom(
                repository=root,
                output=root / "second" / "trustgate-v0.1.0.cdx.json",
                ref="v0.1.0",
                expected_tag="v0.1.0",
            )

            self.assertEqual(first.read_bytes(), second.read_bytes())
            sbom = json.loads(first.read_text(encoding="utf-8"))
            self.assertEqual(sbom["bomFormat"], "CycloneDX")
            self.assertEqual(sbom["specVersion"], "1.6")
            self.assertRegex(sbom["serialNumber"], r"^urn:uuid:")
            self.assertEqual(
                sbom["metadata"]["component"]["purl"],
                "pkg:pypi/trustgate@0.1.0",
            )
            self.assertEqual(
                [component["purl"] for component in sbom["components"]],
                [
                    "pkg:pypi/cffi@2.1.0",
                    "pkg:pypi/cryptography@49.0.0",
                    "pkg:pypi/pycparser@3.0",
                ],
            )
            root_dependency = sbom["dependencies"][0]
            self.assertEqual(root_dependency["ref"], "pkg:pypi/trustgate@0.1.0")
            self.assertEqual(
                root_dependency["dependsOn"],
                ["pkg:pypi/cryptography@49.0.0"],
            )
            commit = subprocess.run(
                ["git", "rev-parse", "v0.1.0^{commit}"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            properties = {
                item["name"]: item["value"]
                for item in sbom["metadata"]["properties"]
            }
            self.assertEqual(properties["trustgate:git:commit"], commit)
            self.assertEqual(properties["trustgate:git:tag"], "v0.1.0")

    def test_sbom_rejects_a_direct_dependency_missing_from_the_lock(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._repository(root)
            requirements = root / "requirements" / "runtime.in"
            requirements.write_text(
                "cryptography==49.0.0\nmissing==1.0.0\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", str(requirements)], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "break lock"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "tag", "-f", "v0.1.0"],
                cwd=root,
                check=True,
                capture_output=True,
            )

            with self.assertRaisesRegex(ReleaseError, "missing from runtime.lock"):
                generate_cyclonedx_sbom(
                    repository=root,
                    output=root / "trustgate-v0.1.0.cdx.json",
                    ref="v0.1.0",
                    expected_tag="v0.1.0",
                )

    @patch("trustgate.supply_chain.release.subprocess.run")
    def test_signs_every_archive_and_the_checksum_manifest(
        self,
        run: unittest.mock.Mock,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = [
                root / "trustgate-0.1.0.tar.gz",
                root / "trustgate-0.1.0.zip",
                root / "SHA256SUMS",
            ]
            for artifact in artifacts:
                artifact.write_bytes(b"release")

            def create_bundle(command: list[str], **_: object) -> None:
                Path(command[4]).write_text("{}\n", encoding="utf-8")

            run.side_effect = create_bundle
            bundles = sign_release_artifacts(artifacts, cosign="cosign")

            self.assertEqual(
                [bundle.name for bundle in bundles],
                [
                    "trustgate-0.1.0.tar.gz.sigstore.json",
                    "trustgate-0.1.0.zip.sigstore.json",
                    "SHA256SUMS.sigstore.json",
                ],
            )
            self.assertEqual(run.call_count, 3)
            for artifact, call in zip(artifacts, run.call_args_list, strict=True):
                artifact = artifact.resolve()
                self.assertEqual(
                    call.args[0],
                    [
                        "cosign",
                        "sign-blob",
                        "--yes",
                        "--bundle",
                        str(artifact.with_name(f"{artifact.name}.sigstore.json")),
                        str(artifact),
                    ],
                )
                self.assertTrue(call.kwargs["check"])


if __name__ == "__main__":
    unittest.main()
