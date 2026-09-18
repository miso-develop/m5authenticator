from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import ci_esp_idf_isolated_build
import ci_firmware_handoff
import esp_idf_build_image


WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE_WORKFLOW = WORKFLOWS / "release.yml"
FOUNDATION_WORKFLOW = WORKFLOWS / "foundation.yml"
PAGES_WORKFLOW = WORKFLOWS / "pages.yml"
SECURITY_WORKFLOW = WORKFLOWS / "security.yml"
UPLOAD_ARTIFACT_SHA = "ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD_ARTIFACT_SHA = "d3f86a106a0bac45b974a628896c90dbdf5c8093"
ATTEST_ACTION_SHA = "1e69f48acb82d1966a394da916b4c1698aa569d6"


def job_block(workflow_text: str, job_id: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_id)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow_text,
    )
    if not match:
        raise AssertionError(f"job not found: {job_id}")
    return match.group(0)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CiSupplyChainBoundaryTest(unittest.TestCase):
    def test_isolated_build_copy_is_outside_authoritative_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "checkout"
            firmware = source / "firmware"
            firmware.mkdir(parents=True)
            (firmware / "dependencies.lock").write_text("locked\n", encoding="utf-8")
            (firmware / "source.txt").write_text("trusted\n", encoding="utf-8")
            work = base / "runner-temp" / "build"

            isolated = ci_esp_idf_isolated_build.prepare_isolated_firmware(source, work)
            self.assertNotEqual(isolated, firmware)
            self.assertFalse(source in isolated.parents)
            (isolated / "source.txt").write_text("container mutation\n", encoding="utf-8")
            self.assertEqual((firmware / "source.txt").read_text(encoding="utf-8"), "trusted\n")

    def test_docker_command_mounts_only_isolated_firmware_with_exact_image(self) -> None:
        isolated = Path("/tmp/m5auth-isolated/firmware")
        command = ci_esp_idf_isolated_build.docker_command(
            isolated,
            esp_idf_build_image.ESP_IDF_IMAGE_REFERENCE,
        )
        joined = " ".join(command)
        self.assertIn(str(isolated.resolve()), joined)
        self.assertIn("target=/project/firmware", joined)
        self.assertIn(esp_idf_build_image.ESP_IDF_IMAGE_REFERENCE, command)
        self.assertNotIn("GITHUB_WORKSPACE", joined)
        with self.assertRaises(ValueError):
            ci_esp_idf_isolated_build.docker_command(isolated, "espressif/idf:v5.5.5")

    def test_container_controlled_symlinks_are_rejected_before_host_io(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            isolated_firmware = base / "isolated-firmware"
            build = isolated_firmware / "build"
            (build / "bootloader").mkdir(parents=True)
            (build / "partition_table").mkdir(parents=True)
            regular_outputs = (
                (build / "m5authenticator-merged.bin", b"merged"),
                (build / "bootloader" / "bootloader.bin", b"bootloader"),
                (build / "partition_table" / "partition-table.bin", b"partitions"),
                (build / "m5authenticator.bin", b"app"),
            )
            for path, payload in regular_outputs:
                path.write_bytes(payload)
            (isolated_firmware / "dependencies.lock").write_text("locked\n", encoding="utf-8")

            outside_file = base / "outside-secret.txt"
            outside_file.write_text("must-not-be-read-or-copied\n", encoding="utf-8")
            merged = build / "m5authenticator-merged.bin"
            merged.unlink()
            merged.symlink_to(outside_file)
            artifact = base / "artifact"

            with mock.patch.object(
                ci_firmware_handoff.shutil,
                "copyfile",
                side_effect=AssertionError("copy must not run for rejected inputs"),
            ) as copyfile:
                with self.assertRaises(ValueError):
                    ci_firmware_handoff.create_build_handoff(
                        build,
                        isolated_firmware,
                        artifact,
                        "a" * 40,
                    )
                copyfile.assert_not_called()
            self.assertFalse(artifact.exists())

            merged.unlink()
            merged.write_bytes(b"merged")
            isolated_lock = isolated_firmware / "dependencies.lock"
            isolated_lock.unlink()
            isolated_lock.symlink_to(outside_file)
            authoritative_firmware = base / "authoritative" / "firmware"
            authoritative_firmware.mkdir(parents=True)
            (authoritative_firmware / "dependencies.lock").write_text("locked\n", encoding="utf-8")

            with mock.patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("read must not run for rejected lock symlink"),
            ) as read_bytes:
                with self.assertRaises(ValueError):
                    ci_esp_idf_isolated_build.verify_dependency_lock(
                        authoritative_firmware,
                        isolated_firmware,
                    )
                read_bytes.assert_not_called()

    def test_untrusted_path_guard_rejects_parent_symlink_non_regular_and_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            isolated = base / "isolated"
            isolated.mkdir()
            outside = base / "outside"
            outside.mkdir()
            outside_file = outside / "m5authenticator.bin"
            outside_file.write_bytes(b"outside")

            (isolated / "build").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                ci_esp_idf_isolated_build.require_contained_regular_file(
                    isolated,
                    isolated / "build" / "m5authenticator.bin",
                )
            with self.assertRaises(ValueError):
                ci_esp_idf_isolated_build.require_contained_regular_file(
                    isolated,
                    outside_file,
                )

            directory_candidate = isolated / "directory-not-file"
            directory_candidate.mkdir()
            with self.assertRaises(ValueError):
                ci_esp_idf_isolated_build.require_contained_regular_file(
                    isolated,
                    directory_candidate,
                )

    def test_build_handoff_detects_artifact_or_lock_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            isolated_firmware = base / "isolated-firmware"
            build = isolated_firmware / "build"
            (build / "bootloader").mkdir(parents=True)
            (build / "partition_table").mkdir(parents=True)
            for path, payload in (
                (build / "m5authenticator-merged.bin", b"merged"),
                (build / "bootloader" / "bootloader.bin", b"bootloader"),
                (build / "partition_table" / "partition-table.bin", b"partitions"),
                (build / "m5authenticator.bin", b"app"),
            ):
                path.write_bytes(payload)
            expected_lock = base / "dependencies.lock"
            expected_lock.write_text("locked\n", encoding="utf-8")
            (isolated_firmware / "dependencies.lock").write_bytes(expected_lock.read_bytes())
            artifact = base / "artifact"
            commit = "a" * 40

            ci_firmware_handoff.create_build_handoff(build, isolated_firmware, artifact, commit)
            provenance = ci_firmware_handoff.verify_build_handoff(artifact, commit, expected_lock)
            self.assertEqual(provenance["esp_idf"], esp_idf_build_image.provenance())

            (artifact / "m5authenticator.bin").write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                ci_firmware_handoff.verify_build_handoff(artifact, commit, expected_lock)

    def test_release_package_verifier_binds_checksums_to_build_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            package = base / "release"
            package.mkdir()
            commit = "b" * 40
            payload = package / "firmware.bin"
            payload.write_bytes(b"firmware")
            metadata = {
                "build_commit": commit,
                "build_environment": {"esp_idf": esp_idf_build_image.provenance()},
            }
            (package / "release-metadata.json").write_text(
                json.dumps(metadata), encoding="utf-8"
            )
            checksums = {
                "firmware.bin": sha256(payload),
                "release-metadata.json": sha256(package / "release-metadata.json"),
            }
            (package / "SHA256SUMS").write_text(
                "".join(f"{digest}  {name}\n" for name, digest in checksums.items()),
                encoding="utf-8",
            )
            provenance_path = base / "build-provenance.json"
            provenance_path.write_text(
                json.dumps(
                    {
                        "format": 1,
                        "source_commit": commit,
                        "esp_idf": esp_idf_build_image.provenance(),
                        "files": [],
                    }
                ),
                encoding="utf-8",
            )

            checksum_manifest_digest = ci_firmware_handoff.verify_release_package(
                package, provenance_path, commit
            )
            self.assertEqual(checksum_manifest_digest, sha256(package / "SHA256SUMS"))
            payload.write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                ci_firmware_handoff.verify_release_package(package, provenance_path, commit)

    def test_release_authorize_build_verify_attest_publish_permissions_are_separated(self) -> None:
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        authorize = job_block(text, "authorize")
        build = job_block(text, "build")
        verify = job_block(text, "verify")
        attest = job_block(text, "attest")
        publish = job_block(text, "publish")
        cleanup = job_block(text, "cleanup")

        self.assertIn("contents: read", authorize)
        self.assertIn("checks: read", authorize)
        self.assertNotIn("contents: write", authorize)
        self.assertIn("needs: authorize", build)
        self.assertIn("contents: read", build)
        self.assertNotIn("contents: write", build)
        self.assertNotIn("id-token: write", build)
        self.assertNotIn("attestations: write", build)
        self.assertIn("contents: read", verify)
        self.assertNotIn("contents: write", verify)
        self.assertNotIn("id-token: write", verify)
        self.assertIn("id-token: write", attest)
        self.assertIn("attestations: write", attest)
        self.assertIn("artifact-metadata: write", attest)
        self.assertNotIn("contents: write", attest)
        self.assertNotIn("docker run", attest)
        self.assertIn("needs: [verify, attest]", publish)
        self.assertIn("contents: write", publish)
        self.assertNotIn("id-token: write", publish)
        self.assertNotIn("attestations: write", publish)
        self.assertNotIn("docker run", publish)
        self.assertNotIn("ci_esp_idf_isolated_build.py", publish)
        self.assertIn("actions: write", cleanup)
        self.assertNotIn("contents: write", cleanup)

    def test_release_authorization_is_exact_main_and_exact_sha_security_check(self) -> None:
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        authorize = job_block(text, "authorize")

        self.assertIn("git fetch --no-tags origin main", authorize)
        self.assertIn("git rev-parse refs/remotes/origin/main", authorize)
        self.assertIn("/commits/$GITHUB_SHA/check-runs?filter=latest&per_page=100", authorize)
        self.assertIn("scripts/release_authorization.py", authorize)
        self.assertIn('--source-sha "$GITHUB_SHA"', authorize)
        self.assertIn('--main-sha "$MAIN_SHA"', authorize)
        self.assertIn("scripts/validate_release.py --require-production", authorize)
        self.assertIn("Verify tag matches firmware version", authorize)
        self.assertNotIn("--verify-tag", authorize)

    def test_release_attests_same_verified_artifact_before_publish(self) -> None:
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        attest = job_block(text, "attest")
        publish = job_block(text, "publish")

        action_ref = f"actions/attest@{ATTEST_ACTION_SHA}"
        self.assertEqual(attest.count(action_ref), 2)
        self.assertIn("scripts/release_attestation.py", attest)
        self.assertIn(
            "predicate-type: https://miso-develop.github.io/m5authenticator/attestations/release-provenance/v1",
            attest,
        )
        self.assertIn("subject-path: ${{ runner.temp }}/m5auth-release/*", attest)
        self.assertIn("artifact-ids: ${{ needs.verify.outputs.artifact-id }}", attest)
        self.assertIn("artifact-ids: ${{ needs.verify.outputs.artifact-id }}", publish)
        self.assertIn("EXPECTED_SHA256SUMS", attest)
        self.assertIn("sha256sum -c SHA256SUMS", attest)
        self.assertIn("EXPECTED_SHA256SUMS", publish)
        self.assertIn("sha256sum -c SHA256SUMS", publish)

    def test_release_uses_bounded_provenance_handoffs_and_exact_verified_bytes(self) -> None:
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        build = job_block(text, "build")
        verify = job_block(text, "verify")
        publish = job_block(text, "publish")

        self.assertIn(f"actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}", build)
        self.assertIn("retention-days: 1", build)
        self.assertIn("ci_firmware_handoff.py create-build", build)
        self.assertIn(f"actions/download-artifact@{DOWNLOAD_ARTIFACT_SHA}", verify)
        self.assertIn("ci_firmware_handoff.py verify-build", verify)
        self.assertIn("verify_firmware_image.py", verify)
        self.assertIn("package_firmware.py", verify)
        self.assertIn("ci_firmware_handoff.py verify-release-package", verify)
        self.assertIn(f"actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}", verify)
        self.assertIn("retention-days: 1", verify)
        self.assertIn(f"actions/download-artifact@{DOWNLOAD_ARTIFACT_SHA}", publish)
        self.assertIn("EXPECTED_SHA256SUMS", publish)
        self.assertIn("sha256sum -c SHA256SUMS", publish)
        self.assertIn("gh release create", publish)

    def test_foundation_pages_release_do_not_mount_authoritative_checkout(self) -> None:
        for path in (FOUNDATION_WORKFLOW, PAGES_WORKFLOW, RELEASE_WORKFLOW):
            text = path.read_text(encoding="utf-8")
            with self.subTest(workflow=path.name):
                self.assertIn("scripts/ci_esp_idf_isolated_build.py", text)
                self.assertIn('ESP_IDF_IMAGE="$(python scripts/esp_idf_build_image.py --reference)"', text)
                self.assertNotIn('$GITHUB_WORKSPACE:/project', text)
                self.assertNotRegex(text, r"source=\$\{?GITHUB_WORKSPACE\}?")
                self.assertIn("git diff --exit-code", text)

    def test_security_workflow_runs_supply_chain_boundary_regression(self) -> None:
        text = SECURITY_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("tests/ci_supply_chain_boundary_test.py", text)


if __name__ == "__main__":
    unittest.main()
