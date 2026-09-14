#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import package_firmware
import validate_release


class ReleasePackagingTest(unittest.TestCase):
    def make_test_binaries(self, root: Path) -> tuple[Path, Path, Path, Path]:
        merged = root / "merged.bin"
        bootloader = root / "bootloader.bin"
        partition_table = root / "partition-table.bin"
        app = root / "m5authenticator.bin"
        merged.write_bytes(b"\xe9" + b"\x00" * 4095)
        bootloader.write_bytes(b"\xe9" + b"\x00" * 4095)
        partition_table.write_bytes(b"\xaa" * 3072)
        app.write_bytes(b"\xe9" + b"\x00" * 8191)
        return merged, bootloader, partition_table, app

    def package_test_binaries(self, root: Path, build_commit: str = "abcdef123456") -> list[Path]:
        merged, bootloader, partition_table, app = self.make_test_binaries(root)
        return package_firmware.package_firmware(
            merged,
            bootloader,
            partition_table,
            app,
            root / "out",
            build_commit,
        )

    def test_repository_release_profile_is_v1_contract_and_production_eligible(self) -> None:
        result = validate_release.validate_release(require_production=True)
        profile = result["profile"]
        self.assertEqual(profile["format"], 2)
        self.assertEqual(profile["protocol_version"], 2)
        self.assertEqual(profile["storage_schema_version"], 2)
        self.assertEqual(profile["vault_format_version"], 1)
        self.assertEqual(profile["security_profile"], validate_release.V1_SECURITY_PROFILE)
        self.assertEqual(profile["security_profile_version"], 1)
        self.assertEqual(profile["credential_flash_storage"], "encrypted-vault-only")
        self.assertEqual(profile["vmk_persistence"], "ram-only")
        self.assertIs(profile["public_synthetic_flash_key_allowed"], False)
        self.assertIs(profile["project_specific_efuse_required"], False)
        self.assertEqual(profile["post_update_state"], "locked")
        self.assertTrue(profile["production_release_allowed"])

    def test_production_validation_fails_closed_when_eligibility_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = validate_release.load_profile()
            profile["production_release_allowed"] = False
            profile_path = Path(directory) / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            with self.assertRaises(validate_release.ReleaseValidationError):
                validate_release.validate_release(
                    profile_path=profile_path,
                    require_production=True,
                )

    def test_release_contract_rejects_public_synthetic_flash_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = validate_release.load_profile()
            profile["public_synthetic_flash_key_allowed"] = True
            profile_path = Path(directory) / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            with self.assertRaises(validate_release.ReleaseValidationError):
                validate_release.validate_release(profile_path=profile_path)

    def test_release_contract_rejects_legacy_synthetic_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bootstrap = root / "app_main.cpp"
            source = validate_release.DEFAULT_BOOTSTRAP.read_text(encoding="utf-8")
            bootstrap.write_text(source + "\n// DevSecurityBackend must remain unreachable.\n", encoding="utf-8")
            with self.assertRaises(validate_release.ReleaseValidationError):
                validate_release.validate_release(bootstrap_path=bootstrap)

    def test_package_rejects_image_that_reaches_auth_partition(self) -> None:
        profile = validate_release.validate_release()["profile"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            merged, bootloader, partition_table, app = self.make_test_binaries(root)
            merged.write_bytes(b"\xff" * (int(profile["auth_nvs_offset"]) + 1))
            with self.assertRaises(validate_release.ReleaseValidationError):
                package_firmware.package_firmware(
                    merged,
                    bootloader,
                    partition_table,
                    app,
                    root / "out",
                    "abcdef123456",
                )

    def test_normal_update_rejects_partition_table_that_overlaps_nvs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            merged, bootloader, partition_table, app = self.make_test_binaries(root)
            partition_table.write_bytes(b"\xaa" * 0x1001)
            with self.assertRaises(validate_release.ReleaseValidationError):
                package_firmware.package_firmware(
                    merged,
                    bootloader,
                    partition_table,
                    app,
                    root / "out",
                    "abcdef123456",
                )

    def test_normal_update_rejects_app_that_exceeds_ota0(self) -> None:
        partitions = validate_release.validate_release()["partitions"]
        ota0_size = int(partitions["ota_0"]["size"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            merged, bootloader, partition_table, app = self.make_test_binaries(root)
            app.write_bytes(b"\xe9" + b"\x00" * ota0_size)
            with self.assertRaises(validate_release.ReleaseValidationError):
                package_firmware.package_firmware(
                    merged,
                    bootloader,
                    partition_table,
                    app,
                    root / "out",
                    "abcdef123456",
                )

    def test_package_metadata_is_secret_free_and_update_is_partition_aware(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = self.package_test_binaries(root)
            names = {path.name for path in outputs}
            self.assertIn("factory-manifest.json", names)
            self.assertIn("update-manifest.json", names)
            self.assertIn("SHA256SUMS", names)
            self.assertFalse(any(name.endswith("-m5burner.zip") for name in names))

            factory = json.loads((root / "out" / "factory-manifest.json").read_text())
            update = json.loads((root / "out" / "update-manifest.json").read_text())
            self.assertFalse(factory["new_install_prompt_erase"])
            self.assertTrue(update["new_install_prompt_erase"])

            factory_parts = factory["builds"][0]["parts"]
            self.assertEqual(len(factory_parts), 1)
            self.assertEqual(factory_parts[0]["offset"], 0)
            self.assertTrue((root / "out" / factory_parts[0]["path"]).is_file())

            update_parts = update["builds"][0]["parts"]
            self.assertEqual(
                [part["offset"] for part in update_parts],
                [
                    package_firmware.UPDATE_BOOTLOADER_OFFSET,
                    package_firmware.UPDATE_PARTITION_TABLE_OFFSET,
                    package_firmware.UPDATE_APP_OFFSET,
                ],
            )
            self.assertEqual(len({part["path"] for part in update_parts}), 3)
            for part in update_parts:
                self.assertTrue((root / "out" / part["path"]).is_file())
            self.assertNotEqual(factory_parts, update_parts)

            metadata = json.loads((root / "out" / "release-metadata.json").read_text())
            self.assertEqual(metadata["format"], 2)
            self.assertEqual(metadata["protocol_version"], 2)
            self.assertEqual(metadata["storage_schema_version"], 2)
            self.assertEqual(metadata["vault_format_version"], 1)
            self.assertEqual(metadata["security_profile"], validate_release.V1_SECURITY_PROFILE)
            self.assertEqual(metadata["security_profile_version"], 1)
            self.assertEqual(metadata["vmk_persistence"], "ram-only")
            self.assertEqual(metadata["post_update_state"], "locked")
            self.assertTrue(metadata["production_release_allowed"])
            self.assertFalse(metadata["normal_update"]["erase_first"])
            self.assertEqual(metadata["normal_update"]["required_preserve_partitions"], ["nvs", "auth_nvs"])
            self.assertIn("nvs", metadata["normal_update"]["untouched_partitions"])
            self.assertIn("auth_nvs", metadata["normal_update"]["untouched_partitions"])
            self.assertIn("ota_1", metadata["normal_update"]["untouched_partitions"])
            self.assertNotIn("security_backend", metadata)
            serialized = json.dumps(metadata).lower()
            self.assertNotIn("totp_secret", serialized)
            self.assertNotIn("wifi_password", serialized)
            self.assertNotIn("devsecuritybackend", serialized)

    def test_release_workflow_has_no_project_efuse_or_universal_key_dependency(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8").lower()
        self.assertIn("--require-production", workflow)
        self.assertNotIn("efuse", workflow)
        self.assertNotIn("hmac", workflow)
        self.assertNotIn("development-synthetic", workflow)
        self.assertNotIn("universal production", workflow)

    def test_layout_validation_rejects_auth_partition_not_at_flash_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = validate_release.load_profile()
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            partitions = validate_release.DEFAULT_PARTITIONS.read_text(encoding="utf-8")
            partitions = partitions.replace("0x7d0000, 0x30000", "0x7c0000, 0x30000")
            partitions_path = root / "partitions.csv"
            partitions_path.write_text(partitions, encoding="utf-8")
            with self.assertRaises(validate_release.ReleaseValidationError):
                validate_release.validate_release(
                    profile_path=profile_path,
                    partitions_path=partitions_path,
                )


if __name__ == "__main__":
    unittest.main()
