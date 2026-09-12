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
    def test_repository_release_profile_is_v1_contract_but_not_yet_production_eligible(self) -> None:
        result = validate_release.validate_release()
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
        self.assertFalse(profile["production_release_allowed"])
        with self.assertRaises(validate_release.ReleaseValidationError):
            validate_release.validate_release(require_production=True)

    def test_security_closeout_can_flip_only_final_eligibility_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = validate_release.load_profile()
            profile["production_release_allowed"] = True
            profile_path = Path(directory) / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            result = validate_release.validate_release(
                profile_path=profile_path,
                require_production=True,
            )
            self.assertTrue(result["profile"]["production_release_allowed"])

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
            merged = root / "merged.bin"
            merged.write_bytes(b"\xff" * (int(profile["auth_nvs_offset"]) + 1))
            with self.assertRaises(validate_release.ReleaseValidationError):
                package_firmware.package_firmware(merged, root / "out", "abcdef123456")

    def test_package_metadata_is_secret_free_and_one_image_drives_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            merged = root / "merged.bin"
            merged.write_bytes(b"\xe9" + b"\x00" * 4095)
            outputs = package_firmware.package_firmware(merged, root / "out", "abcdef123456")
            names = {path.name for path in outputs}
            self.assertIn("factory-manifest.json", names)
            self.assertIn("update-manifest.json", names)
            self.assertIn("SHA256SUMS", names)
            self.assertFalse(any(name.endswith("-m5burner.zip") for name in names))

            factory = json.loads((root / "out" / "factory-manifest.json").read_text())
            update = json.loads((root / "out" / "update-manifest.json").read_text())
            self.assertFalse(factory["new_install_prompt_erase"])
            self.assertTrue(update["new_install_prompt_erase"])
            self.assertEqual(factory["builds"][0]["parts"], update["builds"][0]["parts"])
            self.assertEqual(factory["builds"][0]["parts"][0]["offset"], 0)

            firmware_name = factory["builds"][0]["parts"][0]["path"]
            self.assertTrue((root / "out" / firmware_name).is_file())

            metadata = json.loads((root / "out" / "release-metadata.json").read_text())
            self.assertEqual(metadata["format"], 2)
            self.assertEqual(metadata["protocol_version"], 2)
            self.assertEqual(metadata["storage_schema_version"], 2)
            self.assertEqual(metadata["vault_format_version"], 1)
            self.assertEqual(metadata["security_profile"], validate_release.V1_SECURITY_PROFILE)
            self.assertEqual(metadata["security_profile_version"], 1)
            self.assertEqual(metadata["vmk_persistence"], "ram-only")
            self.assertEqual(metadata["post_update_state"], "locked")
            self.assertFalse(metadata["production_release_allowed"])
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
