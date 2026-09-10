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
    def test_repository_release_profile_is_hmac_but_not_yet_production(self) -> None:
        result = validate_release.validate_release()
        self.assertEqual(result["profile"]["security_backend"], "hmac-efuse")
        self.assertFalse(result["profile"]["production_security_validated"])
        self.assertFalse(result["profile"]["production_release_allowed"])
        with self.assertRaises(validate_release.ReleaseValidationError):
            validate_release.validate_release(require_production=True)

    def test_release_rejects_unvalidated_hmac_profile_even_if_allowed_flag_is_flipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = validate_release.load_profile()
            profile["production_release_allowed"] = True
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            with self.assertRaises(validate_release.ReleaseValidationError):
                validate_release.validate_release(profile_path=profile_path)

    def test_development_backend_can_never_be_marked_production_eligible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = validate_release.load_profile()
            profile["security_backend"] = "development-synthetic"
            profile["production_security_validated"] = False
            profile["production_release_allowed"] = True
            profile.pop("hmac_efuse_key_id", None)
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")

            sdkconfig = validate_release.DEFAULT_SDKCONFIG.read_text(encoding="utf-8")
            sdkconfig = sdkconfig.replace(
                "CONFIG_M5AUTH_SECURITY_BACKEND_PRODUCTION=y\n# CONFIG_M5AUTH_SECURITY_BACKEND_DEV is not set\nCONFIG_M5AUTH_HMAC_KEY_ID=0\n",
                "# CONFIG_M5AUTH_SECURITY_BACKEND_PRODUCTION is not set\nCONFIG_M5AUTH_SECURITY_BACKEND_DEV=y\n",
            )
            sdkconfig_path = root / "sdkconfig.defaults"
            sdkconfig_path.write_text(sdkconfig, encoding="utf-8")

            with self.assertRaises(validate_release.ReleaseValidationError):
                validate_release.validate_release(
                    profile_path=profile_path,
                    sdkconfig_path=sdkconfig_path,
                )

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
            self.assertFalse(metadata["production_release_allowed"])
            serialized = json.dumps(metadata).lower()
            self.assertNotIn("totp_secret", serialized)
            self.assertNotIn("wifi_password", serialized)

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
