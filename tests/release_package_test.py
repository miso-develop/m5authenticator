#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
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

    def test_product_version_sources_are_exactly_1_0_0(self) -> None:
        result = validate_release.validate_release(require_production=True)
        self.assertEqual(result["project_version"], "1.0.0")
        self.assertEqual(result["metadata"]["firmware_version"], "1.0.0")
        self.assertEqual(result["profile"]["firmware_version"], "1.0.0")

    def test_remaining_0_1_0_literals_are_only_classified_noncanonical_values(self) -> None:
        legacy_version = "0." + "1.0"
        private_npm_metadata = {
            "web/package.json",
            "web/package-lock.json",
        }
        historical_compatibility_references = {
            "firmware/components/m5auth_vault/include/m5auth/vault.hpp",
            "tests/vault_interop_test.cpp",
        }

        completed = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO_ROOT,
            check=True,
            stdout=subprocess.PIPE,
        )
        classified: dict[str, list[str]] = {
            "private npm package metadata": [],
            "test/smoke fixture": [],
            "historical compatibility reference": [],
        }
        unexpected: list[str] = []

        for raw_path in completed.stdout.split(b"\0"):
            if not raw_path:
                continue
            relative = raw_path.decode("utf-8")
            path = REPO_ROOT / relative
            try:
                source = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            for line_number, line in enumerate(source.splitlines(), start=1):
                if legacy_version not in line:
                    continue
                evidence = f"{relative}:{line_number}: {line.strip()}"

                if relative in private_npm_metadata:
                    classified["private npm package metadata"].append(evidence)
                    continue

                if relative in historical_compatibility_references:
                    self.assertIn("v" + legacy_version, line)
                    self.assertTrue(line.lstrip().startswith("//"))
                    classified["historical compatibility reference"].append(evidence)
                    continue

                is_web_unit_fixture = relative.startswith("web/src/") and relative.endswith(".test.ts")
                is_browser_smoke_fixture = relative.startswith("web/tests/browser/") and relative.endswith(".ts")
                if relative == "web/vite.config.ts" or is_web_unit_fixture or is_browser_smoke_fixture:
                    classified["test/smoke fixture"].append(evidence)
                    continue

                unexpected.append(evidence)

        self.assertFalse(
            unexpected,
            "unexpected current legacy version literal outside classified noncanonical sources:\n"
            + "\n".join(unexpected),
        )
        self.assertTrue(classified["private npm package metadata"])
        self.assertTrue(classified["test/smoke fixture"])
        self.assertTrue(classified["historical compatibility reference"])

        canonical_sources = {
            "firmware/CMakeLists.txt",
            "firmware/components/m5auth_core/include/m5auth/core/metadata.hpp",
            "firmware/release-profile.json",
        }
        all_classified = "\n".join(item for values in classified.values() for item in values)
        for canonical in canonical_sources:
            self.assertNotIn(canonical + ":", all_classified)

    def test_release_version_consistency_rejects_each_source_divergence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            cmake_path = root / "CMakeLists.txt"
            cmake_path.write_text(
                validate_release.DEFAULT_PROJECT_CMAKE.read_text(encoding="utf-8").replace(
                    "VERSION 1.0.0",
                    "VERSION 9.9.9",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                validate_release.ReleaseValidationError,
                "CMake project version does not match firmware metadata",
            ):
                validate_release.validate_release(project_cmake_path=cmake_path)

            metadata_path = root / "metadata.hpp"
            metadata_path.write_text(
                validate_release.DEFAULT_METADATA.read_text(encoding="utf-8").replace(
                    'kFirmwareVersion[] = "1.0.0"',
                    'kFirmwareVersion[] = "9.9.9"',
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                validate_release.ReleaseValidationError,
                "firmware_version does not match firmware metadata",
            ):
                validate_release.validate_release(metadata_path=metadata_path)

            profile = validate_release.load_profile()
            profile["firmware_version"] = "9.9.9"
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            with self.assertRaisesRegex(
                validate_release.ReleaseValidationError,
                "firmware_version does not match firmware metadata",
            ):
                validate_release.validate_release(profile_path=profile_path)

    def test_cmake_product_version_parser_rejects_missing_or_malformed_version(self) -> None:
        invalid_sources = (
            "cmake_minimum_required(VERSION 3.16)\nproject(m5authenticator)\n",
            "cmake_minimum_required(VERSION 3.16)\nproject(m5authenticator VERSION 1.0)\n",
            "cmake_minimum_required(VERSION 3.16)\nproject(m5authenticator VERSION 1.0.0.1)\n",
            "cmake_minimum_required(VERSION 3.16)\nproject(m5authenticator VERSION 1.0.0-beta)\n",
            "cmake_minimum_required(VERSION 3.16)\nproject(other VERSION 1.0.0)\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, source in enumerate(invalid_sources):
                with self.subTest(source=source):
                    cmake_path = root / f"CMakeLists-{index}.txt"
                    cmake_path.write_text(source, encoding="utf-8")
                    with self.assertRaises(validate_release.ReleaseValidationError):
                        validate_release.parse_cmake_project_version(cmake_path)

    def test_non_x_y_z_cmake_version_fails_both_validation_paths(self) -> None:
        invalid_versions = ("1.0.0.1", "1.0.0-beta")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for version in invalid_versions:
                cmake_path = root / ("CMakeLists-" + version.replace(".", "_") + ".txt")
                cmake_path.write_text(
                    f"cmake_minimum_required(VERSION 3.16)\n"
                    f"project(m5authenticator VERSION {version})\n",
                    encoding="utf-8",
                )
                for require_production in (False, True):
                    with self.subTest(version=version, require_production=require_production):
                        with self.assertRaisesRegex(
                            validate_release.ReleaseValidationError,
                            "VERSION must be exactly X.Y.Z",
                        ):
                            validate_release.validate_release(
                                project_cmake_path=cmake_path,
                                require_production=require_production,
                            )

    def test_inactive_cmake_project_examples_cannot_mask_active_version(self) -> None:
        cases = (
            (
                "# project(m5authenticator VERSION 1.0.0)\n"
                "project(m5authenticator VERSION 1.0.0.1)\n",
                "VERSION must be exactly X.Y.Z",
            ),
            (
                "# project(m5authenticator VERSION 1.0.0)\n"
                "project(m5authenticator VERSION 9.9.9)\n",
                "CMake project version does not match firmware metadata",
            ),
            (
                'set(EXAMPLE "project(m5authenticator VERSION 1.0.0)")\n'
                "project(m5authenticator VERSION 9.9.9)\n",
                "CMake project version does not match firmware metadata",
            ),
            (
                "#[[\n"
                "project(m5authenticator VERSION 1.0.0)\n"
                "]]\n"
                "project(m5authenticator VERSION 9.9.9)\n",
                "CMake project version does not match firmware metadata",
            ),
            (
                "set(EXAMPLE [[project(m5authenticator VERSION 1.0.0)]])\n"
                "project(m5authenticator VERSION 9.9.9)\n",
                "CMake project version does not match firmware metadata",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (source, expected_error) in enumerate(cases):
                cmake_path = root / f"CMakeLists-mask-{index}.txt"
                cmake_path.write_text(source, encoding="utf-8")
                for require_production in (False, True):
                    with self.subTest(
                        source=source,
                        require_production=require_production,
                    ):
                        with self.assertRaisesRegex(
                            validate_release.ReleaseValidationError,
                            expected_error,
                        ):
                            validate_release.validate_release(
                                project_cmake_path=cmake_path,
                                require_production=require_production,
                            )

    def test_production_validation_fails_closed_when_eligibility_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = validate_release.load_profile()
            profile["production_release_allowed"] = False
            profile_path = Path(directory) / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            with self.assertRaises(validate_release.ReleaseValidationError):
                validate_release.validate_release(profile_path=profile_path, require_production=True)

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
                package_firmware.package_firmware(merged, bootloader, partition_table, app, root / "out", "abcdef123456")

    def test_package_rejects_non_commit_build_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            merged, bootloader, partition_table, app = self.make_test_binaries(root)
            with self.assertRaises(validate_release.ReleaseValidationError):
                package_firmware.package_firmware(merged, bootloader, partition_table, app, root / "out", "web-current")

    def test_normal_update_rejects_partition_table_that_overlaps_nvs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            merged, bootloader, partition_table, app = self.make_test_binaries(root)
            partition_table.write_bytes(b"\xaa" * 0x1001)
            with self.assertRaises(validate_release.ReleaseValidationError):
                package_firmware.package_firmware(merged, bootloader, partition_table, app, root / "out", "abcdef123456")

    def test_normal_update_rejects_app_that_exceeds_ota0(self) -> None:
        partitions = validate_release.validate_release()["partitions"]
        ota0_size = int(partitions["ota_0"]["size"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            merged, bootloader, partition_table, app = self.make_test_binaries(root)
            app.write_bytes(b"\xe9" + b"\x00" * ota0_size)
            with self.assertRaises(validate_release.ReleaseValidationError):
                package_firmware.package_firmware(merged, bootloader, partition_table, app, root / "out", "abcdef123456")

    def test_package_metadata_is_secret_free_and_update_is_partition_aware(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = self.package_test_binaries(root)
            names = {path.name for path in outputs}
            self.assertIn("factory-manifest.json", names)
            self.assertIn("update-manifest.json", names)
            self.assertIn("factory-manifest-abcdef123456.json", names)
            self.assertIn("update-manifest-abcdef123456.json", names)
            self.assertIn("firmware-target.json", names)
            self.assertIn("SHA256SUMS", names)
            self.assertIn("m5authenticator-v1.0.0-abcdef123456-m5sticks3.bin", names)
            self.assertIn("m5authenticator-v1.0.0-abcdef123456-m5sticks3-update-bootloader.bin", names)
            self.assertIn("m5authenticator-v1.0.0-abcdef123456-m5sticks3-update-partition-table.bin", names)
            self.assertIn("m5authenticator-v1.0.0-abcdef123456-m5sticks3-update-ota0.bin", names)
            self.assertFalse(any(name.endswith("-m5burner.zip") for name in names))

            factory = json.loads((root / "out" / "factory-manifest.json").read_text())
            update = json.loads((root / "out" / "update-manifest.json").read_text())
            pinned_factory = json.loads((root / "out" / "factory-manifest-abcdef123456.json").read_text())
            pinned_update = json.loads((root / "out" / "update-manifest-abcdef123456.json").read_text())
            target = json.loads((root / "out" / "firmware-target.json").read_text())

            self.assertEqual(factory, pinned_factory)
            self.assertEqual(update, pinned_update)
            self.assertFalse(factory["new_install_prompt_erase"])
            self.assertTrue(update["new_install_prompt_erase"])
            self.assertEqual(factory["name"], "M5Authenticator")
            self.assertEqual(update["name"], "M5Authenticator")
            self.assertEqual(factory["version"], update["version"])
            self.assertEqual(factory["version"], "1.0.0")
            self.assertEqual(update["version"], "1.0.0")
            self.assertEqual(target["version"], "1.0.0")
            self.assertEqual(factory["build_commit"], "abcdef123456")
            self.assertEqual(update["build_commit"], "abcdef123456")
            self.assertFalse(factory["exact_release"])
            self.assertFalse(update["exact_release"])
            self.assertEqual(target["build_commit"], "abcdef123456")
            self.assertEqual(target["factory_manifest"], "factory-manifest-abcdef123456.json")
            self.assertEqual(target["update_manifest"], "update-manifest-abcdef123456.json")

            factory_parts = factory["builds"][0]["parts"]
            self.assertEqual(len(factory_parts), 1)
            self.assertEqual(factory_parts[0]["offset"], 0)
            self.assertIn("abcdef123456", factory_parts[0]["path"])
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
                self.assertIn("abcdef123456", part["path"])
                self.assertTrue((root / "out" / part["path"]).is_file())
            self.assertNotEqual(factory_parts, update_parts)

            metadata = json.loads((root / "out" / "release-metadata.json").read_text())
            self.assertEqual(metadata["format"], 2)
            self.assertEqual(metadata["firmware_version"], "1.0.0")
            self.assertEqual(metadata["protocol_version"], 2)
            self.assertEqual(metadata["storage_schema_version"], 2)
            self.assertEqual(metadata["vault_format_version"], 1)
            self.assertEqual(metadata["security_profile"], validate_release.V1_SECURITY_PROFILE)
            self.assertEqual(metadata["security_profile_version"], 1)
            self.assertEqual(metadata["vmk_persistence"], "ram-only")
            self.assertEqual(metadata["post_update_state"], "locked")
            self.assertEqual(metadata["build_commit"], "abcdef123456")
            self.assertFalse(metadata["exact_release"])
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

    def test_exact_release_provenance_is_consistent_across_package_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            merged, bootloader, partition_table, app = self.make_test_binaries(root)
            commit = "1234567890abcdef"
            package_firmware.package_firmware(
                merged,
                bootloader,
                partition_table,
                app,
                root / "out",
                commit,
                exact_release=True,
            )
            for filename in (
                "factory-manifest.json",
                "update-manifest.json",
                f"factory-manifest-{commit}.json",
                f"update-manifest-{commit}.json",
                "firmware-target.json",
                "release-metadata.json",
            ):
                value = json.loads((root / "out" / filename).read_text())
                self.assertEqual(value["build_commit"], commit)
                self.assertTrue(value["exact_release"])

    def test_release_workflow_has_no_project_efuse_or_universal_key_dependency(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "release-authorized.yml").read_text(encoding="utf-8").lower()
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
                validate_release.validate_release(profile_path=profile_path, partitions_path=partitions_path)


if __name__ == "__main__":
    unittest.main()
