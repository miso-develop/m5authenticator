from pathlib import Path
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import ci_pages_released_firmware
import ci_pages_summary
import validate_release


class PagesCandidateSummaryTests(unittest.TestCase):
    def test_candidate_authorization_summary_records_exact_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            ci_pages_summary.append_candidate_authorization_summary(
                summary,
                source_ref="refs/heads/main",
                source_sha="a" * 40,
                candidate_sha="a" * 40,
                current_main="a" * 40,
            )
            self.assertEqual(
                summary.read_text(encoding="utf-8"),
                "## PRE-RELEASE Pages candidate\n"
                "\n"
                "- source ref: `refs/heads/main`\n"
                f"- source SHA: `{'a' * 40}`\n"
                f"- candidate SHA: `{'a' * 40}`\n"
                f"- current main: `{'a' * 40}`\n"
                "- this deployment is a mutable public candidate, not an immutable GitHub Release\n",
            )

    def test_candidate_build_identity_records_non_exact_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            ci_pages_summary.append_candidate_build_identity(
                summary,
                version="1.0.0",
                build_commit="b" * 40,
                exact_release="false",
            )
            self.assertEqual(
                summary.read_text(encoding="utf-8"),
                "\n"
                "### Candidate build identity\n"
                "- Web/Firmware version: `v1.0.0`\n"
                f"- build commit: `{'b' * 40}`\n"
                "- exact release: `false`\n",
            )

    def test_cli_preserves_shell_metacharacters_as_literal_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = root / "summary.md"
            backtick_sentinel = root / "backtick-executed"
            dollar_sentinel = root / "dollar-executed"
            source_ref = (
                "refs/heads/main"
                f"`touch {backtick_sentinel}`"
                f"$(touch {dollar_sentinel})"
            )

            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "ci_pages_summary.py"),
                    "candidate-authorization",
                    "--summary-path",
                    str(summary),
                    "--source-ref",
                    source_ref,
                    "--source-sha",
                    "c" * 40,
                    "--candidate-sha",
                    "c" * 40,
                    "--current-main",
                    "c" * 40,
                ],
                cwd=REPO_ROOT,
                check=True,
            )

            rendered = summary.read_text(encoding="utf-8")
            self.assertIn("refs/heads/main", rendered)
            self.assertIn("$(touch ", rendered)
            self.assertIn("\\`touch ", rendered)
            self.assertFalse(backtick_sentinel.exists())
            self.assertFalse(dollar_sentinel.exists())




SOURCE_SHA = "a" * 40
WEB_SHA = "c" * 40
PUBLISHER_SHA = "b" * 40
CUSTOM_PREDICATE_TYPE = ci_pages_released_firmware.CUSTOM_PREDICATE_TYPE


def profile(version: str = "1.0.0") -> dict[str, object]:
    return {
        "format": 2,
        "device": "M5StickS3",
        "chip_family": "ESP32-S3",
        "flash_size_bytes": 8388608,
        "firmware_version": version,
        "protocol_version": 2,
        "storage_schema_version": 2,
        "vault_format_version": 1,
        "security_profile": "encrypted-vault-ram-only-vmk",
        "security_profile_version": 1,
        "credential_flash_storage": "encrypted-vault-only",
        "vmk_persistence": "ram-only",
        "public_synthetic_flash_key_allowed": False,
        "project_specific_efuse_required": False,
        "post_update_state": "locked",
        "production_release_allowed": True,
        "ota_0_offset": 196608,
        "ota_0_size": 3997696,
        "ota_1_offset": 4194304,
        "ota_1_size": 3997696,
        "auth_nvs_offset": 8192000,
        "auth_nvs_size": 196608,
    }


def tag_ruleset() -> dict[str, object]:
    return {
        "id": 23666967,
        "name": "SemVer tag immutability",
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*.*.*"], "exclude": []}},
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "update"},
        ],
        "bypass_actors": [],
    }


def protected_main_evidence(
    sha: str = WEB_SHA,
) -> tuple[list[object], dict[str, object], dict[str, object]]:
    rules = [{
        "type": "required_status_checks",
        "parameters": {
            "required_status_checks": [
                {"context": "security:scan", "integration_id": 15368}
            ]
        },
    }]
    checks = {"check_runs": [{
        "name": "security:scan",
        "head_sha": sha,
        "status": "completed",
        "conclusion": "success",
        "app": {"id": 15368},
    }]}
    return rules, checks, {"statuses": []}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def synthetic_release_package(
    root: Path,
) -> tuple[Path, dict[str, object], dict[str, object]]:
    package = root / "package"
    package.mkdir()
    version = "1.0.0"
    factory_bin = f"m5authenticator-v{version}-{SOURCE_SHA}-m5sticks3.bin"
    boot_bin = f"m5authenticator-v{version}-{SOURCE_SHA}-m5sticks3-update-bootloader.bin"
    table_bin = f"m5authenticator-v{version}-{SOURCE_SHA}-m5sticks3-update-partition-table.bin"
    ota_bin = f"m5authenticator-v{version}-{SOURCE_SHA}-m5sticks3-update-ota0.bin"
    factory_manifest_name = f"factory-manifest-{SOURCE_SHA}.json"
    update_manifest_name = f"update-manifest-{SOURCE_SHA}.json"

    for name, payload in (
        (factory_bin, b"factory"),
        (boot_bin, b"boot"),
        (table_bin, b"partition"),
        (ota_bin, b"ota"),
    ):
        (package / name).write_bytes(payload)

    identity = {
        "name": "M5Authenticator",
        "version": version,
        "build_commit": SOURCE_SHA,
        "exact_release": True,
    }
    write_json(
        package / factory_manifest_name,
        {
            **identity,
            "builds": [{
                "chipFamily": "ESP32-S3",
                "parts": [{"path": factory_bin, "offset": 0}],
            }],
        },
    )
    write_json(
        package / update_manifest_name,
        {
            **identity,
            "builds": [{
                "chipFamily": "ESP32-S3",
                "parts": [
                    {"path": boot_bin, "offset": 0},
                    {"path": table_bin, "offset": 0x8000},
                    {"path": ota_bin, "offset": 0x30000},
                ],
            }],
        },
    )
    (package / "factory-manifest.json").write_bytes(
        (package / factory_manifest_name).read_bytes()
    )
    (package / "update-manifest.json").write_bytes(
        (package / update_manifest_name).read_bytes()
    )
    write_json(
        package / "firmware-target.json",
        {
            **identity,
            "factory_manifest": factory_manifest_name,
            "update_manifest": update_manifest_name,
        },
    )
    release_profile = profile()
    write_json(
        package / "release-metadata.json",
        {
            "format": 2,
            "device": release_profile["device"],
            "chip_family": release_profile["chip_family"],
            "firmware_version": version,
            "protocol_version": release_profile["protocol_version"],
            "storage_schema_version": release_profile["storage_schema_version"],
            "vault_format_version": release_profile["vault_format_version"],
            "security_profile": release_profile["security_profile"],
            "security_profile_version": release_profile["security_profile_version"],
            "vmk_persistence": release_profile["vmk_persistence"],
            "post_update_state": release_profile["post_update_state"],
            "build_commit": SOURCE_SHA,
            "exact_release": True,
            "flash_offset": 0,
            "merged_image_bytes": (package / factory_bin).stat().st_size,
            "build_environment": {
                "esp_idf": {
                    "version": "5.5.5",
                    "image": "example.invalid/idf@sha256:" + "d" * 64,
                }
            },
            "production_release_allowed": True,
            "auth_nvs_offset": release_profile["auth_nvs_offset"],
            "auth_nvs_size": release_profile["auth_nvs_size"],
            "normal_update": {
                "erase_first": False,
                "parts": [
                    {
                        "name": "bootloader",
                        "path": boot_bin,
                        "offset": 0,
                        "bytes": (package / boot_bin).stat().st_size,
                    },
                    {
                        "name": "partition_table",
                        "path": table_bin,
                        "offset": 0x8000,
                        "bytes": (package / table_bin).stat().st_size,
                    },
                    {
                        "name": "ota_0",
                        "path": ota_bin,
                        "offset": release_profile["ota_0_offset"],
                        "bytes": (package / ota_bin).stat().st_size,
                    },
                ],
                "required_preserve_partitions": ["nvs", "auth_nvs"],
            },
        },
    )

    payload_names = sorted(path.name for path in package.iterdir())
    (package / "SHA256SUMS").write_text(
        "".join(
            f"{ci_pages_released_firmware.sha256(package / name)}  {name}\n"
            for name in payload_names
        ),
        encoding="utf-8",
    )
    assets = []
    for index, path in enumerate(sorted(package.iterdir()), start=1):
        assets.append({
            "id": index,
            "name": path.name,
            "size": path.stat().st_size,
            "digest": "sha256:" + ci_pages_released_firmware.sha256(path),
            "state": "uploaded",
        })
    release = {
        "id": 1234,
        "tag_name": "v1.0.0",
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "assets": assets,
    }
    return package, release, release_profile


def refresh_release_asset(release: dict[str, object], package: Path, name: str) -> None:
    path = package / name
    for asset in release["assets"]:
        if asset["name"] == name:
            asset["size"] = path.stat().st_size
            asset["digest"] = "sha256:" + ci_pages_released_firmware.sha256(path)
            return
    raise AssertionError(name)


def synthetic_attestation_outputs(
    root: Path,
    package: Path,
    package_result: dict[str, object],
) -> tuple[Path, Path]:
    standard = root / "standard"
    custom = root / "custom"
    standard.mkdir()
    custom.mkdir()
    artifacts = [
        {"name": name, "sha256": digest}
        for name, digest in sorted(package_result["checksums"].items())
    ]
    predicate = {
        "format": 1,
        "predicate_type": CUSTOM_PREDICATE_TYPE,
        "source_commit": SOURCE_SHA,
        "workflow": {
            "repository": "miso-develop/m5authenticator",
            "workflow_ref": (
                "miso-develop/m5authenticator/.github/workflows/"
                "release-authorized.yml@refs/heads/main"
            ),
            "workflow_sha": PUBLISHER_SHA,
            "run_id": 100,
            "run_attempt": 1,
        },
        "build_environment": {
            "esp_idf": package_result["release_metadata"]["build_environment"]["esp_idf"]
        },
        "sha256sums_sha256": package_result["sha256sums_sha256"],
        "artifacts": artifacts,
    }
    for path in package.iterdir():
        digest = ci_pages_released_firmware.sha256(path)
        subject = [{"name": path.name, "digest": {"sha256": digest}}]
        write_json(
            standard / f"{path.name}.json",
            [{
                "verificationResult": {
                    "statement": {
                        "predicateType": ci_pages_released_firmware.STANDARD_PREDICATE_TYPE,
                        "subject": subject,
                        "predicate": {},
                    }
                }
            }],
        )
        write_json(
            custom / f"{path.name}.json",
            [{
                "verificationResult": {
                    "statement": {
                        "predicateType": CUSTOM_PREDICATE_TYPE,
                        "subject": subject,
                        "predicate": predicate,
                    }
                }
            }],
        )
    return standard, custom


EXPECTED_HISTORICAL_SOURCE_BLOBS = (
    "firmware/release-profile.json",
    "firmware/components/m5auth_core/include/m5auth/core/metadata.hpp",
    "firmware/CMakeLists.txt",
    "firmware/partitions.csv",
    "firmware/main/app_main.cpp",
    "firmware/sdkconfig.defaults",
    "firmware/main/usb_protocol_transport.hpp",
    "firmware/main/usb_protocol_transport.cpp",
    "firmware/components/m5auth_provisioning/CMakeLists.txt",
    "firmware/components/m5auth_device_sticks3/CMakeLists.txt",
    "firmware/components/m5auth_time/CMakeLists.txt",
    "firmware/components/m5auth_totp/CMakeLists.txt",
)


def make_historical_source_repo(
    root: Path,
    *,
    omit: str | None = None,
    executable: str | None = None,
    malicious_sentinel: Path | None = None,
    replacements: dict[str, tuple[bytes, bytes]] | None = None,
) -> tuple[Path, str]:
    repo = root / "historical"
    repo.mkdir()

    def git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    git("init", "-q")
    git("config", "user.email", "tests@example.invalid")
    git("config", "user.name", "M5Authenticator Tests")

    for relative_path in EXPECTED_HISTORICAL_SOURCE_BLOBS:
        if relative_path == omit:
            continue
        destination = repo / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = (REPO_ROOT / relative_path).read_bytes()
        if replacements is not None and relative_path in replacements:
            before, after = replacements[relative_path]
            if before not in payload:
                raise AssertionError(f"fixture mutation anchor missing: {relative_path}")
            payload = payload.replace(before, after, 1)
        if malicious_sentinel is not None and relative_path == "firmware/CMakeLists.txt":
            payload += (
                "\n# inert historical text: $(touch "
                + str(malicious_sentinel)
                + ")\n# python: __import__('pathlib').Path('"
                + str(malicious_sentinel)
                + "').write_text('executed')\n"
            ).encode("utf-8")
        destination.write_bytes(payload)

    if malicious_sentinel is not None:
        unlisted = repo / "scripts" / "validate_release.py"
        unlisted.parent.mkdir(parents=True, exist_ok=True)
        unlisted.write_text(
            "from pathlib import Path\n"
            f"Path({str(malicious_sentinel)!r}).write_text('executed')\n",
            encoding="utf-8",
        )

    git("add", ".")
    if executable is not None:
        git("update-index", "--chmod=+x", executable)
    git("commit", "-q", "-m", "historical fixture")
    return repo, git("rev-parse", "HEAD").stdout.strip()




class PagesReleasedFirmwareVerifierTests(unittest.TestCase):
    def test_historical_source_allowlist_is_exact(self) -> None:
        self.assertEqual(
            ci_pages_released_firmware.HISTORICAL_SOURCE_BLOB_PATHS,
            EXPECTED_HISTORICAL_SOURCE_BLOBS,
        )

    def test_current_release_validator_default_paths_remain_valid(self) -> None:
        result = validate_release.validate_release(require_production=True)
        self.assertTrue(result["profile"]["production_release_allowed"])

    def test_historical_source_is_validated_as_data_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "historical-code-executed"
            historical, source_sha = make_historical_source_repo(
                root,
                malicious_sentinel=sentinel,
            )
            current_profile = json.loads(
                (REPO_ROOT / "firmware/release-profile.json").read_text(encoding="utf-8")
            )
            validation_parent = root / "validation"
            result = ci_pages_released_firmware.validate_historical_release_source(
                repo_root=historical,
                source_sha=source_sha,
                release_tag="v1.0.0",
                current_profile=current_profile,
                temp_parent=validation_parent,
            )
            self.assertFalse(sentinel.exists())
            self.assertEqual(result["validated_paths"], list(EXPECTED_HISTORICAL_SOURCE_BLOBS))
            self.assertEqual(result["firmware_source_sha"], source_sha)
            self.assertEqual(set(result), ci_pages_released_firmware.SOURCE_VALIDATION_KEYS)
            self.assertFalse(
                any(validation_parent.glob("m5auth-release-source-data-*")),
                "temporary historical validation data must be removed after validation",
            )

    def test_historical_source_missing_blob_and_wrong_mode_fail_closed(self) -> None:
        current_profile = json.loads(
            (REPO_ROOT / "firmware/release-profile.json").read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            historical, source_sha = make_historical_source_repo(
                root,
                omit="firmware/components/m5auth_totp/CMakeLists.txt",
            )
            with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                ci_pages_released_firmware.validate_historical_release_source(
                    repo_root=historical,
                    source_sha=source_sha,
                    release_tag="v1.0.0",
                    current_profile=current_profile,
                    temp_parent=root / "validation",
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            historical, source_sha = make_historical_source_repo(
                root,
                executable="firmware/CMakeLists.txt",
            )
            with self.assertRaisesRegex(ValueError, "ordinary non-executable blob 100644"):
                ci_pages_released_firmware.validate_historical_release_source(
                    repo_root=historical,
                    source_sha=source_sha,
                    release_tag="v1.0.0",
                    current_profile=current_profile,
                    temp_parent=root / "validation",
                )

    def test_historical_contract_mutations_are_rejected_by_current_main_validation(self) -> None:
        current_profile = json.loads(
            (REPO_ROOT / "firmware/release-profile.json").read_text(encoding="utf-8")
        )
        cases = {
            "profile": (
                "firmware/release-profile.json",
                b'"protocol_version": 2',
                b'"protocol_version": 3',
            ),
            "metadata": (
                "firmware/components/m5auth_core/include/m5auth/core/metadata.hpp",
                b"kProtocolVersion = 2",
                b"kProtocolVersion = 3",
            ),
            "project-cmake": (
                "firmware/CMakeLists.txt",
                b"project(m5authenticator VERSION 1.0.0)",
                b"project(m5authenticator VERSION 1.0.1)",
            ),
            "partitions": (
                "firmware/partitions.csv",
                b"ota_0,      app,  ota_0,   0x30000,  0x3d0000,",
                b"ota_0,      app,  ota_0,   0x30001,  0x3d0000,",
            ),
            "bootstrap": (
                "firmware/main/app_main.cpp",
                b"m5auth::vault_runtime::CompatibleNvsPersistence",
                b"m5auth::vault_runtime::BrokenPersistence",
            ),
            "transport": (
                "firmware/main/usb_protocol_transport.hpp",
                b"kUsbProtocolRxBufferBytes = 1024",
                b"kUsbProtocolRxBufferBytes = 2048",
            ),
            "build-surface": (
                "firmware/components/m5auth_provisioning/CMakeLists.txt",
                b'"canonical_protocol_v2.cpp"',
                b'"legacy_protocol_v2.cpp"',
            ),
        }
        for label, (relative_path, before, after) in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                historical, source_sha = make_historical_source_repo(
                    root,
                    replacements={relative_path: (before, after)},
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "historical release source fails current-main validation",
                ):
                    ci_pages_released_firmware.validate_historical_release_source(
                        repo_root=historical,
                        source_sha=source_sha,
                        release_tag="v1.0.0",
                        current_profile=current_profile,
                        temp_parent=root / "validation",
                    )

    def test_bounded_source_validation_result_rejects_shape_or_identity_drift(self) -> None:
        payload = {
            "format": ci_pages_released_firmware.SOURCE_VALIDATION_FORMAT,
            "release_tag": "v1.0.0",
            "firmware_version": "1.0.0",
            "firmware_source_sha": SOURCE_SHA,
            "release_profile": profile(),
            "metadata": {
                "firmware_version": "1.0.0",
                "protocol_version": 2,
                "storage_schema_version": 2,
                "vault_format_version": 1,
            },
            "project_version": "1.0.0",
            "partitions": {},
            "validated_paths": list(EXPECTED_HISTORICAL_SOURCE_BLOBS),
        }
        self.assertEqual(
            ci_pages_released_firmware.require_source_validation_result(
                payload,
                release_tag="v1.0.0",
                source_sha=SOURCE_SHA,
            ),
            payload,
        )
        mutated = copy.deepcopy(payload)
        mutated["validated_paths"] = mutated["validated_paths"][:-1]
        with self.assertRaisesRegex(ValueError, "path set mismatch"):
            ci_pages_released_firmware.require_source_validation_result(
                mutated,
                release_tag="v1.0.0",
                source_sha=SOURCE_SHA,
            )
        mutated = copy.deepcopy(payload)
        mutated["unexpected"] = "historical text"
        with self.assertRaisesRegex(ValueError, "shape is invalid"):
            ci_pages_released_firmware.require_source_validation_result(
                mutated,
                release_tag="v1.0.0",
                source_sha=SOURCE_SHA,
            )

    def test_web_authorization_reuses_required_check_semantics(self) -> None:
        rules, checks, statuses = protected_main_evidence()
        self.assertEqual(
            ci_pages_released_firmware.require_web_authorization(
                source_ref="refs/heads/main",
                workflow_sha=WEB_SHA,
                requested_web_sha=WEB_SHA,
                current_main=WEB_SHA,
                deployment_ack="true",
                main_rules_payload=rules,
                check_runs_payload=checks,
                statuses_payload=statuses,
            ),
            WEB_SHA,
        )
        with self.assertRaisesRegex(ValueError, "requested Web SHA"):
            ci_pages_released_firmware.require_web_authorization(
                source_ref="refs/heads/main",
                workflow_sha=WEB_SHA,
                requested_web_sha="e" * 40,
                current_main=WEB_SHA,
                deployment_ack="true",
                main_rules_payload=rules,
                check_runs_payload=checks,
                statuses_payload=statuses,
            )
        failing_checks = copy.deepcopy(checks)
        failing_checks["check_runs"][0]["conclusion"] = "failure"
        with self.assertRaisesRegex(ValueError, "required protected-main"):
            ci_pages_released_firmware.require_web_authorization(
                source_ref="refs/heads/main",
                workflow_sha=WEB_SHA,
                requested_web_sha=WEB_SHA,
                current_main=WEB_SHA,
                deployment_ack="true",
                main_rules_payload=rules,
                check_runs_payload=failing_checks,
                statuses_payload=statuses,
            )

    def test_release_authorization_rejects_mutability_and_accepts_distinct_version(self) -> None:
        release = {
            "id": 1234,
            "tag_name": "v1.0.0",
            "draft": False,
            "prerelease": False,
            "immutable": True,
        }
        current = profile("1.0.1")
        old = profile("1.0.0")
        with mock.patch.object(ci_pages_released_firmware, "require_ancestor"):
            result = ci_pages_released_firmware.require_release_authorization(
                repo_root=REPO_ROOT,
                web_sha=WEB_SHA,
                release_tag="v1.0.0",
                tag_sha=SOURCE_SHA,
                release_payload=release,
                tag_ruleset_payload=tag_ruleset(),
                current_profile=current,
                release_profile=old,
            )
            self.assertEqual(result["firmware_source_sha"], SOURCE_SHA)
            for field in ("draft", "prerelease", "immutable"):
                mutated = dict(release)
                mutated[field] = True if field != "immutable" else False
                with self.subTest(field=field), self.assertRaises(ValueError):
                    ci_pages_released_firmware.require_release_authorization(
                        repo_root=REPO_ROOT,
                        web_sha=WEB_SHA,
                        release_tag="v1.0.0",
                        tag_sha=SOURCE_SHA,
                        release_payload=mutated,
                        tag_ruleset_payload=tag_ruleset(),
                        current_profile=current,
                        release_profile=old,
                    )

    def test_every_non_version_profile_change_rejects(self) -> None:
        release = profile("1.0.0")
        current = profile("1.0.1")
        ci_pages_released_firmware.require_compatible_profiles(current, release)
        for key in sorted(k for k in release if k != "firmware_version"):
            mutated = copy.deepcopy(current)
            value = mutated[key]
            if isinstance(value, bool):
                mutated[key] = not value
            elif isinstance(value, int):
                mutated[key] = value + 1
            else:
                mutated[key] = str(value) + "-changed"
            with self.subTest(key=key), self.assertRaisesRegex(
                ValueError, "compatibility profile mismatch"
            ):
                ci_pages_released_firmware.require_compatible_profiles(mutated, release)

    def test_tag_ruleset_exclusion_and_non_ancestor_fail_closed(self) -> None:
        ruleset = tag_ruleset()
        ruleset["conditions"]["ref_name"]["exclude"] = ["refs/tags/v1.0.0"]
        with self.assertRaises(ValueError):
            ci_pages_released_firmware.release_authorization.require_tag_immutability(ruleset)

        completed = subprocess.CompletedProcess(
            ["git", "merge-base"], returncode=1, stdout=b"", stderr=b""
        )
        with mock.patch.object(
            ci_pages_released_firmware.subprocess, "run", return_value=completed
        ):
            with self.assertRaisesRegex(ValueError, "not an ancestor"):
                ci_pages_released_firmware.require_ancestor(REPO_ROOT, SOURCE_SHA, WEB_SHA)

    def test_release_asset_preflight_rejects_unsafe_names_and_missing_digests(self) -> None:
        release = {
            "assets": [
                {
                    "id": 1,
                    "name": "firmware.bin",
                    "size": 1,
                    "digest": "sha256:" + "a" * 64,
                    "state": "uploaded",
                },
                {
                    "id": 2,
                    "name": "SHA256SUMS",
                    "size": 80,
                    "digest": "sha256:" + "b" * 64,
                    "state": "uploaded",
                },
            ]
        }
        self.assertEqual(ci_pages_released_firmware.preflight_release_assets(release), 2)

        for bad_name in (
            "../firmware.bin",
            "folder/firmware.bin",
            "bad\\name.bin",
            "bad\nname.bin",
        ):
            bad = copy.deepcopy(release)
            bad["assets"][0]["name"] = bad_name
            with self.subTest(name=bad_name), self.assertRaisesRegex(ValueError, "unsafe"):
                ci_pages_released_firmware.preflight_release_assets(bad)

        missing_digest = copy.deepcopy(release)
        missing_digest["assets"][0]["digest"] = None
        with self.assertRaisesRegex(ValueError, "no exact SHA-256 digest"):
            ci_pages_released_firmware.preflight_release_assets(missing_digest)

        duplicate = copy.deepcopy(release)
        duplicate["assets"].append(copy.deepcopy(duplicate["assets"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            ci_pages_released_firmware.preflight_release_assets(duplicate)

    def test_release_package_requires_api_digest_and_exact_checksum_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package, release, release_profile = synthetic_release_package(root)
            result = ci_pages_released_firmware.verify_release_package(
                package_dir=package,
                release_payload=release,
                release_tag="v1.0.0",
                source_sha=SOURCE_SHA,
                release_profile=release_profile,
            )
            self.assertEqual(result["firmware_source_sha"], SOURCE_SHA)

            bad_release = copy.deepcopy(release)
            bad_release["assets"][0]["digest"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(ValueError, "API digest mismatch"):
                ci_pages_released_firmware.verify_release_package(
                    package_dir=package,
                    release_payload=bad_release,
                    release_tag="v1.0.0",
                    source_sha=SOURCE_SHA,
                    release_profile=release_profile,
                )

            checksum_path = package / "SHA256SUMS"
            lines = checksum_path.read_text(encoding="utf-8").splitlines()
            checksum_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
            refresh_release_asset(release, package, "SHA256SUMS")
            with self.assertRaisesRegex(ValueError, "exactly cover"):
                ci_pages_released_firmware.verify_release_package(
                    package_dir=package,
                    release_payload=release,
                    release_tag="v1.0.0",
                    source_sha=SOURCE_SHA,
                    release_profile=release_profile,
                )

    def test_release_target_identity_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package, release, release_profile = synthetic_release_package(root)
            target_path = package / "firmware-target.json"
            target = json.loads(target_path.read_text(encoding="utf-8"))
            target["exact_release"] = False
            write_json(target_path, target)
            checksums = ci_pages_released_firmware.ci_firmware_handoff.parse_sha256sums(
                package / "SHA256SUMS"
            )
            checksums["firmware-target.json"] = ci_pages_released_firmware.sha256(target_path)
            (package / "SHA256SUMS").write_text(
                "".join(f"{digest}  {name}\n" for name, digest in checksums.items()),
                encoding="utf-8",
            )
            refresh_release_asset(release, package, "firmware-target.json")
            refresh_release_asset(release, package, "SHA256SUMS")
            with self.assertRaisesRegex(ValueError, "not marked exact_release"):
                ci_pages_released_firmware.verify_release_package(
                    package_dir=package,
                    release_payload=release,
                    release_tag="v1.0.0",
                    source_sha=SOURCE_SHA,
                    release_profile=release_profile,
                )

    def test_release_layout_metadata_and_stable_aliases_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package, release, release_profile = synthetic_release_package(root)

            metadata_path = package / "release-metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["normal_update"]["parts"][2]["offset"] += 1
            write_json(metadata_path, metadata)
            checksums = ci_pages_released_firmware.ci_firmware_handoff.parse_sha256sums(
                package / "SHA256SUMS"
            )
            checksums["release-metadata.json"] = ci_pages_released_firmware.sha256(metadata_path)
            (package / "SHA256SUMS").write_text(
                "".join(f"{digest}  {name}\n" for name, digest in checksums.items()),
                encoding="utf-8",
            )
            refresh_release_asset(release, package, "release-metadata.json")
            refresh_release_asset(release, package, "SHA256SUMS")
            with self.assertRaisesRegex(ValueError, "normal_update layout mismatch"):
                ci_pages_released_firmware.verify_release_package(
                    package_dir=package,
                    release_payload=release,
                    release_tag="v1.0.0",
                    source_sha=SOURCE_SHA,
                    release_profile=release_profile,
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package, release, release_profile = synthetic_release_package(root)
            stable = package / "factory-manifest.json"
            stable.write_text("{}\n", encoding="utf-8")
            checksums = ci_pages_released_firmware.ci_firmware_handoff.parse_sha256sums(
                package / "SHA256SUMS"
            )
            checksums["factory-manifest.json"] = ci_pages_released_firmware.sha256(stable)
            (package / "SHA256SUMS").write_text(
                "".join(f"{digest}  {name}\n" for name, digest in checksums.items()),
                encoding="utf-8",
            )
            refresh_release_asset(release, package, "factory-manifest.json")
            refresh_release_asset(release, package, "SHA256SUMS")
            with self.assertRaisesRegex(ValueError, "stable factory manifest differs"):
                ci_pages_released_firmware.verify_release_package(
                    package_dir=package,
                    release_payload=release,
                    release_tag="v1.0.0",
                    source_sha=SOURCE_SHA,
                    release_profile=release_profile,
                )

    def test_signed_provenance_accepts_distinct_source_and_publisher(self) -> None:
        self.assertNotEqual(SOURCE_SHA, PUBLISHER_SHA)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package, release, release_profile = synthetic_release_package(root)
            package_result = ci_pages_released_firmware.verify_release_package(
                package_dir=package,
                release_payload=release,
                release_tag="v1.0.0",
                source_sha=SOURCE_SHA,
                release_profile=release_profile,
            )
            standard, custom = synthetic_attestation_outputs(root, package, package_result)
            verified = ci_pages_released_firmware.verify_attestations(
                package_dir=package,
                standard_dir=standard,
                custom_dir=custom,
                source_sha=SOURCE_SHA,
                checksums=package_result["checksums"],
                sha256sums_sha256=package_result["sha256sums_sha256"],
                release_metadata=package_result["release_metadata"],
            )
            self.assertEqual(verified["publisher_workflow_sha"], PUBLISHER_SHA)

            victim = custom / "SHA256SUMS.json"
            payload = json.loads(victim.read_text(encoding="utf-8"))
            payload[0]["verificationResult"]["statement"]["predicate"]["source_commit"] = "f" * 40
            write_json(victim, payload)
            with self.assertRaisesRegex(ValueError, "source_commit mismatch"):
                ci_pages_released_firmware.verify_attestations(
                    package_dir=package,
                    standard_dir=standard,
                    custom_dir=custom,
                    source_sha=SOURCE_SHA,
                    checksums=package_result["checksums"],
                    sha256sums_sha256=package_result["sha256sums_sha256"],
                    release_metadata=package_result["release_metadata"],
                )

    def test_missing_attestation_and_notice_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package, release, release_profile = synthetic_release_package(root)
            package_result = ci_pages_released_firmware.verify_release_package(
                package_dir=package,
                release_payload=release,
                release_tag="v1.0.0",
                source_sha=SOURCE_SHA,
                release_profile=release_profile,
            )
            standard, custom = synthetic_attestation_outputs(root, package, package_result)
            (custom / "SHA256SUMS.json").unlink()
            with self.assertRaisesRegex(ValueError, "incomplete"):
                ci_pages_released_firmware.verify_attestations(
                    package_dir=package,
                    standard_dir=standard,
                    custom_dir=custom,
                    source_sha=SOURCE_SHA,
                    checksums=package_result["checksums"],
                    sha256sums_sha256=package_result["sha256sums_sha256"],
                    release_metadata=package_result["release_metadata"],
                )
            dist = root / "dist"
            dist.mkdir()
            with self.assertRaisesRegex(ValueError, "notice"):
                ci_pages_released_firmware.assemble_site(
                    package_dir=package,
                    dist_dir=dist,
                    notice_path=root / "missing.md",
                )

    def test_assembly_preserves_release_bytes_and_separate_current_notice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package, _, _ = synthetic_release_package(root)
            dist = root / "dist"
            dist.mkdir()
            (dist / "index.html").write_text("web", encoding="utf-8")
            notice = root / "THIRD_PARTY_NOTICES.md"
            notice.write_bytes(b"current-main notice\n")
            ci_pages_released_firmware.assemble_site(
                package_dir=package,
                dist_dir=dist,
                notice_path=notice,
            )
            self.assertEqual(
                (dist / "THIRD_PARTY_NOTICES.md").read_bytes(),
                b"current-main notice\n",
            )
            for source in package.iterdir():
                self.assertEqual(
                    (dist / "firmware" / source.name).read_bytes(),
                    source.read_bytes(),
                )


class PagesReleasedFirmwareWorkflowContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = (
            REPO_ROOT / ".github" / "workflows" / "pages-web-released-firmware.yml"
        ).read_text(encoding="utf-8")
        self.existing = (
            REPO_ROOT / ".github" / "workflows" / "pages.yml"
        ).read_text(encoding="utf-8")

    def test_new_workflow_is_manual_only_with_exact_inputs(self) -> None:
        header = self.workflow[: self.workflow.index("permissions:")]
        self.assertIn("workflow_dispatch:", header)
        for forbidden in ("push:", "repository_dispatch:", "workflow_call:", "schedule:"):
            self.assertNotIn(forbidden, header)
        for required in ("web_sha:", "firmware_release_tag:", "deployment_ack:"):
            self.assertIn(required, header)
        for forbidden_input in ("firmware_source_sha:", "asset_url:", "asset_id:"):
            self.assertNotIn(forbidden_input, header)

    def test_existing_pages_cadence_remains_tag_plus_candidate_only(self) -> None:
        header = self.existing[: self.existing.index("permissions:")]
        self.assertIn("push:", header)
        self.assertIn("tags:", header)
        self.assertIn("'v*.*.*'", header)
        self.assertIn("workflow_dispatch:", header)
        self.assertIn("candidate_sha:", header)
        self.assertNotIn("branches:", header)

    def test_no_firmware_rebuild_or_release_mutation_authority(self) -> None:
        for forbidden in (
            "ci_esp_idf_isolated_build.py",
            "package_firmware.py",
            "idf.py",
            "docker run",
            "contents: write",
            "gh release create",
            "gh release upload",
            "gh release edit",
            "gh release delete",
            "git push",
            "repository_dispatch",
            "uses: ./.github/workflows/release-authorized.yml",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.workflow)

    def test_historical_release_source_never_executes_or_persists_as_a_tree(self) -> None:
        for forbidden in (
            "git worktree",
            "M5AUTH_RELEASE_SOURCE_ROOT",
            "RELEASE_SOURCE_ROOT",
            "PYTHONPATH",
            'python "$RELEASE_SOURCE_ROOT/scripts/validate_release.py"',
            "--release-profile",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.workflow)
        self.assertIn(
            '--result-json "$RUNNER_TEMP/released-firmware-source-validation.json"',
            self.workflow,
        )
        self.assertIn(
            '--source-validation "$RUNNER_TEMP/released-firmware-source-validation.json"',
            self.workflow,
        )

    def test_workflow_verifies_required_checks_release_and_attestations(self) -> None:
        for required in (
            "/rules/branches/main?per_page=100",
            "/commits/$MAIN_SHA/check-runs?filter=latest&per_page=100",
            "/commits/$MAIN_SHA/status",
            "authorize-web",
            "select-tag-ruleset",
            "authorize-release",
            "preflight-assets",
            "gh release download",
            "verify-package",
            "gh attestation verify",
            "--predicate-type",
            "verify-attestations",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.workflow)
        self.assertLess(
            self.workflow.index("preflight-assets"),
            self.workflow.index("gh release download"),
        )

    def test_notice_and_released_assets_are_assembled_after_web_build(self) -> None:
        self.assertIn("python scripts/verify_third_party_notices.py", self.workflow)
        self.assertIn('--notice "THIRD_PARTY_NOTICES.md"', self.workflow)
        self.assertIn("web/dist/THIRD_PARTY_NOTICES.md", self.workflow)
        self.assertIn("web/dist/firmware/firmware-target.json", self.workflow)
        self.assertLess(
            self.workflow.index("Build exact current-main production Web"),
            self.workflow.index("Assemble verified immutable Release bytes after Web build"),
        )
        self.assertIn('VITE_M5AUTH_WEB_EXACT_RELEASE: "false"', self.workflow)

    def test_permissions_retention_cleanup_and_concurrency_are_bounded(self) -> None:
        self.assertIn("group: github-pages", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)
        self.assertEqual(self.workflow.count("actions/upload-pages-artifact@"), 1)
        self.assertIn("retention-days: 1", self.workflow)
        self.assertIn("needs.build.outputs.pages-artifact-id", self.workflow)
        self.assertIn(
            'gh api --method DELETE "/repos/$GITHUB_REPOSITORY/actions/artifacts/$PAGES_ARTIFACT_ID"',
            self.workflow,
        )
        build_block = self.workflow[
            self.workflow.index("  build:") : self.workflow.index("  deploy:")
        ]
        for required in ("contents: read", "checks: read", "statuses: read", "attestations: read"):
            self.assertIn(required, build_block)
        for forbidden in ("pages: write", "id-token: write", "actions: write"):
            self.assertNotIn(forbidden, build_block)
        deploy_block = self.workflow[self.workflow.index("  deploy:") :]
        for required in ("pages: write", "id-token: write", "actions: write"):
            self.assertIn(required, deploy_block)
        self.assertNotIn("contents: write", deploy_block)
        self.assertNotIn("gh attestation verify", deploy_block)
        self.assertNotIn("gh release", deploy_block)

    def test_mixed_identity_summary_keeps_shell_metacharacters_literal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = root / "summary.md"
            sentinel = root / "executed"
            ci_pages_summary.append_web_released_firmware_summary(
                summary,
                web_version="1.0.0",
                web_sha=WEB_SHA,
                firmware_release_tag=f"v1.0.0$(touch {sentinel})",
                release_id="392327695",
                firmware_source_sha=SOURCE_SHA,
                sha256sums_sha256="d" * 64,
                publisher_workflow_sha=PUBLISHER_SHA,
                publisher_run_id="35492573744",
                publisher_run_attempt="1",
            )
            rendered = summary.read_text(encoding="utf-8")
            self.assertIn("$(touch ", rendered)
            self.assertFalse(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
