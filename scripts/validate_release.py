#!/usr/bin/env python3
"""Validate M5Authenticator release metadata and the fixed V1 flash/security contract."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = REPO_ROOT / "firmware" / "release-profile.json"
DEFAULT_METADATA = REPO_ROOT / "firmware" / "components" / "m5auth_core" / "include" / "m5auth" / "core" / "metadata.hpp"
DEFAULT_PARTITIONS = REPO_ROOT / "firmware" / "partitions.csv"
DEFAULT_BOOTSTRAP = REPO_ROOT / "firmware" / "main" / "app_main.cpp"
DEFAULT_SDKCONFIG = REPO_ROOT / "firmware" / "sdkconfig.defaults"
DEFAULT_PROVISIONING_CMAKE = REPO_ROOT / "firmware" / "components" / "m5auth_provisioning" / "CMakeLists.txt"
DEFAULT_DEVICE_CMAKE = REPO_ROOT / "firmware" / "components" / "m5auth_device_sticks3" / "CMakeLists.txt"
DEFAULT_TIME_CMAKE = REPO_ROOT / "firmware" / "components" / "m5auth_time" / "CMakeLists.txt"
DEFAULT_TOTP_CMAKE = REPO_ROOT / "firmware" / "components" / "m5auth_totp" / "CMakeLists.txt"

REQUIRED_PARTITIONS = ("nvs", "otadata", "phy_init", "ota_0", "ota_1", "auth_nvs")
V1_SECURITY_PROFILE = "encrypted-vault-ram-only-vmk"
V1_SECURITY_PROFILE_VERSION = 1
V1_CREDENTIAL_FLASH_STORAGE = "encrypted-vault-only"
V1_VMK_PERSISTENCE = "ram-only"
V1_POST_UPDATE_STATE = "locked"


class ReleaseValidationError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseValidationError(message)


def _read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseValidationError(f"cannot read {label}: {exc}") from exc


def load_profile(path: Path = DEFAULT_PROFILE) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseValidationError(f"invalid release profile: {exc}") from exc
    _require(isinstance(data, dict), "release profile must be a JSON object")
    return data


def parse_metadata(path: Path = DEFAULT_METADATA) -> dict[str, Any]:
    source = _read_text(path, "firmware metadata")

    version = re.search(r'kFirmwareVersion\[\]\s*=\s*"([^"]+)"', source)
    protocol = re.search(r"kProtocolVersion\s*=\s*(\d+)", source)
    storage = re.search(r"kStorageSchemaVersion\s*=\s*(\d+)", source)
    vault = re.search(r"kVaultFormatVersion\s*=\s*(\d+)", source)
    _require(version is not None, "firmware version constant not found")
    _require(protocol is not None, "protocol version constant not found")
    _require(storage is not None, "storage schema constant not found")
    _require(vault is not None, "Vault format constant not found")
    return {
        "firmware_version": version.group(1),
        "protocol_version": int(protocol.group(1)),
        "storage_schema_version": int(storage.group(1)),
        "vault_format_version": int(vault.group(1)),
    }


def parse_partitions(path: Path = DEFAULT_PARTITIONS) -> dict[str, dict[str, int | str]]:
    partitions: dict[str, dict[str, int | str]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ReleaseValidationError(f"cannot read partition table: {exc}") from exc

    for raw in csv.reader(line for line in lines if line.strip() and not line.lstrip().startswith("#")):
        _require(len(raw) >= 5, "partition row has fewer than five columns")
        name, part_type, subtype, offset_text, size_text = (value.strip() for value in raw[:5])
        _require(name not in partitions, f"duplicate partition: {name}")
        try:
            offset = int(offset_text, 0)
            size = int(size_text, 0)
        except ValueError as exc:
            raise ReleaseValidationError(f"invalid offset/size for partition {name}") from exc
        _require(offset >= 0 and size > 0, f"invalid range for partition {name}")
        partitions[name] = {
            "type": part_type,
            "subtype": subtype,
            "offset": offset,
            "size": size,
        }
    return partitions


def validate_canonical_bootstrap(path: Path = DEFAULT_BOOTSTRAP) -> None:
    source = _read_text(path, "firmware bootstrap")

    required = (
        "m5auth::vault_runtime::CompatibleNvsPersistence",
        "m5auth::vault_runtime::Runtime runtime",
        "m5auth::provisioning::CanonicalProtocolV2Handler protocol",
        '"m5auth/device/sticks3/canonical_device.hpp"',
    )
    for token in required:
        _require(token in source, f"canonical V1 bootstrap missing: {token}")

    forbidden = (
        "DevSecurityBackend",
        "m5auth::storage::Store",
        "m5auth::provisioning::Session provisioning",
        '"m5auth/device/sticks3/device.hpp"',
    )
    for token in forbidden:
        _require(token not in source, f"legacy/synthetic credential bootstrap is release-ineligible: {token}")


def validate_release_build_surface(
    sdkconfig_path: Path = DEFAULT_SDKCONFIG,
    provisioning_cmake_path: Path = DEFAULT_PROVISIONING_CMAKE,
    device_cmake_path: Path = DEFAULT_DEVICE_CMAKE,
    time_cmake_path: Path = DEFAULT_TIME_CMAKE,
    totp_cmake_path: Path = DEFAULT_TOTP_CMAKE,
) -> None:
    sdkconfig = _read_text(sdkconfig_path, "release sdkconfig defaults")
    _require(
        re.search(r"^CONFIG_ESP_COREDUMP_ENABLE_TO_NONE=y$", sdkconfig, re.MULTILINE) is not None,
        "release firmware must explicitly disable ESP-IDF core dumps",
    )
    for forbidden in (
        "CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y",
        "CONFIG_ESP_COREDUMP_ENABLE_TO_UART=y",
    ):
        _require(forbidden not in sdkconfig, f"credential-bearing core dump destination is forbidden: {forbidden}")

    surfaces = (
        (
            "provisioning",
            _read_text(provisioning_cmake_path, "provisioning component CMake"),
            ("canonical_protocol_v2.cpp", "session_protocol_v2.cpp"),
            ('"protocol.cpp"', "m5auth_storage"),
        ),
        (
            "device",
            _read_text(device_cmake_path, "device component CMake"),
            ("release_device.cpp", "canonical_device.cpp"),
            ('"device.cpp"', '"ui_model.cpp"', "m5auth_storage"),
        ),
        (
            "time",
            _read_text(time_cmake_path, "time component CMake"),
            ("canonical_time_service.cpp",),
            ('"time_service.cpp"', "m5auth_storage"),
        ),
        (
            "totp",
            _read_text(totp_cmake_path, "TOTP component CMake"),
            ("vault_generator.cpp",),
            ('"generator.cpp"', "m5auth_storage"),
        ),
    )
    for label, source, required, forbidden in surfaces:
        for token in required:
            _require(token in source, f"release {label} surface missing canonical source: {token}")
        for token in forbidden:
            _require(token not in source, f"release {label} surface still includes legacy source/dependency: {token}")


def validate_release(
    profile_path: Path = DEFAULT_PROFILE,
    metadata_path: Path = DEFAULT_METADATA,
    partitions_path: Path = DEFAULT_PARTITIONS,
    require_production: bool = False,
    bootstrap_path: Path = DEFAULT_BOOTSTRAP,
) -> dict[str, Any]:
    profile = load_profile(profile_path)
    metadata = parse_metadata(metadata_path)
    partitions = parse_partitions(partitions_path)

    _require(profile.get("format") == 2, "unsupported release profile format")
    _require(profile.get("device") == "M5StickS3", "V1 release device must be M5StickS3")
    _require(profile.get("chip_family") == "ESP32-S3", "V1 chip family must be ESP32-S3")
    _require(profile.get("flash_size_bytes") == 8 * 1024 * 1024, "V1 flash size must be 8 MiB")

    for key in ("firmware_version", "protocol_version", "storage_schema_version", "vault_format_version"):
        _require(profile.get(key) == metadata[key], f"{key} does not match firmware metadata")

    _require(profile.get("protocol_version") == 2, "V1 production contract requires Protocol 2")
    _require(profile.get("storage_schema_version") == 2, "V1 production contract requires Storage Schema 2")
    _require(profile.get("vault_format_version") == 1, "V1 production contract requires Vault Format 1")
    _require(profile.get("security_profile") == V1_SECURITY_PROFILE, "unexpected V1 security profile")
    _require(profile.get("security_profile_version") == V1_SECURITY_PROFILE_VERSION, "unexpected security profile version")
    _require(profile.get("credential_flash_storage") == V1_CREDENTIAL_FLASH_STORAGE, "credential Flash storage must be encrypted Vault only")
    _require(profile.get("vmk_persistence") == V1_VMK_PERSISTENCE, "VMK must be RAM-only")
    _require(profile.get("public_synthetic_flash_key_allowed") is False, "public/synthetic Flash credential key is forbidden")
    _require(profile.get("project_specific_efuse_required") is False, "project-specific eFuse must not be a V1 release requirement")
    _require(profile.get("post_update_state") == V1_POST_UPDATE_STATE, "post-update state must be LOCKED")

    eligible = profile.get("production_release_allowed")
    _require(isinstance(eligible, bool), "production_release_allowed must be boolean")

    validate_canonical_bootstrap(bootstrap_path)
    validate_release_build_surface()

    for name in REQUIRED_PARTITIONS:
        _require(name in partitions, f"missing required partition: {name}")

    expected = {
        "ota_0": ("ota_0_offset", "ota_0_size"),
        "ota_1": ("ota_1_offset", "ota_1_size"),
        "auth_nvs": ("auth_nvs_offset", "auth_nvs_size"),
    }
    for name, (offset_key, size_key) in expected.items():
        _require(partitions[name]["offset"] == profile.get(offset_key), f"{name} offset does not match release profile")
        _require(partitions[name]["size"] == profile.get(size_key), f"{name} size does not match release profile")

    flash_size = int(profile["flash_size_bytes"])
    ranges: list[tuple[int, int, str]] = []
    for name, part in partitions.items():
        start = int(part["offset"])
        end = start + int(part["size"])
        _require(end <= flash_size, f"partition {name} exceeds flash size")
        ranges.append((start, end, name))
    ranges.sort()
    for previous, current in zip(ranges, ranges[1:]):
        _require(previous[1] <= current[0], f"partitions overlap: {previous[2]} and {current[2]}")

    auth = partitions["auth_nvs"]
    auth_start = int(auth["offset"])
    auth_end = auth_start + int(auth["size"])
    _require(auth_end == flash_size, "auth_nvs must occupy the end of flash")
    ota1 = partitions["ota_1"]
    _require(int(ota1["offset"]) + int(ota1["size"]) == auth_start, "ota_1 must end exactly where auth_nvs begins")

    if require_production:
        _require(eligible is True, "production release is blocked pending V1 security closeout")

    return {
        "profile": profile,
        "metadata": metadata,
        "partitions": partitions,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--partitions", type=Path, default=DEFAULT_PARTITIONS)
    parser.add_argument("--bootstrap", type=Path, default=DEFAULT_BOOTSTRAP)
    parser.add_argument("--require-production", action="store_true")
    args = parser.parse_args()
    try:
        result = validate_release(
            args.profile,
            args.metadata,
            args.partitions,
            args.require_production,
            args.bootstrap,
        )
    except ReleaseValidationError as exc:
        print(f"release validation failed: {exc}")
        return 1

    profile = result["profile"]
    eligibility = "production-eligible" if profile["production_release_allowed"] else "security-closeout-pending"
    print(
        "release validation OK: "
        f"{profile['device']} v{profile['firmware_version']} "
        f"protocol={profile['protocol_version']} storage={profile['storage_schema_version']} "
        f"vault={profile['vault_format_version']} "
        f"security={profile['security_profile']}/v{profile['security_profile_version']} "
        f"eligibility={eligibility}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
