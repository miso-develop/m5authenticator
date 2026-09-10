#!/usr/bin/env python3
"""Validate M5Authenticator release metadata and the fixed V1 flash layout."""

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
DEFAULT_SDKCONFIG = REPO_ROOT / "firmware" / "sdkconfig.defaults"

REQUIRED_PARTITIONS = ("nvs", "otadata", "phy_init", "ota_0", "ota_1", "auth_nvs")


class ReleaseValidationError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseValidationError(message)


def load_profile(path: Path = DEFAULT_PROFILE) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseValidationError(f"invalid release profile: {exc}") from exc
    _require(isinstance(data, dict), "release profile must be a JSON object")
    return data


def parse_metadata(path: Path = DEFAULT_METADATA) -> dict[str, Any]:
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseValidationError(f"cannot read firmware metadata: {exc}") from exc

    version = re.search(r'kFirmwareVersion\[\]\s*=\s*"([^"]+)"', source)
    protocol = re.search(r"kProtocolVersion\s*=\s*(\d+)", source)
    storage = re.search(r"kStorageSchemaVersion\s*=\s*(\d+)", source)
    _require(version is not None, "firmware version constant not found")
    _require(protocol is not None, "protocol version constant not found")
    _require(storage is not None, "storage schema constant not found")
    return {
        "firmware_version": version.group(1),
        "protocol_version": int(protocol.group(1)),
        "storage_schema_version": int(storage.group(1)),
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


def parse_sdkconfig_defaults(path: Path = DEFAULT_SDKCONFIG) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ReleaseValidationError(f"cannot read sdkconfig defaults: {exc}") from exc
    values: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key] = value
    return values


def validate_release(
    profile_path: Path = DEFAULT_PROFILE,
    metadata_path: Path = DEFAULT_METADATA,
    partitions_path: Path = DEFAULT_PARTITIONS,
    sdkconfig_path: Path = DEFAULT_SDKCONFIG,
    require_production: bool = False,
) -> dict[str, Any]:
    profile = load_profile(profile_path)
    metadata = parse_metadata(metadata_path)
    partitions = parse_partitions(partitions_path)
    sdkconfig = parse_sdkconfig_defaults(sdkconfig_path)

    _require(profile.get("format") == 1, "unsupported release profile format")
    _require(profile.get("device") == "M5StickS3", "V1 release device must be M5StickS3")
    _require(profile.get("chip_family") == "ESP32-S3", "V1 chip family must be ESP32-S3")
    _require(profile.get("flash_size_bytes") == 8 * 1024 * 1024, "V1 flash size must be 8 MiB")

    for key in ("firmware_version", "protocol_version", "storage_schema_version"):
        _require(profile.get(key) == metadata[key], f"{key} does not match firmware metadata")

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

    security_backend = profile.get("security_backend")
    eligible = profile.get("production_release_allowed")
    _require(security_backend in {"development-synthetic", "hmac-efuse"}, "unsupported security_backend")
    _require(isinstance(eligible, bool), "production_release_allowed must be boolean")

    if security_backend == "development-synthetic":
        _require(eligible is False, "development synthetic backend cannot be production eligible")
        _require(sdkconfig.get("CONFIG_M5AUTH_SECURITY_BACKEND_DEV") == "y", "release profile/backend mismatch")
    else:
        validated = profile.get("production_security_validated")
        key_id = profile.get("hmac_efuse_key_id")
        _require(isinstance(validated, bool), "production_security_validated must be boolean")
        _require(isinstance(key_id, int) and not isinstance(key_id, bool) and 0 <= key_id <= 5,
                 "hmac_efuse_key_id must be an integer from 0 to 5")
        _require(sdkconfig.get("CONFIG_M5AUTH_SECURITY_BACKEND_PRODUCTION") == "y",
                 "HMAC release profile requires production backend in sdkconfig defaults")
        _require(sdkconfig.get("CONFIG_M5AUTH_HMAC_KEY_ID") == str(key_id),
                 "HMAC key ID does not match sdkconfig defaults")
        if eligible:
            _require(validated is True, "production release requires completed physical security validation")

    if require_production:
        _require(security_backend == "hmac-efuse", "production release requires HMAC eFuse backend")
        _require(profile.get("production_security_validated") is True,
                 "production release is blocked until physical security validation completes")
        _require(eligible is True, "production release is blocked by release profile")

    return {
        "profile": profile,
        "metadata": metadata,
        "partitions": partitions,
        "sdkconfig": sdkconfig,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--partitions", type=Path, default=DEFAULT_PARTITIONS)
    parser.add_argument("--sdkconfig", type=Path, default=DEFAULT_SDKCONFIG)
    parser.add_argument("--require-production", action="store_true")
    args = parser.parse_args()
    try:
        result = validate_release(
            args.profile,
            args.metadata,
            args.partitions,
            args.sdkconfig,
            args.require_production,
        )
    except ReleaseValidationError as exc:
        print(f"release validation failed: {exc}")
        return 1

    profile = result["profile"]
    state = "production-eligible" if profile["production_release_allowed"] else "development-only"
    print(
        "release validation OK: "
        f"{profile['device']} v{profile['firmware_version']} "
        f"protocol={profile['protocol_version']} storage={profile['storage_schema_version']} "
        f"security={profile['security_backend']} profile={state}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
