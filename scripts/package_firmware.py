#!/usr/bin/env python3
"""Package CI-built firmware for destructive install and state-preserving update."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

from validate_release import ReleaseValidationError, validate_release

UPDATE_BOOTLOADER_OFFSET = 0x000000
UPDATE_PARTITION_TABLE_OFFSET = 0x008000
UPDATE_APP_OFFSET = 0x030000
BUILD_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def require_binary(path: Path, label: str) -> int:
    if not path.is_file():
        raise ReleaseValidationError(f"{label} not found: {path}")
    size = path.stat().st_size
    if size <= 0:
        raise ReleaseValidationError(f"{label} is empty")
    return size


def ranges_overlap(left_start: int, left_end: int, right_start: int, right_end: int) -> bool:
    return left_start < right_end and right_start < left_end


def validate_update_write_plan(
    bootloader_binary: Path,
    partition_table_binary: Path,
    app_binary: Path,
    partitions: dict[str, dict[str, int | str]],
) -> list[dict[str, Any]]:
    if "nvs" not in partitions or "ota_0" not in partitions or "auth_nvs" not in partitions:
        raise ReleaseValidationError("Normal Update requires nvs, ota_0, and auth_nvs partitions")

    nvs_start = int(partitions["nvs"]["offset"])
    ota0_start = int(partitions["ota_0"]["offset"])
    ota0_end = ota0_start + int(partitions["ota_0"]["size"])

    if nvs_start != 0x009000:
        raise ReleaseValidationError("Normal Update contract requires ordinary nvs at 0x9000")
    if ota0_start != UPDATE_APP_OFFSET:
        raise ReleaseValidationError("Normal Update contract requires ota_0 at 0x30000")

    sizes = {
        "bootloader": require_binary(bootloader_binary, "bootloader binary"),
        "partition_table": require_binary(partition_table_binary, "partition table binary"),
        "ota_0": require_binary(app_binary, "ota_0 application binary"),
    }

    plan: list[dict[str, Any]] = [
        {
            "name": "bootloader",
            "source": bootloader_binary,
            "offset": UPDATE_BOOTLOADER_OFFSET,
            "size": sizes["bootloader"],
            "range_end": UPDATE_PARTITION_TABLE_OFFSET,
        },
        {
            "name": "partition_table",
            "source": partition_table_binary,
            "offset": UPDATE_PARTITION_TABLE_OFFSET,
            "size": sizes["partition_table"],
            "range_end": nvs_start,
        },
        {
            "name": "ota_0",
            "source": app_binary,
            "offset": ota0_start,
            "size": sizes["ota_0"],
            "range_end": ota0_end,
        },
    ]

    for part in plan:
        start = int(part["offset"])
        end = start + int(part["size"])
        if end > int(part["range_end"]):
            raise ReleaseValidationError(
                f"Normal Update {part['name']} binary exceeds allowed write window: "
                f"0x{start:x}-0x{end:x}"
            )

        for partition_name, partition in partitions.items():
            persistent_start = int(partition["offset"])
            persistent_end = persistent_start + int(partition["size"])
            if not ranges_overlap(start, end, persistent_start, persistent_end):
                continue
            if part["name"] == "ota_0" and partition_name == "ota_0":
                continue
            raise ReleaseValidationError(
                f"Normal Update {part['name']} write range overlaps partition {partition_name}"
            )

    return plan


def package_firmware(
    merged_binary: Path,
    bootloader_binary: Path,
    partition_table_binary: Path,
    app_binary: Path,
    output_dir: Path,
    build_commit: str,
    require_production: bool = False,
    exact_release: bool = False,
) -> list[Path]:
    result = validate_release(require_production=require_production)
    profile = result["profile"]
    partitions = result["partitions"]

    merged_size = require_binary(merged_binary, "merged firmware")
    auth_start = int(profile["auth_nvs_offset"])
    if merged_size > auth_start:
        raise ReleaseValidationError("merged firmware would overlap auth_nvs")
    if not BUILD_COMMIT_RE.fullmatch(build_commit):
        raise ReleaseValidationError("invalid build commit metadata")
    build_commit = build_commit.lower()

    update_plan = validate_update_write_plan(
        bootloader_binary,
        partition_table_binary,
        app_binary,
        partitions,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    for child in output_dir.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()

    version = str(profile["firmware_version"])
    build_suffix = f"{version}-{build_commit}"
    firmware_name = f"m5authenticator-v{build_suffix}-m5sticks3.bin"
    firmware_path = output_dir / firmware_name
    shutil.copyfile(merged_binary, firmware_path)

    update_names = {
        "bootloader": f"m5authenticator-v{build_suffix}-m5sticks3-update-bootloader.bin",
        "partition_table": f"m5authenticator-v{build_suffix}-m5sticks3-update-partition-table.bin",
        "ota_0": f"m5authenticator-v{build_suffix}-m5sticks3-update-ota0.bin",
    }
    update_outputs: list[Path] = []
    update_manifest_parts: list[dict[str, int | str]] = []
    update_metadata_parts: list[dict[str, int | str]] = []
    for part in update_plan:
        name = str(part["name"])
        output_path = output_dir / update_names[name]
        shutil.copyfile(Path(part["source"]), output_path)
        update_outputs.append(output_path)
        update_manifest_parts.append({"path": output_path.name, "offset": int(part["offset"])})
        update_metadata_parts.append(
            {
                "name": name,
                "path": output_path.name,
                "offset": int(part["offset"]),
                "bytes": int(part["size"]),
            }
        )

    artifact_identity = {
        "name": "M5Authenticator",
        "version": version,
        "build_commit": build_commit,
        "exact_release": exact_release,
    }

    factory_manifest_value = {
        **artifact_identity,
        "new_install_prompt_erase": False,
        "improv": False,
        "builds": [
            {
                "chipFamily": profile["chip_family"],
                "parts": [{"path": firmware_name, "offset": 0}],
            }
        ],
    }
    update_manifest_value = {
        **artifact_identity,
        # Normal Update is executed only by the M5Authenticator low-level
        # flasher with eraseFirst=false. Retain the generic erase warning if
        # the manifest is opened outside that UI.
        "new_install_prompt_erase": True,
        "improv": False,
        "builds": [
            {
                "chipFamily": profile["chip_family"],
                "parts": update_manifest_parts,
            }
        ],
    }

    pinned_factory_manifest = output_dir / f"factory-manifest-{build_commit}.json"
    pinned_update_manifest = output_dir / f"update-manifest-{build_commit}.json"
    write_json(pinned_factory_manifest, factory_manifest_value)
    write_json(pinned_update_manifest, update_manifest_value)

    # Keep stable manifest aliases for external/manual consumers, but the Web UI
    # never binds flashing to these mutable names. The browser first resolves
    # firmware-target.json and then uses only the commit-addressed manifests.
    factory_manifest = output_dir / "factory-manifest.json"
    update_manifest = output_dir / "update-manifest.json"
    write_json(factory_manifest, factory_manifest_value)
    write_json(update_manifest, update_manifest_value)

    target_path = output_dir / "firmware-target.json"
    write_json(
        target_path,
        {
            **artifact_identity,
            "factory_manifest": pinned_factory_manifest.name,
            "update_manifest": pinned_update_manifest.name,
        },
    )

    untouched_partitions = [name for name in partitions if name != "ota_0"]
    metadata_path = output_dir / "release-metadata.json"
    write_json(
        metadata_path,
        {
            "format": 2,
            "device": profile["device"],
            "chip_family": profile["chip_family"],
            "firmware_version": version,
            "protocol_version": profile["protocol_version"],
            "storage_schema_version": profile["storage_schema_version"],
            "vault_format_version": profile["vault_format_version"],
            "security_profile": profile["security_profile"],
            "security_profile_version": profile["security_profile_version"],
            "vmk_persistence": profile["vmk_persistence"],
            "post_update_state": profile["post_update_state"],
            "build_commit": build_commit,
            "exact_release": exact_release,
            "production_release_allowed": profile["production_release_allowed"],
            "flash_offset": 0,
            "merged_image_bytes": merged_size,
            "auth_nvs_offset": profile["auth_nvs_offset"],
            "auth_nvs_size": profile["auth_nvs_size"],
            "normal_update": {
                "erase_first": False,
                "parts": update_metadata_parts,
                "untouched_partitions": untouched_partitions,
                "required_preserve_partitions": ["nvs", "auth_nvs"],
            },
        },
    )

    # M5Burner USER CUSTOM -> Publish uses only the merged image. The separate
    # update parts exist solely for the state-preserving GitHub Pages path.
    checksum_targets = [
        firmware_path,
        *update_outputs,
        pinned_factory_manifest,
        pinned_update_manifest,
        factory_manifest,
        update_manifest,
        target_path,
        metadata_path,
    ]
    checksums = output_dir / "SHA256SUMS"
    checksums.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in checksum_targets),
        encoding="utf-8",
    )
    return checksum_targets + [checksums]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--merged-binary", type=Path, required=True)
    parser.add_argument("--bootloader-binary", type=Path)
    parser.add_argument("--partition-table-binary", type=Path)
    parser.add_argument("--app-binary", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--build-commit", required=True)
    parser.add_argument("--require-production", action="store_true")
    parser.add_argument("--exact-release", action="store_true")
    args = parser.parse_args()

    build_dir = args.merged_binary.parent
    bootloader_binary = args.bootloader_binary or build_dir / "bootloader" / "bootloader.bin"
    partition_table_binary = args.partition_table_binary or build_dir / "partition_table" / "partition-table.bin"
    app_binary = args.app_binary or build_dir / "m5authenticator.bin"

    try:
        outputs = package_firmware(
            args.merged_binary,
            bootloader_binary,
            partition_table_binary,
            app_binary,
            args.output_dir,
            args.build_commit,
            args.require_production,
            args.exact_release,
        )
    except ReleaseValidationError as exc:
        print(f"firmware packaging failed: {exc}")
        return 1

    for path in outputs:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
