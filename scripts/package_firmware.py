#!/usr/bin/env python3
"""Package one CI-built merged firmware image for Releases, Web Flasher, and M5Burner."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import zipfile
from pathlib import Path

from validate_release import ReleaseValidationError, validate_release


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def package_firmware(
    merged_binary: Path,
    output_dir: Path,
    build_commit: str,
    require_production: bool = False,
) -> list[Path]:
    result = validate_release(require_production=require_production)
    profile = result["profile"]

    if not merged_binary.is_file():
        raise ReleaseValidationError(f"merged firmware not found: {merged_binary}")
    merged_size = merged_binary.stat().st_size
    if merged_size <= 0:
        raise ReleaseValidationError("merged firmware is empty")
    auth_start = int(profile["auth_nvs_offset"])
    if merged_size > auth_start:
        raise ReleaseValidationError("merged firmware would overlap auth_nvs")
    if not build_commit or len(build_commit) > 64 or any(ch.isspace() for ch in build_commit):
        raise ReleaseValidationError("invalid build commit metadata")

    output_dir.mkdir(parents=True, exist_ok=True)
    for child in output_dir.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()

    version = str(profile["firmware_version"])
    firmware_name = f"m5authenticator-v{version}-m5sticks3.bin"
    firmware_path = output_dir / firmware_name
    shutil.copyfile(merged_binary, firmware_path)

    common_build = {
        "chipFamily": profile["chip_family"],
        "parts": [{"path": firmware_name, "offset": 0}],
    }
    factory_manifest = output_dir / "factory-manifest.json"
    update_manifest = output_dir / "update-manifest.json"
    write_json(
        factory_manifest,
        {
            "name": "M5Authenticator",
            "version": version,
            "new_install_prompt_erase": False,
            "improv": False,
            "builds": [common_build],
        },
    )
    write_json(
        update_manifest,
        {
            "name": "M5Authenticator",
            "version": version,
            "new_install_prompt_erase": True,
            "improv": False,
            "builds": [common_build],
        },
    )

    metadata_path = output_dir / "release-metadata.json"
    write_json(
        metadata_path,
        {
            "format": 1,
            "device": profile["device"],
            "chip_family": profile["chip_family"],
            "firmware_version": version,
            "protocol_version": profile["protocol_version"],
            "storage_schema_version": profile["storage_schema_version"],
            "build_commit": build_commit,
            "security_backend": profile["security_backend"],
            "production_release_allowed": profile["production_release_allowed"],
            "flash_offset": 0,
            "merged_image_bytes": merged_size,
            "auth_nvs_offset": profile["auth_nvs_offset"],
            "auth_nvs_size": profile["auth_nvs_size"],
        },
    )

    m5_root = output_dir / "m5burner"
    m5_firmware = m5_root / "firmware"
    m5_firmware.mkdir(parents=True)
    m5_binary = m5_firmware / "m5authenticator_0x0.bin"
    shutil.copyfile(merged_binary, m5_binary)
    write_json(
        m5_root / "m5burner.json",
        {
            "name": "M5Authenticator",
            "description": "Dedicated TOTP authenticator for M5StickS3",
            "keywords": "M5StickS3,TOTP,Authenticator",
            "author": "miso-develop",
            "repository": "https://github.com/miso-develop/m5authenticator",
            "firmware_category": {
                "M5StickS3": {
                    "path": "firmware",
                    "device": ["M5StickS3"],
                    "default_baud": 921600,
                }
            },
            "version": version,
            "framework": "ESP-IDF",
        },
    )

    m5_zip = output_dir / f"m5authenticator-v{version}-m5sticks3-m5burner.zip"
    with zipfile.ZipFile(m5_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(m5_root / "m5burner.json", "m5burner.json")
        archive.write(m5_binary, "firmware/m5authenticator_0x0.bin")
    shutil.rmtree(m5_root)

    checksum_targets = [firmware_path, factory_manifest, update_manifest, metadata_path, m5_zip]
    checksums = output_dir / "SHA256SUMS"
    checksums.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in checksum_targets),
        encoding="utf-8",
    )
    return checksum_targets + [checksums]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--merged-binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--build-commit", required=True)
    parser.add_argument("--require-production", action="store_true")
    args = parser.parse_args()
    try:
        outputs = package_firmware(
            args.merged_binary,
            args.output_dir,
            args.build_commit,
            args.require_production,
        )
    except ReleaseValidationError as exc:
        print(f"firmware packaging failed: {exc}")
        return 1

    for path in outputs:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
