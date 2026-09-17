#!/usr/bin/env python3
"""Run the official ESP-IDF build against a disposable firmware-only source copy."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

import esp_idf_build_image


EXPECTED_BUILD_OUTPUTS = (
    Path("build/m5authenticator-merged.bin"),
    Path("build/bootloader/bootloader.bin"),
    Path("build/partition_table/partition-table.bin"),
    Path("build/m5authenticator.bin"),
)


def prepare_isolated_firmware(source_root: Path, work_root: Path) -> Path:
    source_root = source_root.resolve()
    work_root = work_root.resolve()
    if (
        source_root == work_root
        or source_root in work_root.parents
        or work_root in source_root.parents
    ):
        raise ValueError(
            "isolated build workspace must be disjoint from the authoritative checkout"
        )

    source_firmware = source_root / "firmware"
    if not source_firmware.is_dir():
        raise ValueError(f"firmware source directory not found: {source_firmware}")

    if work_root.exists():
        shutil.rmtree(work_root)
    isolated_firmware = work_root / "firmware"
    work_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_firmware, isolated_firmware)
    return isolated_firmware


def docker_command(isolated_firmware: Path, image_reference: str) -> list[str]:
    isolated_firmware = isolated_firmware.resolve()
    if image_reference != esp_idf_build_image.ESP_IDF_IMAGE_REFERENCE:
        raise ValueError("ESP-IDF image reference does not match the repository-owned immutable identity")
    return [
        "docker",
        "run",
        "--rm",
        "--mount",
        f"type=bind,source={isolated_firmware},target=/project/firmware",
        "-w",
        "/project/firmware",
        image_reference,
        "bash",
        "-lc",
        "idf.py set-target esp32s3 && idf.py build && "
        "idf.py merge-bin -o m5authenticator-merged.bin -f raw",
    ]


def verify_dependency_lock(authoritative_firmware: Path, isolated_firmware: Path) -> None:
    authoritative_lock = authoritative_firmware / "dependencies.lock"
    isolated_lock = isolated_firmware / "dependencies.lock"
    if not authoritative_lock.is_file() or not isolated_lock.is_file():
        raise RuntimeError("ESP-IDF dependency lockfile is missing")
    if authoritative_lock.read_bytes() != isolated_lock.read_bytes():
        raise RuntimeError("ESP-IDF build changed dependencies.lock in the isolated workspace")


def verify_build_outputs(isolated_firmware: Path) -> None:
    missing = [str(path) for path in EXPECTED_BUILD_OUTPUTS if not (isolated_firmware / path).is_file()]
    if missing:
        raise RuntimeError("ESP-IDF build outputs missing: " + ", ".join(missing))


def run_isolated_build(
    source_root: Path,
    work_root: Path,
    image_reference: str,
) -> Path:
    source_root = source_root.resolve()
    isolated_firmware = prepare_isolated_firmware(source_root, work_root)
    subprocess.run(docker_command(isolated_firmware, image_reference), check=True)
    verify_dependency_lock(source_root / "firmware", isolated_firmware)
    verify_build_outputs(isolated_firmware)
    return isolated_firmware / "build"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--image-reference", required=True)
    args = parser.parse_args()

    try:
        build_dir = run_isolated_build(args.source_root, args.work_root, args.image_reference)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"isolated ESP-IDF build failed: {exc}")
        return 1

    print(build_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
