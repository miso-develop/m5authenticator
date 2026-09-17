#!/usr/bin/env python3
"""Run the official ESP-IDF build against a disposable firmware-only source copy."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
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
        "set -euo pipefail && "
        "gcc -std=c11 -I\"$IDF_PATH/components/json/cJSON\" "
        "-c \"$IDF_PATH/components/json/cJSON/cJSON.c\" -o /tmp/m5auth-cjson.o && "
        "g++ -std=c++20 -Wall -Wextra -Werror -pthread "
        "-Icomponents/m5auth_provisioning/test_host/stubs "
        "-Icomponents/m5auth_core/include "
        "-Icomponents/m5auth_provisioning/include "
        "-Icomponents/m5auth_registration/include "
        "-Icomponents/m5auth_session/include "
        "-Icomponents/m5auth_time/include "
        "-Icomponents/m5auth_vault/include "
        "-Icomponents/m5auth_vault_runtime/include "
        "-I\"$IDF_PATH/components/json/cJSON\" "
        "components/m5auth_provisioning/canonical_protocol_v2.cpp "
        "components/m5auth_session/session_protocol_v2.cpp "
        "components/m5auth_session/p256_public_key.cpp "
        "components/m5auth_session/user_presence.cpp "
        "components/m5auth_vault/vault_format.cpp "
        "components/m5auth_vault/vault_crypto.cpp "
        "components/m5auth_vault_runtime/runtime.cpp "
        "components/m5auth_provisioning/test_host/canonical_factory_reset_protocol_test.cpp "
        "/tmp/m5auth-cjson.o -lcrypto "
        "-o /tmp/m5auth-canonical-factory-reset-protocol-test && "
        "/tmp/m5auth-canonical-factory-reset-protocol-test && "
        "idf.py set-target esp32s3 && idf.py build && "
        "idf.py merge-bin -o m5authenticator-merged.bin -f raw",
    ]


def _absolute_without_symlink_resolution(path: Path) -> Path:
    return Path(os.path.abspath(path))


def require_contained_regular_file(root: Path, candidate: Path) -> Path:
    """Validate container-controlled filesystem metadata before reading file bytes."""
    root = _absolute_without_symlink_resolution(root)
    candidate = _absolute_without_symlink_resolution(candidate)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"untrusted file escapes isolated root: {candidate}") from exc
    if not relative.parts:
        raise ValueError("untrusted file path must name a file beneath the isolated root")

    try:
        root_mode = root.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"isolated root is unavailable: {root}") from exc
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise ValueError(f"isolated root must be a real directory: {root}")

    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise ValueError(f"untrusted file path is unavailable: {current}") from exc
        if stat.S_ISLNK(mode):
            raise ValueError(f"untrusted file path contains a symlink: {current}")
        if index < len(relative.parts) - 1:
            if not stat.S_ISDIR(mode):
                raise ValueError(f"untrusted file parent is not a directory: {current}")
        elif not stat.S_ISREG(mode):
            raise ValueError(f"untrusted file is not a regular file: {current}")

    resolved_root = root.resolve(strict=True)
    resolved_candidate = candidate.resolve(strict=True)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"untrusted file resolves outside isolated root: {candidate}") from exc
    return resolved_candidate


def verify_dependency_lock(authoritative_firmware: Path, isolated_firmware: Path) -> None:
    authoritative_lock = authoritative_firmware / "dependencies.lock"
    isolated_lock = require_contained_regular_file(
        isolated_firmware,
        isolated_firmware / "dependencies.lock",
    )
    if not authoritative_lock.is_file():
        raise RuntimeError("authoritative ESP-IDF dependency lockfile is missing")
    if authoritative_lock.read_bytes() != isolated_lock.read_bytes():
        raise RuntimeError("ESP-IDF build changed dependencies.lock in the isolated workspace")


def verify_build_outputs(isolated_firmware: Path) -> None:
    errors: list[str] = []
    for relative_path in EXPECTED_BUILD_OUTPUTS:
        try:
            require_contained_regular_file(
                isolated_firmware,
                isolated_firmware / relative_path,
            )
        except ValueError as exc:
            errors.append(f"{relative_path}: {exc}")
    if errors:
        raise RuntimeError("invalid ESP-IDF build outputs: " + "; ".join(errors))


def run_isolated_build(
    source_root: Path,
    work_root: Path,
    image_reference: str,
) -> Path:
    source_root = source_root.resolve()
    isolated_firmware = prepare_isolated_firmware(source_root, work_root)
    subprocess.run(docker_command(isolated_firmware, image_reference), check=True)
    # Validate all expected container-controlled output metadata before any
    # post-container content read. Only after that metadata gate do we compare
    # dependency-lock bytes with authoritative repository state.
    verify_build_outputs(isolated_firmware)
    verify_dependency_lock(source_root / "firmware", isolated_firmware)
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
