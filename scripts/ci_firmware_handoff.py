#!/usr/bin/env python3
"""Create and independently verify transient firmware CI handoffs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

import esp_idf_build_image


BUILD_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
BUILD_ARTIFACT_SOURCES = {
    "m5authenticator-merged.bin": Path("m5authenticator-merged.bin"),
    "bootloader.bin": Path("bootloader/bootloader.bin"),
    "partition-table.bin": Path("partition_table/partition-table.bin"),
    "m5authenticator.bin": Path("m5authenticator.bin"),
}
BUILD_PROVENANCE_NAME = "build-provenance.json"
DEPENDENCY_LOCK_NAME = "dependencies.lock"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_source_commit(source_commit: str) -> str:
    if not BUILD_COMMIT_RE.fullmatch(source_commit):
        raise ValueError("invalid source commit")
    return source_commit.lower()


def file_record(path: Path) -> dict[str, int | str]:
    if not path.is_file():
        raise ValueError(f"handoff file missing: {path}")
    size = path.stat().st_size
    if size <= 0:
        raise ValueError(f"handoff file is empty: {path}")
    return {"path": path.name, "bytes": size, "sha256": sha256(path)}


def clean_directory(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def create_build_handoff(
    build_dir: Path,
    isolated_firmware_dir: Path,
    artifact_dir: Path,
    source_commit: str,
) -> None:
    source_commit = require_source_commit(source_commit)
    clean_directory(artifact_dir)

    for output_name, relative_source in BUILD_ARTIFACT_SOURCES.items():
        source = build_dir / relative_source
        if not source.is_file():
            raise ValueError(f"build output missing: {source}")
        shutil.copyfile(source, artifact_dir / output_name)

    dependency_lock = isolated_firmware_dir / DEPENDENCY_LOCK_NAME
    if not dependency_lock.is_file():
        raise ValueError(f"dependency lock missing: {dependency_lock}")
    shutil.copyfile(dependency_lock, artifact_dir / DEPENDENCY_LOCK_NAME)

    records = [
        file_record(artifact_dir / name)
        for name in sorted((*BUILD_ARTIFACT_SOURCES.keys(), DEPENDENCY_LOCK_NAME))
    ]
    provenance = {
        "format": 1,
        "source_commit": source_commit,
        "esp_idf": esp_idf_build_image.provenance(),
        "files": records,
    }
    (artifact_dir / BUILD_PROVENANCE_NAME).write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_build_provenance(artifact_dir: Path) -> dict[str, Any]:
    path = artifact_dir / BUILD_PROVENANCE_NAME
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid build provenance: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("build provenance must be an object")
    return value


def verify_build_handoff(artifact_dir: Path, source_commit: str, expected_lock: Path) -> dict[str, Any]:
    source_commit = require_source_commit(source_commit)
    expected_names = set(BUILD_ARTIFACT_SOURCES) | {DEPENDENCY_LOCK_NAME, BUILD_PROVENANCE_NAME}
    actual_names = {path.name for path in artifact_dir.iterdir() if path.is_file()}
    if actual_names != expected_names:
        raise ValueError(
            f"unexpected build handoff file set: expected {sorted(expected_names)}, got {sorted(actual_names)}"
        )

    provenance = load_build_provenance(artifact_dir)
    if provenance.get("format") != 1:
        raise ValueError("unsupported build provenance format")
    if provenance.get("source_commit") != source_commit:
        raise ValueError("build provenance source commit mismatch")
    if provenance.get("esp_idf") != esp_idf_build_image.provenance():
        raise ValueError("build provenance ESP-IDF identity mismatch")

    records = provenance.get("files")
    if not isinstance(records, list):
        raise ValueError("build provenance files must be a list")
    record_by_name: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise ValueError("invalid build provenance file record")
        name = str(record["path"])
        if name in record_by_name:
            raise ValueError(f"duplicate build provenance file: {name}")
        record_by_name[name] = record

    expected_payload_names = expected_names - {BUILD_PROVENANCE_NAME}
    if set(record_by_name) != expected_payload_names:
        raise ValueError("build provenance file set mismatch")
    for name, record in record_by_name.items():
        path = artifact_dir / name
        current = file_record(path)
        if record != current:
            raise ValueError(f"build handoff digest/size mismatch: {name}")

    if not expected_lock.is_file():
        raise ValueError(f"authoritative dependency lock missing: {expected_lock}")
    if (artifact_dir / DEPENDENCY_LOCK_NAME).read_bytes() != expected_lock.read_bytes():
        raise ValueError("build handoff dependency lock differs from authoritative source")
    return provenance


def parse_sha256sums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"cannot read SHA256SUMS: {exc}") from exc
    for line in lines:
        parts = line.split("  ", 1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise ValueError(f"invalid SHA256SUMS line: {line!r}")
        name = parts[1]
        if not name or Path(name).name != name or name in checksums:
            raise ValueError(f"invalid SHA256SUMS path: {name!r}")
        checksums[name] = parts[0]
    if not checksums:
        raise ValueError("SHA256SUMS is empty")
    return checksums


def verify_release_package(
    package_dir: Path,
    build_provenance_path: Path,
    source_commit: str,
) -> str:
    source_commit = require_source_commit(source_commit)
    try:
        build_provenance = json.loads(build_provenance_path.read_text(encoding="utf-8"))
        metadata = json.loads((package_dir / "release-metadata.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid release handoff metadata: {exc}") from exc

    if build_provenance.get("source_commit") != source_commit:
        raise ValueError("release handoff build source commit mismatch")
    if build_provenance.get("esp_idf") != esp_idf_build_image.provenance():
        raise ValueError("release handoff ESP-IDF provenance mismatch")
    if metadata.get("build_commit") != source_commit:
        raise ValueError("release metadata build commit mismatch")
    if metadata.get("build_environment", {}).get("esp_idf") != build_provenance.get("esp_idf"):
        raise ValueError("release metadata does not preserve build ESP-IDF provenance")

    checksum_path = package_dir / "SHA256SUMS"
    checksums = parse_sha256sums(checksum_path)
    actual_payload_names = {
        path.name for path in package_dir.iterdir() if path.is_file() and path.name != "SHA256SUMS"
    }
    if set(checksums) != actual_payload_names:
        raise ValueError("SHA256SUMS does not exactly cover the release package payload")
    for name, expected_digest in checksums.items():
        if sha256(package_dir / name) != expected_digest:
            raise ValueError(f"release package checksum mismatch: {name}")
    return sha256(checksum_path)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create-build")
    create.add_argument("--build-dir", type=Path, required=True)
    create.add_argument("--isolated-firmware-dir", type=Path, required=True)
    create.add_argument("--artifact-dir", type=Path, required=True)
    create.add_argument("--source-commit", required=True)

    verify = subparsers.add_parser("verify-build")
    verify.add_argument("--artifact-dir", type=Path, required=True)
    verify.add_argument("--source-commit", required=True)
    verify.add_argument("--expected-lock", type=Path, required=True)

    verify_release = subparsers.add_parser("verify-release-package")
    verify_release.add_argument("--package-dir", type=Path, required=True)
    verify_release.add_argument("--build-provenance", type=Path, required=True)
    verify_release.add_argument("--source-commit", required=True)

    args = parser.parse_args()
    try:
        if args.command == "create-build":
            create_build_handoff(
                args.build_dir,
                args.isolated_firmware_dir,
                args.artifact_dir,
                args.source_commit,
            )
        elif args.command == "verify-build":
            verify_build_handoff(args.artifact_dir, args.source_commit, args.expected_lock)
        else:
            print(
                verify_release_package(
                    args.package_dir,
                    args.build_provenance,
                    args.source_commit,
                )
            )
    except (OSError, ValueError) as exc:
        print(f"CI firmware handoff verification failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
