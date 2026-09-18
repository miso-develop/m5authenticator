#!/usr/bin/env python3
"""Generate deterministic custom provenance for signed release-asset attestations."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import esp_idf_build_image

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PREDICATE_TYPE = (
    "https://miso-develop.github.io/m5authenticator/"
    "attestations/release-provenance/v1"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_sha(value: str, label: str) -> str:
    value = value.strip().lower()
    if not SHA_RE.fullmatch(value):
        raise ValueError(f"{label} must be a full 40-character lowercase Git SHA")
    return value


def require_regular_package_file(package_dir: Path, name: str) -> Path:
    if Path(name).name != name:
        raise ValueError(f"invalid package filename in checksum manifest: {name}")
    path = package_dir / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"release package subject must be a regular file: {name}")
    return path


def parse_and_verify_checksums(package_dir: Path) -> list[dict[str, str]]:
    checksums_path = package_dir / "SHA256SUMS"
    if checksums_path.is_symlink() or not checksums_path.is_file():
        raise ValueError("SHA256SUMS must be a regular file")

    subjects: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw_line in checksums_path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip():
            continue
        parts = raw_line.split()
        if len(parts) != 2:
            raise ValueError(f"invalid SHA256SUMS line: {raw_line}")
        digest, name = parts
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"invalid SHA-256 digest for {name}")
        if name in seen:
            raise ValueError(f"duplicate SHA256SUMS subject: {name}")
        path = require_regular_package_file(package_dir, name)
        actual = sha256(path)
        if actual != digest:
            raise ValueError(f"release package digest mismatch for {name}")
        seen.add(name)
        subjects.append({"name": name, "sha256": digest})

    if not subjects:
        raise ValueError("SHA256SUMS contains no release subjects")
    return sorted(subjects, key=lambda item: item["name"])


def build_predicate(
    package_dir: Path,
    source_commit: str,
    repository: str,
    workflow_ref: str,
    workflow_sha: str,
    run_id: str,
    run_attempt: str,
) -> dict[str, Any]:
    source = normalize_sha(source_commit, "source commit")
    workflow_commit = normalize_sha(workflow_sha, "workflow SHA")
    if not repository or "/" not in repository:
        raise ValueError("repository identity is required")
    if not workflow_ref:
        raise ValueError("workflow_ref is required")
    if not run_id.isdigit() or not run_attempt.isdigit():
        raise ValueError("run_id and run_attempt must be decimal integers")

    subjects = parse_and_verify_checksums(package_dir)
    metadata_path = require_regular_package_file(package_dir, "release-metadata.json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("build_commit") != source:
        raise ValueError("release metadata build_commit does not match source commit")
    if metadata.get("exact_release") is not True:
        raise ValueError("release metadata is not marked exact_release")

    build_environment = metadata.get("build_environment")
    if not isinstance(build_environment, dict):
        raise ValueError("release metadata build_environment is missing")
    esp_idf = build_environment.get("esp_idf")
    expected_esp_idf = esp_idf_build_image.provenance()
    if esp_idf != expected_esp_idf:
        raise ValueError("release metadata ESP-IDF provenance does not match immutable build identity")

    checksums_path = package_dir / "SHA256SUMS"
    return {
        "format": 1,
        "predicate_type": PREDICATE_TYPE,
        "source_commit": source,
        "workflow": {
            "repository": repository,
            "workflow_ref": workflow_ref,
            "workflow_sha": workflow_commit,
            "run_id": int(run_id),
            "run_attempt": int(run_attempt),
        },
        "build_environment": {
            "esp_idf": expected_esp_idf,
        },
        "sha256sums_sha256": sha256(checksums_path),
        "artifacts": subjects,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-dir", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        predicate = build_predicate(
            args.package_dir,
            args.source_commit,
            args.repository,
            args.workflow_ref,
            args.workflow_sha,
            args.run_id,
            args.run_attempt,
        )
        args.output.write_text(
            json.dumps(predicate, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Release attestation predicate generation failed: {exc}")
        return 1

    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
