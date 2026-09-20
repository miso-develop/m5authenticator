#!/usr/bin/env python3
"""Verify exact-current-main Web + immutable released firmware Pages inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import ci_firmware_handoff
import release_authorization
import validate_release

REPOSITORY = "miso-develop/m5authenticator"
AUTHORIZED_RELEASE_WORKFLOW_REF = (
    "miso-develop/m5authenticator/.github/workflows/release-authorized.yml@refs/heads/main"
)
CUSTOM_PREDICATE_TYPE = (
    "https://miso-develop.github.io/m5authenticator/"
    "attestations/release-provenance/v1"
)
STANDARD_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SEMVER_TAG_RE = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HISTORICAL_SOURCE_BLOB_PATHS = (
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
SOURCE_VALIDATION_FORMAT = 1
SOURCE_VALIDATION_KEYS = {
    "format",
    "release_tag",
    "firmware_version",
    "firmware_source_sha",
    "release_profile",
    "metadata",
    "project_version",
    "partitions",
    "validated_paths",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {exc}") from exc


def normalize_release_tag(tag: str) -> tuple[str, str]:
    value = tag.strip()
    if not SEMVER_TAG_RE.fullmatch(value):
        raise ValueError("firmware release tag must be canonical vX.Y.Z")
    return value, value[1:]


def require_safe_asset_name(name: object) -> str:
    if not isinstance(name, str) or not name:
        raise ValueError("Release asset name must be a non-empty string")
    if (
        name in {".", ".."}
        or "/" in name
        or "\\" in name
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)
    ):
        raise ValueError(f"unsafe Release asset name: {name!r}")
    if Path(name).name != name:
        raise ValueError(f"unsafe Release asset basename: {name!r}")
    return name


def require_regular_file(path: Path, label: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"{label} is missing: {path}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise ValueError(f"{label} must be a regular file: {path}")
    return path


def require_web_authorization(
    *,
    source_ref: str,
    workflow_sha: str,
    requested_web_sha: str,
    current_main: str,
    deployment_ack: str,
    main_rules_payload: object,
    check_runs_payload: dict[str, Any],
    statuses_payload: dict[str, Any],
) -> str:
    if source_ref != "refs/heads/main":
        raise ValueError("Web-only Pages workflow must run from refs/heads/main")
    if deployment_ack != "true":
        raise ValueError("Web-only Pages deployment requires explicit acknowledgement")
    workflow = release_authorization.normalize_sha(workflow_sha, "workflow SHA")
    requested = release_authorization.normalize_sha(requested_web_sha, "requested Web SHA")
    main = release_authorization.normalize_sha(current_main, "current main SHA")
    if workflow != main:
        raise ValueError("workflow source SHA is not fresh current main")
    if requested != main:
        raise ValueError("requested Web SHA is not fresh current main")
    release_authorization.require_protected_main_checks(
        main,
        main_rules_payload,
        check_runs_payload,
        statuses_payload,
    )
    return main


def select_tag_immutability_ruleset_id(payload: object) -> int:
    if not isinstance(payload, list):
        raise ValueError("rulesets payload must be a list")
    matches = [
        item
        for item in payload
        if isinstance(item, dict)
        and item.get("name") == "SemVer tag immutability"
        and item.get("target") == "tag"
        and item.get("enforcement") == "active"
    ]
    if len(matches) != 1:
        raise ValueError("exact active SemVer tag immutability Ruleset was not found uniquely")
    ruleset_id = matches[0].get("id")
    if not isinstance(ruleset_id, int) or ruleset_id <= 0:
        raise ValueError("SemVer tag immutability Ruleset id is invalid")
    return ruleset_id


def require_ancestor(repo_root: Path, source_sha: str, web_sha: str) -> None:
    source = release_authorization.normalize_sha(source_sha, "firmware source SHA")
    web = release_authorization.normalize_sha(web_sha, "Web SHA")
    try:
        completed = subprocess.run(
            ["git", "merge-base", "--is-ancestor", source, web],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise ValueError(f"cannot start git ancestry verification: {exc}") from exc
    if completed.returncode == 1:
        raise ValueError("firmware release source is not an ancestor of current Web SHA")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"cannot prove firmware release ancestry: {detail or completed.returncode}")


def require_compatible_profiles(
    current_profile: object,
    release_profile: object,
) -> tuple[str, str]:
    if not isinstance(current_profile, dict) or not isinstance(release_profile, dict):
        raise ValueError("release profiles must be JSON objects")
    current_version = current_profile.get("firmware_version")
    release_version = release_profile.get("firmware_version")
    if not isinstance(current_version, str) or not isinstance(release_version, str):
        raise ValueError("release profiles must contain firmware_version strings")

    current_normalized = dict(current_profile)
    release_normalized = dict(release_profile)
    current_normalized.pop("firmware_version", None)
    release_normalized.pop("firmware_version", None)
    if current_normalized != release_normalized:
        current_keys = set(current_normalized)
        release_keys = set(release_normalized)
        differing = sorted(
            (current_keys ^ release_keys)
            | {
                key
                for key in current_keys & release_keys
                if current_normalized[key] != release_normalized[key]
            }
        )
        raise ValueError(
            "current Web/released firmware compatibility profile mismatch outside "
            f"firmware_version: {differing}"
        )
    return current_version, release_version



def _run_git(repo_root: Path, args: list[str], label: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise ValueError(f"cannot start git {label}: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git {label} failed: {detail or completed.returncode}")
    return completed.stdout


def _read_historical_blob(repo_root: Path, source_sha: str, relative_path: str) -> bytes:
    if relative_path not in HISTORICAL_SOURCE_BLOB_PATHS:
        raise ValueError(f"historical source path is not allowlisted: {relative_path}")
    source = release_authorization.normalize_sha(source_sha, "firmware source SHA")
    listing = _run_git(
        repo_root,
        ["ls-tree", source, "--", relative_path],
        f"ls-tree {relative_path}",
    )
    try:
        line = listing.decode("utf-8").rstrip("\n")
    except UnicodeDecodeError as exc:
        raise ValueError(f"historical Git tree entry is not UTF-8: {relative_path}") from exc
    if not line or "\n" in line or "\t" not in line:
        raise ValueError(f"historical allowlisted path is missing or ambiguous: {relative_path}")
    metadata, actual_path = line.split("\t", 1)
    fields = metadata.split()
    if len(fields) != 3:
        raise ValueError(f"historical Git tree entry is malformed: {relative_path}")
    mode, object_type, object_sha = fields
    if actual_path != relative_path:
        raise ValueError(f"historical Git tree path mismatch: {relative_path}")
    if mode != "100644" or object_type != "blob":
        raise ValueError(
            f"historical allowlisted path must be ordinary non-executable blob 100644: "
            f"{relative_path} ({mode} {object_type})"
        )
    if not GIT_OBJECT_SHA_RE.fullmatch(object_sha):
        raise ValueError(f"historical Git blob identity is invalid: {relative_path}")
    return _run_git(repo_root, ["cat-file", "blob", object_sha], f"cat-file {relative_path}")


def _materialize_historical_validation_data(
    repo_root: Path,
    source_sha: str,
    data_root: Path,
) -> None:
    if data_root.exists():
        raise ValueError("historical validation data directory must not already exist")
    data_root.mkdir(parents=True)
    for relative_path in HISTORICAL_SOURCE_BLOB_PATHS:
        destination = data_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(_read_historical_blob(repo_root, source_sha, relative_path))
        destination.chmod(0o600)


def validate_historical_release_source(
    *,
    repo_root: Path,
    source_sha: str,
    release_tag: str,
    current_profile: object,
    temp_parent: Path,
) -> dict[str, Any]:
    source = release_authorization.normalize_sha(source_sha, "firmware source SHA")
    tag, version = normalize_release_tag(release_tag)
    if not isinstance(current_profile, dict):
        raise ValueError("current release profile must be an object")

    repo_resolved = repo_root.resolve()
    temp_parent_resolved = temp_parent.resolve()
    if temp_parent_resolved == repo_resolved or repo_resolved in temp_parent_resolved.parents:
        raise ValueError("historical validation data must be outside the current workspace")
    temp_parent_resolved.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory(
            prefix="m5auth-release-source-data-",
            dir=temp_parent_resolved,
        ) as directory:
            data_root = Path(directory) / "source"
            _materialize_historical_validation_data(repo_root, source, data_root)
            result = validate_release.validate_release(
                profile_path=data_root / "firmware/release-profile.json",
                metadata_path=(
                    data_root
                    / "firmware/components/m5auth_core/include/m5auth/core/metadata.hpp"
                ),
                project_cmake_path=data_root / "firmware/CMakeLists.txt",
                partitions_path=data_root / "firmware/partitions.csv",
                require_production=True,
                bootstrap_path=data_root / "firmware/main/app_main.cpp",
                sdkconfig_path=data_root / "firmware/sdkconfig.defaults",
                transport_header_path=data_root / "firmware/main/usb_protocol_transport.hpp",
                transport_cpp_path=data_root / "firmware/main/usb_protocol_transport.cpp",
                provisioning_cmake_path=(
                    data_root / "firmware/components/m5auth_provisioning/CMakeLists.txt"
                ),
                device_cmake_path=(
                    data_root / "firmware/components/m5auth_device_sticks3/CMakeLists.txt"
                ),
                time_cmake_path=data_root / "firmware/components/m5auth_time/CMakeLists.txt",
                totp_cmake_path=data_root / "firmware/components/m5auth_totp/CMakeLists.txt",
            )
    except validate_release.ReleaseValidationError as exc:
        raise ValueError(f"historical release source fails current-main validation: {exc}") from exc

    release_profile = result["profile"]
    _, release_version = require_compatible_profiles(current_profile, release_profile)
    if release_version != version:
        raise ValueError("historical release profile firmware_version does not match selected tag")

    return {
        "format": SOURCE_VALIDATION_FORMAT,
        "release_tag": tag,
        "firmware_version": release_version,
        "firmware_source_sha": source,
        "release_profile": release_profile,
        "metadata": result["metadata"],
        "project_version": result["project_version"],
        "partitions": result["partitions"],
        "validated_paths": list(HISTORICAL_SOURCE_BLOB_PATHS),
    }


def require_source_validation_result(
    payload: object,
    *,
    release_tag: str,
    source_sha: str,
) -> dict[str, Any]:
    tag, version = normalize_release_tag(release_tag)
    source = release_authorization.normalize_sha(source_sha, "firmware source SHA")
    if not isinstance(payload, dict) or set(payload) != SOURCE_VALIDATION_KEYS:
        raise ValueError("historical source validation result shape is invalid")
    if payload.get("format") != SOURCE_VALIDATION_FORMAT:
        raise ValueError("historical source validation result format is invalid")
    if payload.get("release_tag") != tag:
        raise ValueError("historical source validation release tag mismatch")
    if payload.get("firmware_version") != version:
        raise ValueError("historical source validation firmware version mismatch")
    if payload.get("firmware_source_sha") != source:
        raise ValueError("historical source validation source SHA mismatch")
    if payload.get("validated_paths") != list(HISTORICAL_SOURCE_BLOB_PATHS):
        raise ValueError("historical source validation path set mismatch")
    if not isinstance(payload.get("release_profile"), dict):
        raise ValueError("historical source validation release profile is invalid")
    if not isinstance(payload.get("metadata"), dict):
        raise ValueError("historical source validation metadata is invalid")
    if not isinstance(payload.get("project_version"), str):
        raise ValueError("historical source validation project version is invalid")
    if not isinstance(payload.get("partitions"), dict):
        raise ValueError("historical source validation partition facts are invalid")
    return payload


def require_release_authorization(
    *,
    repo_root: Path,
    web_sha: str,
    release_tag: str,
    tag_sha: str,
    release_payload: object,
    tag_ruleset_payload: object,
    current_profile: object,
    release_profile: object,
) -> dict[str, Any]:
    tag, version = normalize_release_tag(release_tag)
    source = release_authorization.normalize_sha(tag_sha, "firmware tag source SHA")
    web = release_authorization.normalize_sha(web_sha, "Web SHA")

    if not isinstance(release_payload, dict):
        raise ValueError("Release API payload must be an object")
    if release_payload.get("tag_name") != tag:
        raise ValueError("GitHub Release tag_name mismatch")
    if release_payload.get("draft") is not False:
        raise ValueError("GitHub Release must not be a draft")
    if release_payload.get("prerelease") is not False:
        raise ValueError("GitHub Release must not be a prerelease")
    if release_payload.get("immutable") is not True:
        raise ValueError("GitHub Release is not immutable")
    release_id = release_payload.get("id")
    if not isinstance(release_id, int) or release_id <= 0:
        raise ValueError("GitHub Release id is invalid")

    release_authorization.require_tag_immutability(tag_ruleset_payload)
    require_ancestor(repo_root, source, web)

    _, release_version = require_compatible_profiles(current_profile, release_profile)
    if release_version != version:
        raise ValueError("release-profile firmware_version does not match selected release tag")
    return {
        "release_id": release_id,
        "release_tag": tag,
        "firmware_version": release_version,
        "firmware_source_sha": source,
        "web_sha": web,
    }


def _release_assets(release_payload: object) -> dict[str, dict[str, Any]]:
    if not isinstance(release_payload, dict):
        raise ValueError("Release API payload must be an object")
    assets = release_payload.get("assets")
    if not isinstance(assets, list) or not assets:
        raise ValueError("GitHub Release contains no assets")

    by_name: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("GitHub Release asset metadata is invalid")
        name = require_safe_asset_name(asset.get("name"))
        if name in by_name:
            raise ValueError(f"duplicate GitHub Release asset name: {name}")
        size = asset.get("size")
        if not isinstance(size, int) or size <= 0:
            raise ValueError(f"GitHub Release asset has invalid size: {name}")
        digest_value = asset.get("digest")
        if (
            not isinstance(digest_value, str)
            or not digest_value.startswith("sha256:")
            or not SHA256_RE.fullmatch(digest_value[7:].lower())
        ):
            raise ValueError(f"GitHub Release asset has no exact SHA-256 digest: {name}")
        if asset.get("state") != "uploaded":
            raise ValueError(f"GitHub Release asset is not uploaded: {name}")
        by_name[name] = {
            "size": size,
            "sha256": digest_value[7:].lower(),
            "id": asset.get("id"),
        }
    if "SHA256SUMS" not in by_name:
        raise ValueError("GitHub Release is missing SHA256SUMS")
    return by_name



def preflight_release_assets(release_payload: object) -> int:
    """Validate Release asset metadata before any bytes are downloaded."""
    return len(_release_assets(release_payload))

def _directory_regular_files(directory: Path) -> dict[str, Path]:
    try:
        entries = list(directory.iterdir())
    except OSError as exc:
        raise ValueError(f"cannot enumerate directory {directory}: {exc}") from exc
    files: dict[str, Path] = {}
    for path in entries:
        require_regular_file(path, "Release package entry")
        name = require_safe_asset_name(path.name)
        if name in files:
            raise ValueError(f"duplicate downloaded Release asset: {name}")
        files[name] = path
    return files


def _load_json_regular(package_dir: Path, name: str) -> dict[str, Any]:
    path = require_regular_file(package_dir / name, name)
    value = load_json(path, name)
    if not isinstance(value, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return value


def _require_identity(
    payload: dict[str, Any],
    *,
    version: str,
    source_sha: str,
    label: str,
) -> None:
    if payload.get("version") != version:
        raise ValueError(f"{label} version mismatch")
    if payload.get("build_commit") != source_sha:
        raise ValueError(f"{label} build_commit mismatch")
    if payload.get("exact_release") is not True:
        raise ValueError(f"{label} is not marked exact_release")


def _require_manifest_parts(
    package_dir: Path,
    checksums: dict[str, str],
    manifest: dict[str, Any],
    *,
    version: str,
    source_sha: str,
    label: str,
    chip_family: str,
) -> dict[str, int]:
    _require_identity(manifest, version=version, source_sha=source_sha, label=label)
    builds = manifest.get("builds")
    if not isinstance(builds, list) or len(builds) != 1 or not isinstance(builds[0], dict):
        raise ValueError(f"{label} builds must contain exactly one build")
    if builds[0].get("chipFamily") != chip_family:
        raise ValueError(f"{label} chipFamily mismatch")
    parts = builds[0].get("parts")
    if not isinstance(parts, list) or not parts:
        raise ValueError(f"{label} parts are missing")
    result: dict[str, int] = {}
    for part in parts:
        if not isinstance(part, dict):
            raise ValueError(f"{label} part is invalid")
        name = require_safe_asset_name(part.get("path"))
        offset = part.get("offset")
        if not isinstance(offset, int) or offset < 0:
            raise ValueError(f"{label} part offset is invalid: {name}")
        if name in result:
            raise ValueError(f"{label} contains duplicate part: {name}")
        if name not in checksums:
            raise ValueError(f"{label} references an unchecksummed firmware asset: {name}")
        require_regular_file(package_dir / name, f"{label} firmware part")
        result[name] = offset
    return result

def verify_release_package(
    *,
    package_dir: Path,
    release_payload: object,
    release_tag: str,
    source_sha: str,
    release_profile: object,
) -> dict[str, Any]:
    _, version = normalize_release_tag(release_tag)
    source = release_authorization.normalize_sha(source_sha, "firmware source SHA")
    if not isinstance(release_profile, dict):
        raise ValueError("release profile must be an object")
    if release_profile.get("firmware_version") != version:
        raise ValueError("release profile version mismatch")

    assets = _release_assets(release_payload)
    downloaded = _directory_regular_files(package_dir)
    if set(downloaded) != set(assets):
        raise ValueError(
            "downloaded Release asset set does not exactly match GitHub Release metadata"
        )

    for name, metadata in assets.items():
        path = downloaded[name]
        if path.stat().st_size != metadata["size"]:
            raise ValueError(f"GitHub Release asset size mismatch: {name}")
        if sha256(path) != metadata["sha256"]:
            raise ValueError(f"GitHub Release API digest mismatch: {name}")

    checksums_path = downloaded["SHA256SUMS"]
    checksums = ci_firmware_handoff.parse_sha256sums(checksums_path)
    expected_checksum_names = set(assets) - {"SHA256SUMS"}
    if set(checksums) != expected_checksum_names:
        raise ValueError(
            "SHA256SUMS does not exactly cover every non-SHA256SUMS Release asset"
        )
    for name, expected in checksums.items():
        if sha256(downloaded[name]) != expected:
            raise ValueError(f"SHA256SUMS digest mismatch: {name}")
        if assets[name]["sha256"] != expected:
            raise ValueError(f"Release API/SHA256SUMS digest disagreement: {name}")

    metadata = _load_json_regular(package_dir, "release-metadata.json")
    if metadata.get("build_commit") != source:
        raise ValueError("release-metadata build_commit mismatch")
    if metadata.get("firmware_version") != version:
        raise ValueError("release-metadata firmware_version mismatch")
    if metadata.get("exact_release") is not True:
        raise ValueError("release-metadata is not marked exact_release")
    if metadata.get("production_release_allowed") is not True:
        raise ValueError("release-metadata is not production eligible")

    profile_mapping = {
        "format": "format",
        "device": "device",
        "chip_family": "chip_family",
        "protocol_version": "protocol_version",
        "storage_schema_version": "storage_schema_version",
        "vault_format_version": "vault_format_version",
        "security_profile": "security_profile",
        "security_profile_version": "security_profile_version",
        "vmk_persistence": "vmk_persistence",
        "post_update_state": "post_update_state",
        "auth_nvs_offset": "auth_nvs_offset",
        "auth_nvs_size": "auth_nvs_size",
        "production_release_allowed": "production_release_allowed",
    }
    for metadata_key, profile_key in profile_mapping.items():
        if metadata.get(metadata_key) != release_profile.get(profile_key):
            raise ValueError(f"release-metadata/profile mismatch: {metadata_key}")

    target = _load_json_regular(package_dir, "firmware-target.json")
    _require_identity(target, version=version, source_sha=source, label="firmware-target")
    factory_name = target.get("factory_manifest")
    update_name = target.get("update_manifest")
    expected_factory = f"factory-manifest-{source}.json"
    expected_update = f"update-manifest-{source}.json"
    if factory_name != expected_factory or update_name != expected_update:
        raise ValueError("firmware-target pinned manifest identity mismatch")
    for manifest_name in (
        expected_factory,
        expected_update,
        "factory-manifest.json",
        "update-manifest.json",
    ):
        if manifest_name not in checksums:
            raise ValueError(f"required manifest is not checksum-covered: {manifest_name}")

    chip_family = release_profile.get("chip_family")
    if not isinstance(chip_family, str) or not chip_family:
        raise ValueError("release profile chip_family is invalid")
    factory_manifest = _load_json_regular(package_dir, expected_factory)
    update_manifest = _load_json_regular(package_dir, expected_update)
    stable_factory = require_regular_file(
        package_dir / "factory-manifest.json", "stable factory manifest"
    )
    stable_update = require_regular_file(
        package_dir / "update-manifest.json", "stable update manifest"
    )
    if stable_factory.read_bytes() != (package_dir / expected_factory).read_bytes():
        raise ValueError("stable factory manifest differs from pinned manifest")
    if stable_update.read_bytes() != (package_dir / expected_update).read_bytes():
        raise ValueError("stable update manifest differs from pinned manifest")

    factory_binary = f"m5authenticator-v{version}-{source}-m5sticks3.bin"
    update_binaries = {
        "bootloader": (
            f"m5authenticator-v{version}-{source}-m5sticks3-update-bootloader.bin",
            0x000000,
        ),
        "partition_table": (
            f"m5authenticator-v{version}-{source}-m5sticks3-update-partition-table.bin",
            0x008000,
        ),
        "ota_0": (
            f"m5authenticator-v{version}-{source}-m5sticks3-update-ota0.bin",
            release_profile.get("ota_0_offset"),
        ),
    }
    if not isinstance(update_binaries["ota_0"][1], int):
        raise ValueError("release profile ota_0_offset is invalid")

    factory_parts = _require_manifest_parts(
        package_dir,
        checksums,
        factory_manifest,
        version=version,
        source_sha=source,
        label="factory manifest",
        chip_family=chip_family,
    )
    if factory_parts != {factory_binary: 0}:
        raise ValueError("factory manifest released-binary layout mismatch")

    update_parts = _require_manifest_parts(
        package_dir,
        checksums,
        update_manifest,
        version=version,
        source_sha=source,
        label="update manifest",
        chip_family=chip_family,
    )
    expected_update_parts = {
        path: offset for path, offset in update_binaries.values()
    }
    if update_parts != expected_update_parts:
        raise ValueError("update manifest released-binary layout mismatch")

    if metadata.get("flash_offset") != 0:
        raise ValueError("release-metadata flash_offset mismatch")
    if metadata.get("merged_image_bytes") != (package_dir / factory_binary).stat().st_size:
        raise ValueError("release-metadata merged_image_bytes mismatch")
    normal_update = metadata.get("normal_update")
    if not isinstance(normal_update, dict) or normal_update.get("erase_first") is not False:
        raise ValueError("release-metadata normal_update erase contract mismatch")
    if normal_update.get("required_preserve_partitions") != ["nvs", "auth_nvs"]:
        raise ValueError("release-metadata preserve-partition contract mismatch")
    metadata_parts = normal_update.get("parts")
    if not isinstance(metadata_parts, list) or len(metadata_parts) != len(update_binaries):
        raise ValueError("release-metadata normal_update parts are invalid")
    seen_metadata_parts: dict[str, tuple[str, int, int]] = {}
    for part in metadata_parts:
        if not isinstance(part, dict):
            raise ValueError("release-metadata normal_update part is invalid")
        name = part.get("name")
        path = part.get("path")
        offset = part.get("offset")
        size = part.get("bytes")
        if (
            not isinstance(name, str)
            or name in seen_metadata_parts
            or not isinstance(path, str)
            or not isinstance(offset, int)
            or not isinstance(size, int)
        ):
            raise ValueError("release-metadata normal_update part identity is invalid")
        seen_metadata_parts[name] = (path, offset, size)
    expected_metadata_parts = {
        name: (
            path,
            offset,
            (package_dir / path).stat().st_size,
        )
        for name, (path, offset) in update_binaries.items()
    }
    if seen_metadata_parts != expected_metadata_parts:
        raise ValueError("release-metadata normal_update layout mismatch")

    return {
        "firmware_version": version,
        "firmware_source_sha": source,
        "sha256sums_sha256": sha256(checksums_path),
        "checksums": checksums,
        "release_metadata": metadata,
    }


def _load_verification_statements(
    path: Path,
    expected_predicate_type: str,
) -> list[dict[str, Any]]:
    payload = load_json(path, f"attestation verification output {path.name}")
    if not isinstance(payload, list) or not payload:
        raise ValueError(f"attestation verification output is empty: {path.name}")
    statements: list[dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            raise ValueError(f"attestation verification entry is invalid: {path.name}")
        result = entry.get("verificationResult")
        statement = result.get("statement") if isinstance(result, dict) else None
        if not isinstance(statement, dict):
            raise ValueError(f"attestation verification statement is missing: {path.name}")
        if statement.get("predicateType") == expected_predicate_type:
            statements.append(statement)
    if not statements:
        raise ValueError(
            f"verified attestation predicate {expected_predicate_type} is missing for {path.name}"
        )
    return statements


def _subject_has_digest(statement: dict[str, Any], digest: str) -> bool:
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        raise ValueError("attestation statement subject is invalid")
    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        digest_map = subject.get("digest")
        actual = digest_map.get("sha256") if isinstance(digest_map, dict) else None
        if isinstance(actual, str) and actual.lower() == digest:
            return True
    return False


def _predicate_artifacts(predicate: dict[str, Any]) -> dict[str, str]:
    artifacts = predicate.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("custom provenance artifacts must be a list")
    result: dict[str, str] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("custom provenance artifact entry is invalid")
        name = require_safe_asset_name(artifact.get("name"))
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError(f"custom provenance artifact digest is invalid: {name}")
        if name in result:
            raise ValueError(f"duplicate custom provenance artifact: {name}")
        result[name] = digest
    return result


def verify_attestations(
    *,
    package_dir: Path,
    standard_dir: Path,
    custom_dir: Path,
    source_sha: str,
    checksums: object,
    sha256sums_sha256: object,
    release_metadata: object,
) -> dict[str, Any]:
    source = release_authorization.normalize_sha(source_sha, "firmware source SHA")
    if not isinstance(checksums, dict) or not all(
        isinstance(name, str) and isinstance(digest, str)
        for name, digest in checksums.items()
    ):
        raise ValueError("package checksum result is invalid")
    if not isinstance(sha256sums_sha256, str) or not SHA256_RE.fullmatch(sha256sums_sha256):
        raise ValueError("package SHA256SUMS digest result is invalid")
    if not isinstance(release_metadata, dict):
        raise ValueError("release metadata result is invalid")

    package_files = _directory_regular_files(package_dir)
    expected_results = {f"{name}.json" for name in package_files}
    standard_files = _directory_regular_files(standard_dir)
    custom_files = _directory_regular_files(custom_dir)
    if set(standard_files) != expected_results:
        raise ValueError("standard attestation verification result set is incomplete or unexpected")
    if set(custom_files) != expected_results:
        raise ValueError("custom attestation verification result set is incomplete or unexpected")

    expected_esp_idf = release_metadata.get("build_environment", {}).get("esp_idf")
    if not isinstance(expected_esp_idf, dict):
        raise ValueError("release metadata ESP-IDF provenance is missing")

    publisher_identity: tuple[str, int, int] | None = None
    for name, path in sorted(package_files.items()):
        digest = sha256(path)

        standard_statements = _load_verification_statements(
            standard_files[f"{name}.json"],
            STANDARD_PREDICATE_TYPE,
        )
        if not any(_subject_has_digest(statement, digest) for statement in standard_statements):
            raise ValueError(f"standard attestation subject digest mismatch: {name}")

        custom_statements = _load_verification_statements(
            custom_files[f"{name}.json"],
            CUSTOM_PREDICATE_TYPE,
        )
        matching = [
            statement for statement in custom_statements if _subject_has_digest(statement, digest)
        ]
        if len(matching) != 1:
            raise ValueError(f"custom attestation is missing or ambiguous for asset: {name}")
        predicate = matching[0].get("predicate")
        if not isinstance(predicate, dict):
            raise ValueError(f"custom provenance predicate is missing: {name}")
        if predicate.get("format") != 1 or predicate.get("predicate_type") != CUSTOM_PREDICATE_TYPE:
            raise ValueError(f"custom provenance format/type mismatch: {name}")
        if predicate.get("source_commit") != source:
            raise ValueError(f"custom provenance source_commit mismatch: {name}")

        workflow = predicate.get("workflow")
        if not isinstance(workflow, dict):
            raise ValueError(f"custom provenance workflow identity is missing: {name}")
        if workflow.get("repository") != REPOSITORY:
            raise ValueError(f"custom provenance repository mismatch: {name}")
        if workflow.get("workflow_ref") != AUTHORIZED_RELEASE_WORKFLOW_REF:
            raise ValueError(f"custom provenance workflow_ref mismatch: {name}")
        workflow_sha = workflow.get("workflow_sha")
        if not isinstance(workflow_sha, str):
            raise ValueError(f"custom provenance workflow_sha is missing: {name}")
        workflow_sha = release_authorization.normalize_sha(
            workflow_sha,
            "custom provenance workflow SHA",
        )
        run_id = workflow.get("run_id")
        run_attempt = workflow.get("run_attempt")
        if (
            not isinstance(run_id, int)
            or run_id <= 0
            or not isinstance(run_attempt, int)
            or run_attempt <= 0
        ):
            raise ValueError(f"custom provenance run identity is invalid: {name}")
        identity = (workflow_sha, run_id, run_attempt)
        if publisher_identity is None:
            publisher_identity = identity
        elif publisher_identity != identity:
            raise ValueError("custom provenance publisher identity differs across Release assets")

        if predicate.get("sha256sums_sha256") != sha256sums_sha256:
            raise ValueError(f"custom provenance SHA256SUMS digest mismatch: {name}")
        if _predicate_artifacts(predicate) != checksums:
            raise ValueError(f"custom provenance artifact map mismatch: {name}")
        build_environment = predicate.get("build_environment")
        if (
            not isinstance(build_environment, dict)
            or build_environment.get("esp_idf") != expected_esp_idf
        ):
            raise ValueError(f"custom provenance build environment mismatch: {name}")

    if publisher_identity is None:
        raise ValueError("no custom provenance publisher identity was verified")
    return {
        "publisher_workflow_sha": publisher_identity[0],
        "publisher_run_id": publisher_identity[1],
        "publisher_run_attempt": publisher_identity[2],
    }


def assemble_site(*, package_dir: Path, dist_dir: Path, notice_path: Path) -> None:
    package_files = _directory_regular_files(package_dir)
    notice = require_regular_file(notice_path, "current-main third-party notice")
    if notice.stat().st_size <= 0:
        raise ValueError("current-main third-party notice is empty")
    if not dist_dir.is_dir():
        raise ValueError("Web dist directory is missing")

    firmware_dir = dist_dir / "firmware"
    if firmware_dir.exists():
        if firmware_dir.is_symlink() or not firmware_dir.is_dir():
            raise ValueError("Web dist firmware path is not a directory")
        if any(firmware_dir.iterdir()):
            raise ValueError(
                "Web dist firmware directory must be empty before released asset assembly"
            )
    else:
        firmware_dir.mkdir()

    root_notice = dist_dir / "THIRD_PARTY_NOTICES.md"
    if root_notice.exists() or root_notice.is_symlink():
        raise ValueError("Web dist already contains THIRD_PARTY_NOTICES.md")

    for name, source in package_files.items():
        destination = firmware_dir / name
        shutil.copyfile(source, destination, follow_symlinks=False)
        if sha256(destination) != sha256(source):
            raise ValueError(f"released firmware asset changed during Pages assembly: {name}")

    shutil.copyfile(notice, root_notice, follow_symlinks=False)
    if root_notice.read_bytes() != notice.read_bytes():
        raise ValueError("current-main product notice changed during Pages assembly")

    target = _load_json_regular(firmware_dir, "firmware-target.json")
    for key in ("factory_manifest", "update_manifest"):
        name = require_safe_asset_name(target.get(key))
        require_regular_file(firmware_dir / name, f"assembled {key}")

    assembled = _directory_regular_files(firmware_dir)
    if set(assembled) != set(package_files):
        raise ValueError("assembled firmware directory does not exactly match verified Release assets")


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    web = subparsers.add_parser("authorize-web")
    web.add_argument("--source-ref", required=True)
    web.add_argument("--workflow-sha", required=True)
    web.add_argument("--web-sha", required=True)
    web.add_argument("--current-main", required=True)
    web.add_argument("--deployment-ack", required=True)
    web.add_argument("--main-rules", type=Path, required=True)
    web.add_argument("--check-runs", type=Path, required=True)
    web.add_argument("--statuses", type=Path, required=True)

    preflight = subparsers.add_parser("preflight-assets")
    preflight.add_argument("--release-json", type=Path, required=True)

    select = subparsers.add_parser("select-tag-ruleset")
    select.add_argument("--rulesets", type=Path, required=True)

    release = subparsers.add_parser("authorize-release")
    release.add_argument("--repo-root", type=Path, required=True)
    release.add_argument("--web-sha", required=True)
    release.add_argument("--release-tag", required=True)
    release.add_argument("--tag-sha", required=True)
    release.add_argument("--release-json", type=Path, required=True)
    release.add_argument("--tag-ruleset", type=Path, required=True)
    release.add_argument("--current-profile", type=Path, required=True)
    release.add_argument("--result-json", type=Path, required=True)

    package = subparsers.add_parser("verify-package")
    package.add_argument("--package-dir", type=Path, required=True)
    package.add_argument("--release-json", type=Path, required=True)
    package.add_argument("--release-tag", required=True)
    package.add_argument("--source-sha", required=True)
    package.add_argument("--source-validation", type=Path, required=True)
    package.add_argument("--result-json", type=Path, required=True)

    attest = subparsers.add_parser("verify-attestations")
    attest.add_argument("--package-dir", type=Path, required=True)
    attest.add_argument("--standard-dir", type=Path, required=True)
    attest.add_argument("--custom-dir", type=Path, required=True)
    attest.add_argument("--source-sha", required=True)
    attest.add_argument("--package-result", type=Path, required=True)
    attest.add_argument("--result-json", type=Path, required=True)

    assemble = subparsers.add_parser("assemble")
    assemble.add_argument("--package-dir", type=Path, required=True)
    assemble.add_argument("--dist-dir", type=Path, required=True)
    assemble.add_argument("--notice", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "authorize-web":
            web_sha = require_web_authorization(
                source_ref=args.source_ref,
                workflow_sha=args.workflow_sha,
                requested_web_sha=args.web_sha,
                current_main=args.current_main,
                deployment_ack=args.deployment_ack,
                main_rules_payload=load_json(args.main_rules, "main rules"),
                check_runs_payload=load_json(args.check_runs, "check runs"),
                statuses_payload=load_json(args.statuses, "combined status"),
            )
            print(web_sha)
        elif args.command == "preflight-assets":
            print(preflight_release_assets(load_json(args.release_json, "Release API")))

        elif args.command == "select-tag-ruleset":
            print(select_tag_immutability_ruleset_id(load_json(args.rulesets, "rulesets")))
        elif args.command == "authorize-release":
            current_profile = load_json(args.current_profile, "current release profile")
            source_validation = validate_historical_release_source(
                repo_root=args.repo_root,
                source_sha=args.tag_sha,
                release_tag=args.release_tag,
                current_profile=current_profile,
                temp_parent=args.result_json.parent,
            )
            result = require_release_authorization(
                repo_root=args.repo_root,
                web_sha=args.web_sha,
                release_tag=args.release_tag,
                tag_sha=args.tag_sha,
                release_payload=load_json(args.release_json, "Release API"),
                tag_ruleset_payload=load_json(args.tag_ruleset, "tag Ruleset"),
                current_profile=current_profile,
                release_profile=source_validation["release_profile"],
            )
            _write_json(args.result_json, source_validation)
            print(json.dumps(result, sort_keys=True))
        elif args.command == "verify-package":
            source_validation = require_source_validation_result(
                load_json(args.source_validation, "historical source validation result"),
                release_tag=args.release_tag,
                source_sha=args.source_sha,
            )
            result = verify_release_package(
                package_dir=args.package_dir,
                release_payload=load_json(args.release_json, "Release API"),
                release_tag=args.release_tag,
                source_sha=args.source_sha,
                release_profile=source_validation["release_profile"],
            )
            serializable = {
                "firmware_version": result["firmware_version"],
                "firmware_source_sha": result["firmware_source_sha"],
                "sha256sums_sha256": result["sha256sums_sha256"],
                "checksums": result["checksums"],
                "release_metadata": result["release_metadata"],
            }
            _write_json(args.result_json, serializable)
            print(args.result_json)
        elif args.command == "verify-attestations":
            package_result = load_json(args.package_result, "package verification result")
            if not isinstance(package_result, dict):
                raise ValueError("package verification result must be an object")
            result = verify_attestations(
                package_dir=args.package_dir,
                standard_dir=args.standard_dir,
                custom_dir=args.custom_dir,
                source_sha=args.source_sha,
                checksums=package_result.get("checksums"),
                sha256sums_sha256=package_result.get("sha256sums_sha256"),
                release_metadata=package_result.get("release_metadata"),
            )
            _write_json(args.result_json, result)
            print(args.result_json)
        else:
            assemble_site(
                package_dir=args.package_dir,
                dist_dir=args.dist_dir,
                notice_path=args.notice,
            )
    except (OSError, ValueError) as exc:
        print(f"released-firmware Pages verification failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
