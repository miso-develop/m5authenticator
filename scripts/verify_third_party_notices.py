#!/usr/bin/env python3
"""Fail-closed mechanical coverage check for product third-party notice inventory.

This verifier checks exact dependency name/version coverage only. It does not
perform legal interpretation and does not prove license compliance.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NOTICE = ROOT / "THIRD_PARTY_NOTICES.md"
DEFAULT_WEB_LOCK = ROOT / "web" / "package-lock.json"
DEFAULT_FIRMWARE_LOCK = ROOT / "firmware" / "dependencies.lock"

MARKER_RE = re.compile(r"^<!-- M5AUTH-NOTICE (\{.*\}) -->$", re.MULTILINE)
SUPPORTED_SCOPES = {"web", "firmware-lock"}


class NoticeVerificationError(ValueError):
    pass


def _resolve_node_path(packages: dict[str, object], parent_path: str, name: str) -> str | None:
    base = parent_path
    while True:
        candidate = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if candidate in packages:
            return candidate
        marker = base.rfind("/node_modules/")
        if marker < 0:
            break
        base = base[:marker]
    root_candidate = f"node_modules/{name}"
    return root_candidate if root_candidate in packages else None


def web_production_dependencies(lock_path: Path = DEFAULT_WEB_LOCK) -> set[tuple[str, str]]:
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NoticeVerificationError(f"invalid Web lockfile: {exc}") from exc

    packages = payload.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        raise NoticeVerificationError("Web lockfile packages/root entry is missing")

    root = packages[""]
    root_dependencies = root.get("dependencies", {})
    if not isinstance(root_dependencies, dict):
        raise NoticeVerificationError("Web root dependencies must be an object")

    queue: list[tuple[str, str]] = []
    for name in root_dependencies:
        path = _resolve_node_path(packages, "", name)
        if path is None:
            raise NoticeVerificationError(f"unresolved Web runtime dependency: {name}")
        queue.append((name, path))

    visited_paths: set[str] = set()
    closure: set[tuple[str, str]] = set()
    while queue:
        name, package_path = queue.pop(0)
        if package_path in visited_paths:
            continue
        visited_paths.add(package_path)

        package = packages.get(package_path)
        if not isinstance(package, dict):
            raise NoticeVerificationError(f"invalid Web package entry: {package_path}")
        if package.get("dev") is True:
            raise NoticeVerificationError(
                f"production dependency closure unexpectedly reached dev-only package: {package_path}"
            )
        version = package.get("version")
        if not isinstance(version, str) or not version:
            raise NoticeVerificationError(f"Web package has no exact version: {package_path}")
        closure.add((name, version))

        for key in ("dependencies", "optionalDependencies"):
            dependencies = package.get(key, {})
            if dependencies is None:
                continue
            if not isinstance(dependencies, dict):
                raise NoticeVerificationError(f"{package_path} {key} must be an object")
            for dependency_name in dependencies:
                resolved = _resolve_node_path(packages, package_path, dependency_name)
                if resolved is not None:
                    queue.append((dependency_name, resolved))
                elif key == "dependencies":
                    raise NoticeVerificationError(
                        f"unresolved Web runtime dependency {dependency_name} from {package_path}"
                    )

    return closure


def firmware_lock_dependencies(lock_path: Path = DEFAULT_FIRMWARE_LOCK) -> set[tuple[str, str]]:
    try:
        lines = lock_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise NoticeVerificationError(f"cannot read firmware dependency lock: {exc}") from exc

    in_dependencies = False
    current: str | None = None
    found: dict[str, str] = {}
    for line in lines:
        if line == "dependencies:":
            in_dependencies = True
            current = None
            continue
        if not in_dependencies:
            continue
        if line and not line.startswith(" "):
            break

        component_match = re.fullmatch(r"  ([^\s].*):", line)
        if component_match:
            current = component_match.group(1)
            continue

        version_match = re.fullmatch(r"    version:\s*(.+)", line)
        if current and version_match:
            raw = version_match.group(1).strip()
            version = raw.strip("'\"")
            if not version:
                raise NoticeVerificationError(f"firmware dependency has empty version: {current}")
            if current in found:
                raise NoticeVerificationError(f"duplicate firmware dependency entry: {current}")
            found[current] = version

    if not found:
        raise NoticeVerificationError("no firmware dependency entries found")
    return set(found.items())


def notice_markers(notice_path: Path = DEFAULT_NOTICE) -> set[tuple[str, str, str]]:
    if notice_path.is_symlink() or not notice_path.is_file():
        raise NoticeVerificationError(f"product notice must be a regular file: {notice_path}")
    text = notice_path.read_text(encoding="utf-8")
    if not text.strip():
        raise NoticeVerificationError("product notice is empty")

    markers: set[tuple[str, str, str]] = set()
    for raw in MARKER_RE.findall(text):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise NoticeVerificationError(f"invalid notice marker JSON: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {"scope", "name", "version"}:
            raise NoticeVerificationError("notice marker must contain exactly scope/name/version")
        scope = value["scope"]
        name = value["name"]
        version = value["version"]
        if scope not in SUPPORTED_SCOPES:
            raise NoticeVerificationError(f"unsupported notice marker scope: {scope!r}")
        if not all(isinstance(item, str) and item for item in (name, version)):
            raise NoticeVerificationError("notice marker name/version must be non-empty strings")
        marker = (scope, name, version)
        if marker in markers:
            raise NoticeVerificationError(f"duplicate notice marker: {marker}")
        markers.add(marker)
    if not markers:
        raise NoticeVerificationError("product notice contains no structured inventory markers")
    return markers


def _scoped(markers: Iterable[tuple[str, str, str]], scope: str) -> set[tuple[str, str]]:
    return {(name, version) for marker_scope, name, version in markers if marker_scope == scope}


def verify(
    notice_path: Path = DEFAULT_NOTICE,
    web_lock_path: Path = DEFAULT_WEB_LOCK,
    firmware_lock_path: Path = DEFAULT_FIRMWARE_LOCK,
) -> tuple[int, int]:
    expected_web = web_production_dependencies(web_lock_path)
    expected_firmware = firmware_lock_dependencies(firmware_lock_path)
    markers = notice_markers(notice_path)

    actual_web = _scoped(markers, "web")
    actual_firmware = _scoped(markers, "firmware-lock")

    if actual_web != expected_web:
        missing = sorted(expected_web - actual_web)
        stale = sorted(actual_web - expected_web)
        raise NoticeVerificationError(
            f"Web notice inventory drift: missing={missing}, stale={stale}"
        )
    if actual_firmware != expected_firmware:
        missing = sorted(expected_firmware - actual_firmware)
        stale = sorted(actual_firmware - expected_firmware)
        raise NoticeVerificationError(
            f"firmware notice inventory drift: missing={missing}, stale={stale}"
        )
    return len(expected_web), len(expected_firmware)


def main() -> int:
    try:
        web_count, firmware_count = verify()
    except NoticeVerificationError as exc:
        print(f"third-party notice verification failed: {exc}")
        return 1
    print(
        "Third-party notice coverage: OK "
        f"(Web production entries={web_count}, firmware lock entries={firmware_count})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
