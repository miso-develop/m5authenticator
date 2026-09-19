#!/usr/bin/env python3
"""Deterministic, fail-safe CI change-impact classification."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable

ZERO_SHA = "0" * 40
OUTPUT_KEYS = (
    "web",
    "firmware",
    "pages",
    "security_release_shared",
    "snapshot_contract",
    "snapshot_build",
    "process_docs_only",
    "uncertain",
)

PROCESS_DOC_EXACT = {
    "README.md",
    "README.ja.md",
    "AGENTS.md",
}
PROCESS_DOC_PREFIXES = (
    "docs/",
    ".agent/",
    ".agents/",
    "agent/",
)

SHARED_EXACT = {
    ".github/workflows/foundation.yml",
    ".github/workflows/security.yml",
    ".github/workflows/pages.yml",
    ".github/workflows/release-authorized.yml",
    ".github/workflows/release.yml",
    "firmware/release-profile.json",
    "scripts/ci_change_impact.py",
    "tests/ci_change_impact_test.py",
}

SHARED_SCRIPT_EXACT = {
    "scripts/package_firmware.py",
    "scripts/validate_release.py",
    "scripts/release_attestation.py",
    "scripts/release_authorization.py",
    "scripts/security_scan.py",
    "scripts/ci_firmware_handoff.py",
    "scripts/ci_esp_idf_isolated_build.py",
    "scripts/esp_idf_build_image.py",
    "scripts/verify_firmware_image.py",
}

SNAPSHOT_CONTRACT_EXACT = {
    "AGENTS.md",
    "tools/diagnostics/screen_snapshot.py",
}
SNAPSHOT_CONTRACT_PREFIXES = (
    "scripts/windows/",
    "docs/testing/screen-snapshot",
    "tests/screen_snapshot_",
)
SNAPSHOT_BUILD_EXACT = {
    "scripts/ci_change_impact.py",
    "firmware/CMakeLists.txt",
    "firmware/sdkconfig.defaults",
    "scripts/esp_idf_build_image.py",
    "tests/esp_idf_image_pin_contract_test.py",
    ".github/workflows/issue117-screen-snapshot.yml",
}
SNAPSHOT_BUILD_PREFIXES = (
    "firmware/main/",
    "firmware/components/m5auth_device_sticks3/",
    "firmware/components/m5auth_time/",
    "firmware/components/m5auth_session/",
    "firmware/components/m5auth_vault_runtime/",
)

VERSIONED_SHA = re.compile(r"^[0-9a-fA-F]{40}$")


class ImpactError(RuntimeError):
    """Raised when the changed-path set cannot be established safely."""


def _normalize_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _is_process_doc(path: str) -> bool:
    return path in PROCESS_DOC_EXACT or path.startswith(PROCESS_DOC_PREFIXES)


def _is_snapshot_contract(path: str) -> bool:
    return path in SNAPSHOT_CONTRACT_EXACT or path.startswith(SNAPSHOT_CONTRACT_PREFIXES)


def _is_snapshot_build(path: str) -> bool:
    return path in SNAPSHOT_BUILD_EXACT or path.startswith(SNAPSHOT_BUILD_PREFIXES)


def _new_result() -> dict[str, bool]:
    return {key: False for key in OUTPUT_KEYS}


def all_heavy_result(*, uncertain: bool) -> dict[str, bool]:
    result = _new_result()
    result.update(
        {
            "web": True,
            "firmware": True,
            "pages": True,
            "security_release_shared": True,
            "snapshot_contract": True,
            "snapshot_build": True,
            "process_docs_only": False,
            "uncertain": uncertain,
        }
    )
    return result


def classify_paths(paths: Iterable[str]) -> dict[str, bool]:
    normalized = sorted({_normalize_path(path) for path in paths if _normalize_path(path)})
    if not normalized:
        return all_heavy_result(uncertain=True)

    result = _new_result()
    result["process_docs_only"] = all(_is_process_doc(path) for path in normalized)

    for path in normalized:
        snapshot_contract = _is_snapshot_contract(path)
        snapshot_build = _is_snapshot_build(path)
        if snapshot_contract:
            result["snapshot_contract"] = True
        if snapshot_build:
            result["snapshot_contract"] = True
            result["snapshot_build"] = True

        if path == ".github/workflows/issue117-screen-snapshot.yml":
            result["security_release_shared"] = True
            result["web"] = True
            result["firmware"] = True
            result["pages"] = True
            continue

        if path in SHARED_EXACT or path in SHARED_SCRIPT_EXACT:
            result["security_release_shared"] = True
            result["web"] = True
            result["firmware"] = True
            result["pages"] = True
            continue

        if _is_process_doc(path):
            continue

        if path.startswith("web/"):
            result["web"] = True
            result["pages"] = True
            continue

        if path.startswith("firmware/"):
            result["firmware"] = True
            continue

        if path == "tools/diagnostics/screen_snapshot.py":
            continue

        if path.startswith("tests/"):
            if path.endswith((".cpp", ".cc", ".cxx")):
                result["firmware"] = True
                continue
            if snapshot_build:
                result["firmware"] = True
                continue
            if snapshot_contract:
                continue
            result["security_release_shared"] = True
            result["web"] = True
            result["firmware"] = True
            result["pages"] = True
            continue

        if path.startswith("scripts/"):
            if snapshot_contract:
                continue
            result["security_release_shared"] = True
            result["web"] = True
            result["firmware"] = True
            result["pages"] = True
            continue

        # Unknown/unclassified path is deliberately fail-safe.
        result["security_release_shared"] = True
        result["web"] = True
        result["firmware"] = True
        result["pages"] = True

    return result


def resolve_event_range(event_name: str, event: dict[str, object]) -> tuple[str, str]:
    if event_name == "pull_request":
        pull_request = event.get("pull_request")
        if not isinstance(pull_request, dict):
            raise ImpactError("pull_request payload is missing")
        base = pull_request.get("base")
        head = pull_request.get("head")
        if not isinstance(base, dict) or not isinstance(head, dict):
            raise ImpactError("pull_request base/head payload is missing")
        base_sha = base.get("sha")
        head_sha = head.get("sha")
    elif event_name == "push":
        base_sha = event.get("before")
        head_sha = event.get("after")
    else:
        raise ImpactError(f"unsupported CI event: {event_name!r}")

    if not isinstance(base_sha, str) or not isinstance(head_sha, str):
        raise ImpactError("event base/head SHA is unavailable")
    if base_sha == ZERO_SHA:
        raise ImpactError("all-zero push base is not safe to classify")
    if not VERSIONED_SHA.fullmatch(base_sha) or not VERSIONED_SHA.fullmatch(head_sha):
        raise ImpactError("event base/head SHA is malformed")
    return base_sha.lower(), head_sha.lower()


def _parse_name_status_z(payload: bytes) -> list[str]:
    fields = payload.decode("utf-8", errors="strict").split("\0")
    paths: list[str] = []
    index = 0
    while index < len(fields):
        token = fields[index]
        index += 1
        if not token:
            continue

        if "\t" in token:
            status, first_path = token.split("\t", 1)
        else:
            status = token
            if index >= len(fields):
                raise ImpactError("truncated git diff name-status output")
            first_path = fields[index]
            index += 1

        if not status or status[0] not in "ACDMRTUXB":
            raise ImpactError(f"unexpected git diff status: {status!r}")
        paths.append(first_path)

        if status[0] in "RC":
            if index >= len(fields):
                raise ImpactError("truncated rename/copy path in git diff output")
            paths.append(fields[index])
            index += 1

    return [_normalize_path(path) for path in paths if _normalize_path(path)]


def changed_paths(base_sha: str, head_sha: str, *, repo_root: Path = Path(".")) -> list[str]:
    for sha in (base_sha, head_sha):
        probe = subprocess.run(
            ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
            cwd=repo_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if probe.returncode != 0:
            raise ImpactError(f"required commit {sha} is unavailable in checkout history")

    completed = subprocess.run(
        [
            "git",
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            base_sha,
            head_sha,
            "--",
        ],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise ImpactError("git diff failed while computing changed paths")

    paths = _parse_name_status_z(completed.stdout)
    if not paths:
        raise ImpactError("changed-path set is empty")
    return paths


def classify_event(
    event_name: str,
    event: dict[str, object],
    *,
    repo_root: Path = Path("."),
) -> tuple[dict[str, bool], list[str], str | None]:
    try:
        base_sha, head_sha = resolve_event_range(event_name, event)
        paths = changed_paths(base_sha, head_sha, repo_root=repo_root)
        return classify_paths(paths), paths, None
    except (ImpactError, OSError, UnicodeError, json.JSONDecodeError) as error:
        return all_heavy_result(uncertain=True), [], str(error)


def write_github_output(path: Path, result: dict[str, bool], paths: list[str], reason: str | None) -> None:
    with path.open("a", encoding="utf-8") as output:
        for key in OUTPUT_KEYS:
            output.write(f"{key}={'true' if result[key] else 'false'}\n")
        output.write(f"changed_paths_json={json.dumps(paths, separators=(',', ':'))}\n")
        output.write(f"uncertainty_reason_json={json.dumps(reason or '', separators=(',', ':'))}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-file", type=Path)
    parser.add_argument("--event-name")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--path", action="append", default=[])
    args = parser.parse_args(argv)

    if args.path:
        paths = [_normalize_path(path) for path in args.path]
        result = classify_paths(paths)
        reason = None
    else:
        event_path = args.event_file or (Path(os.environ["GITHUB_EVENT_PATH"]) if os.environ.get("GITHUB_EVENT_PATH") else None)
        event_name = args.event_name or os.environ.get("GITHUB_EVENT_NAME")
        if event_path is None or not event_name:
            result = all_heavy_result(uncertain=True)
            paths = []
            reason = "GitHub event metadata is unavailable"
        else:
            try:
                event = json.loads(event_path.read_text(encoding="utf-8"))
                if not isinstance(event, dict):
                    raise ImpactError("GitHub event payload is not an object")
                result, paths, reason = classify_event(event_name, event)
            except (OSError, UnicodeError, json.JSONDecodeError, ImpactError) as error:
                result = all_heavy_result(uncertain=True)
                paths = []
                reason = str(error)

    output_path = args.github_output or (Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None)
    if output_path is not None:
        write_github_output(output_path, result, paths, reason)

    print(json.dumps({"impact": result, "paths": paths, "uncertainty": reason}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
