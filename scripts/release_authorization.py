#!/usr/bin/env python3
"""Fail-closed release authorization for exact protected-main SemVer releases."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_CHECKS: dict[str, int] = {
    # Mirrors the active Protect main ruleset required status check.
    "security:scan": 15368,
}


def normalize_sha(value: str, label: str) -> str:
    value = value.strip().lower()
    if not SHA_RE.fullmatch(value):
        raise ValueError(f"{label} must be a full 40-character lowercase Git SHA")
    return value


def require_exact_main(source_sha: str, main_sha: str) -> str:
    source = normalize_sha(source_sha, "source SHA")
    main = normalize_sha(main_sha, "main SHA")
    if source != main:
        raise ValueError(
            f"release source {source} is not the exact current protected-main HEAD {main}"
        )
    return source


def require_protected_main_checks(
    source_sha: str,
    check_runs_payload: dict[str, Any],
) -> None:
    source = normalize_sha(source_sha, "source SHA")
    runs = check_runs_payload.get("check_runs")
    if not isinstance(runs, list):
        raise ValueError("check-runs payload does not contain check_runs")

    satisfied: set[str] = set()
    for run in runs:
        if not isinstance(run, dict):
            continue
        name = run.get("name")
        if name not in REQUIRED_CHECKS:
            continue
        if str(run.get("head_sha", "")).lower() != source:
            continue
        app = run.get("app")
        app_id = app.get("id") if isinstance(app, dict) else None
        if app_id != REQUIRED_CHECKS[name]:
            continue
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            continue
        satisfied.add(name)

    missing = sorted(set(REQUIRED_CHECKS) - satisfied)
    if missing:
        raise ValueError(
            "required protected-main security checks are missing or unsuccessful "
            f"for {source}: {', '.join(missing)}"
        )


def authorize_release(
    source_sha: str,
    main_sha: str,
    check_runs_payload: dict[str, Any],
) -> str:
    source = require_exact_main(source_sha, main_sha)
    require_protected_main_checks(source, check_runs_payload)
    return source


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--main-sha", required=True)
    parser.add_argument("--check-runs", type=Path, required=True)
    args = parser.parse_args()

    try:
        payload = json.loads(args.check_runs.read_text(encoding="utf-8"))
        source = authorize_release(args.source_sha, args.main_sha, payload)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Release authorization failed: {exc}")
        return 1

    print(f"Release authorization passed for exact protected-main HEAD {source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
