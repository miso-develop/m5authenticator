#!/usr/bin/env python3
"""Fail-closed release authorization for exact protected-main SemVer releases."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_TAG_RE = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)


def normalize_sha(value: str, label: str) -> str:
    value = value.strip().lower()
    if not SHA_RE.fullmatch(value):
        raise ValueError(f"{label} must be a full 40-character lowercase Git SHA")
    return value


def require_requested_tag(requested_tag: str, firmware_version: str) -> str:
    requested = requested_tag.strip()
    if not SEMVER_TAG_RE.fullmatch(requested):
        raise ValueError("requested tag must use exact vX.Y.Z SemVer syntax")
    expected = f"v{firmware_version.strip()}"
    if requested != expected:
        raise ValueError(
            f"requested tag {requested} does not match release profile {expected}"
        )
    return requested


def require_exact_main(source_sha: str, main_sha: str) -> str:
    source = normalize_sha(source_sha, "source SHA")
    main = normalize_sha(main_sha, "main SHA")
    if source != main:
        raise ValueError(
            f"release source {source} is not the exact current protected-main HEAD {main}"
        )
    return source


def require_existing_tag_at_source(tag_sha: str, source_sha: str) -> None:
    tag = normalize_sha(tag_sha, "tag SHA")
    source = normalize_sha(source_sha, "source SHA")
    if tag != source:
        raise ValueError(
            f"existing release tag resolves to {tag}, not exact protected-main source {source}"
        )


def required_status_checks(main_rules_payload: object) -> list[tuple[str, int | None]]:
    if not isinstance(main_rules_payload, list):
        raise ValueError("main-rules payload must be a list")

    required: list[tuple[str, int | None]] = []
    for rule in main_rules_payload:
        if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
            continue
        parameters = rule.get("parameters")
        checks = parameters.get("required_status_checks") if isinstance(parameters, dict) else None
        if not isinstance(checks, list):
            raise ValueError("required_status_checks rule has invalid parameters")
        for check in checks:
            if not isinstance(check, dict):
                raise ValueError("required status check entry is invalid")
            context = check.get("context")
            if not isinstance(context, str) or not context:
                raise ValueError("required status check context is invalid")
            integration_id = check.get("integration_id")
            if integration_id is not None and not isinstance(integration_id, int):
                raise ValueError(f"required status check integration_id is invalid for {context}")
            identity = (context, integration_id)
            if identity not in required:
                required.append(identity)

    if not required:
        raise ValueError("protected main exposes no required status checks; release fails closed")
    return required


def _check_run_state(
    source_sha: str,
    context: str,
    integration_id: int | None,
    check_runs_payload: dict[str, Any],
) -> tuple[bool, bool]:
    runs = check_runs_payload.get("check_runs")
    if not isinstance(runs, list):
        raise ValueError("check-runs payload does not contain check_runs")

    matching: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, dict) or run.get("name") != context:
            continue
        if str(run.get("head_sha", "")).lower() != source_sha:
            continue
        app = run.get("app")
        app_id = app.get("id") if isinstance(app, dict) else None
        if integration_id is not None and app_id != integration_id:
            continue
        matching.append(run)

    if not matching:
        return False, False

    successful_conclusions = {"success", "neutral", "skipped"}
    return True, all(
        run.get("status") == "completed"
        and run.get("conclusion") in successful_conclusions
        for run in matching
    )


def _commit_status_state(
    context: str,
    statuses_payload: dict[str, Any],
) -> tuple[bool, bool]:
    statuses = statuses_payload.get("statuses")
    if not isinstance(statuses, list):
        raise ValueError("combined-status payload does not contain statuses")

    matching = [
        status
        for status in statuses
        if isinstance(status, dict) and status.get("context") == context
    ]
    if not matching:
        return False, False

    # The combined-status endpoint exposes the latest status for each context.
    # Fail closed if a malformed payload contains duplicate same-context entries.
    return True, all(status.get("state") == "success" for status in matching)


def require_protected_main_checks(
    source_sha: str,
    main_rules_payload: object,
    check_runs_payload: dict[str, Any],
    statuses_payload: dict[str, Any],
) -> None:
    source = normalize_sha(source_sha, "source SHA")
    missing: list[str] = []

    for context, integration_id in required_status_checks(main_rules_payload):
        check_present, check_success = _check_run_state(
            source,
            context,
            integration_id,
            check_runs_payload,
        )

        if integration_id is not None:
            # Integration-bound rules can only be satisfied by a Check Run from
            # the exact GitHub App selected by the protected-main Ruleset.
            satisfied = check_present and check_success
        else:
            status_present, status_success = _commit_status_state(
                context,
                statuses_payload,
            )
            # GitHub treats Checks and classic commit statuses as distinct
            # required mechanisms. If the same required name exists in both,
            # both must pass; otherwise the single reported mechanism must pass.
            if check_present and status_present:
                satisfied = check_success and status_success
            elif check_present:
                satisfied = check_success
            elif status_present:
                satisfied = status_success
            else:
                satisfied = False

        if not satisfied:
            suffix = f" (integration {integration_id})" if integration_id is not None else ""
            missing.append(f"{context}{suffix}")

    if missing:
        raise ValueError(
            "required protected-main status/checks are missing or unsuccessful "
            f"for {source}: {', '.join(missing)}"
        )


def authorize_release(
    source_sha: str,
    main_sha: str,
    requested_tag: str,
    firmware_version: str,
    tag_sha: str,
    main_rules_payload: object,
    check_runs_payload: dict[str, Any],
    statuses_payload: dict[str, Any],
) -> str:
    requested = require_requested_tag(requested_tag, firmware_version)
    source = require_exact_main(source_sha, main_sha)
    require_existing_tag_at_source(tag_sha, source)
    require_protected_main_checks(
        source,
        main_rules_payload,
        check_runs_payload,
        statuses_payload,
    )
    return requested


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--main-sha", required=True)
    parser.add_argument("--requested-tag", required=True)
    parser.add_argument("--firmware-version", required=True)
    parser.add_argument("--tag-sha", required=True)
    parser.add_argument("--main-rules", type=Path, required=True)
    parser.add_argument("--check-runs", type=Path, required=True)
    parser.add_argument("--statuses", type=Path, required=True)
    args = parser.parse_args()

    try:
        main_rules_payload = json.loads(args.main_rules.read_text(encoding="utf-8"))
        check_runs_payload = json.loads(args.check_runs.read_text(encoding="utf-8"))
        statuses_payload = json.loads(args.statuses.read_text(encoding="utf-8"))
        requested = authorize_release(
            args.source_sha,
            args.main_sha,
            args.requested_tag,
            args.firmware_version,
            args.tag_sha,
            main_rules_payload,
            check_runs_payload,
            statuses_payload,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Release authorization failed: {exc}")
        return 1

    print(requested)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
