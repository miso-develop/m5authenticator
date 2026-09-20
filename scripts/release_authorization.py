#!/usr/bin/env python3
"""Fail-closed release authorization for protected-main SemVer releases."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_TAG_RE = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)

RECOVERY_ID = "v1.0.0-authorized-release-shell-repair"
RECOVERY_TAG = "v1.0.0"
RECOVERY_SOURCE_SHA = "996378b07d8587c0d11e43362590e5d1062ad8c2"
RECOVERY_FAILED_RUN_ID = 35454271560
RECOVERY_WORKFLOW_ID = 361302600
RECOVERY_REPOSITORY = "miso-develop/m5authenticator"
RECOVERY_WORKFLOW_PATH = ".github/workflows/release-authorized.yml"
LEGACY_WORKFLOW_ID = 354596449
LEGACY_WORKFLOW_NAME = "Release"
LEGACY_WORKFLOW_PATH = ".github/workflows/release.yml"
LEGACY_WORKFLOW_DISABLED_STATE = "disabled_manually"
RECOVERY_MANIFEST = {
    "format": 1,
    "recovery_id": RECOVERY_ID,
    "tag": RECOVERY_TAG,
    "source_sha": RECOVERY_SOURCE_SHA,
    "failed_run_id": RECOVERY_FAILED_RUN_ID,
}
RECOVERY_MANIFEST_KEYS = frozenset(RECOVERY_MANIFEST)
RECOVERY_MANIFEST_PATH = ".github/release-recovery.json"
RECOVERY_ALLOWED_PATHS = frozenset(
    {
        ".github/workflows/release-authorized.yml",
        RECOVERY_MANIFEST_PATH,
        "scripts/release_authorization.py",
        "tests/release_authorization_test.py",
        "tests/release_attestation_test.py",
        "tests/ci_supply_chain_boundary_test.py",
    }
)
RECOVERY_EXISTING_PATHS = RECOVERY_ALLOWED_PATHS - {RECOVERY_MANIFEST_PATH}
REGULAR_GIT_MODES = {"100644", "100755"}

EXPECTED_LEGACY_RELEASE_WORKFLOW = """name: Release

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  retired:
    name: legacy-release-retired
    runs-on: ubuntu-latest
    timeout-minutes: 1
    steps:
      - name: Explain retirement
        run: echo "Legacy Release workflow is retired. Use Authorized Release."
"""


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
            f"existing release tag resolves to {tag}, not authorized release source {source}"
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
            satisfied = check_present and check_success
        else:
            status_present, status_success = _commit_status_state(
                context,
                statuses_payload,
            )
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
    """Normal #199 exact-current-main authorization path."""
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


def require_recovery_manifest(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("recovery manifest must be a JSON object")
    if set(payload) != RECOVERY_MANIFEST_KEYS:
        raise ValueError("recovery manifest keys do not exactly match the approved schema")
    for key, expected in RECOVERY_MANIFEST.items():
        actual = payload.get(key)
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError(f"recovery manifest {key} does not match the approved incident")
    return dict(RECOVERY_MANIFEST)


def require_failed_run(
    run_payload: object,
    jobs_payload: object,
) -> None:
    if not isinstance(run_payload, dict):
        raise ValueError("failed-run payload must be an object")
    expected = {
        "id": RECOVERY_FAILED_RUN_ID,
        "workflow_id": RECOVERY_WORKFLOW_ID,
        "path": RECOVERY_WORKFLOW_PATH,
        "event": "repository_dispatch",
        "run_attempt": 1,
        "head_branch": "main",
        "head_sha": RECOVERY_SOURCE_SHA,
        "conclusion": "failure",
    }
    for key, expected_value in expected.items():
        if run_payload.get(key) != expected_value:
            raise ValueError(f"failed-run metadata mismatch: {key}")

    repository = run_payload.get("repository")
    if not isinstance(repository, dict) or repository.get("full_name") != RECOVERY_REPOSITORY:
        raise ValueError("failed-run repository identity mismatch")

    if not isinstance(jobs_payload, dict) or not isinstance(jobs_payload.get("jobs"), list):
        raise ValueError("failed-run jobs payload is invalid")
    expected_jobs = {
        "authorize-protected-main-release": "failure",
        "build-firmware-unprivileged": "skipped",
        "verify-firmware-unprivileged": "skipped",
        "attest-verified-release-assets": "skipped",
        "publish-verified-release": "skipped",
        "cleanup-transient-release-artifacts": "success",
    }
    jobs = jobs_payload["jobs"]
    for name, conclusion in expected_jobs.items():
        matching = [
            job for job in jobs
            if isinstance(job, dict) and job.get("name") == name
        ]
        if len(matching) != 1 or matching[0].get("conclusion") != conclusion:
            raise ValueError(f"failed-run job-result mismatch: {name}")


def require_tag_immutability(ruleset_payload: object) -> None:
    if not isinstance(ruleset_payload, dict):
        raise ValueError("tag-immutability Ruleset payload must be an object")
    if ruleset_payload.get("name") != "SemVer tag immutability":
        raise ValueError("SemVer tag immutability Ruleset identity mismatch")
    if ruleset_payload.get("target") != "tag" or ruleset_payload.get("enforcement") != "active":
        raise ValueError("SemVer tag immutability Ruleset is not active for tags")

    conditions = ruleset_payload.get("conditions")
    ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
    includes = ref_name.get("include") if isinstance(ref_name, dict) else None
    excludes = ref_name.get("exclude") if isinstance(ref_name, dict) else None
    if not isinstance(includes, list) or "refs/tags/v*.*.*" not in includes:
        raise ValueError("SemVer tag immutability Ruleset does not cover release tags")
    if excludes != []:
        raise ValueError(
            "SemVer tag immutability Ruleset must have no ref exclusions for recovery"
        )

    rules = ruleset_payload.get("rules")
    if not isinstance(rules, list):
        raise ValueError("SemVer tag immutability Ruleset rules are invalid")
    rule_types = {
        rule.get("type")
        for rule in rules
        if isinstance(rule, dict) and isinstance(rule.get("type"), str)
    }
    required_types = {"deletion", "non_fast_forward", "update"}
    if not required_types.issubset(rule_types):
        raise ValueError("SemVer tag immutability Ruleset lacks required protections")

    if ruleset_payload.get("bypass_actors") not in ([], None):
        raise ValueError("SemVer tag immutability Ruleset unexpectedly permits bypass actors")


def require_release_absent(release_state: str) -> None:
    if release_state != "absent":
        raise ValueError(f"GitHub Release {RECOVERY_TAG} already exists or absence is unproven")


def require_legacy_release_tombstone(text: str) -> None:
    if text != EXPECTED_LEGACY_RELEASE_WORKFLOW:
        raise ValueError("legacy Release workflow is not the exact retired tombstone")


def require_legacy_workflow_disabled(payload: object) -> None:
    if not isinstance(payload, dict):
        raise ValueError("legacy Release workflow metadata must be an object")
    expected = {
        "id": LEGACY_WORKFLOW_ID,
        "name": LEGACY_WORKFLOW_NAME,
        "path": LEGACY_WORKFLOW_PATH,
        "state": LEGACY_WORKFLOW_DISABLED_STATE,
    }
    for key, expected_value in expected.items():
        if payload.get(key) != expected_value:
            raise ValueError(f"legacy Release workflow metadata mismatch: {key}")
def _run_git(
    repo_root: Path,
    arguments: list[str],
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise ValueError(f"git command failed to start: {exc}") from exc
    return completed


def require_recovery_ancestry(repo_root: Path, source_sha: str, main_sha: str) -> None:
    source = normalize_sha(source_sha, "recovery source SHA")
    main = normalize_sha(main_sha, "main SHA")
    completed = _run_git(repo_root, ["merge-base", "--is-ancestor", source, main])
    if completed.returncode == 1:
        raise ValueError("approved recovery source is not an ancestor of exact current main")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"cannot prove recovery ancestry: {detail or completed.returncode}")


def parse_name_status_z(payload: bytes) -> list[tuple[str, tuple[str, ...]]]:
    try:
        fields = payload.decode("utf-8", errors="strict").split("\0")
    except UnicodeError as exc:
        raise ValueError("git diff path output is not UTF-8") from exc

    records: list[tuple[str, tuple[str, ...]]] = []
    index = 0
    while index < len(fields):
        token = fields[index]
        index += 1
        if not token:
            continue

        first_path: str | None = None
        if "\t" in token:
            status, first_path = token.split("\t", 1)
        else:
            status = token

        if not status:
            raise ValueError("git diff emitted an empty status")
        path_count = 2 if status[0] in {"R", "C"} else 1
        paths: list[str] = []
        if first_path is not None:
            paths.append(first_path)

        while len(paths) < path_count:
            if index >= len(fields) or not fields[index]:
                raise ValueError("git diff emitted a truncated path record")
            paths.append(fields[index])
            index += 1

        records.append((status, tuple(paths)))
    return records


def _tree_entry(
    repo_root: Path,
    commit_sha: str,
    path: str,
) -> tuple[str, str] | None:
    completed = _run_git(repo_root, ["ls-tree", "-z", commit_sha, "--", path])
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"cannot inspect Git tree for {path}: {detail or completed.returncode}")
    if not completed.stdout:
        return None

    records = [record for record in completed.stdout.split(b"\0") if record]
    if len(records) != 1:
        raise ValueError(f"unexpected Git tree record count for {path}")
    try:
        metadata, observed_path = records[0].decode("utf-8", errors="strict").split("\t", 1)
        mode, object_type, _object_sha = metadata.split(" ", 2)
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"malformed Git tree record for {path}") from exc
    if observed_path != path:
        raise ValueError(f"Git tree path mismatch for {path}")
    return mode, object_type


def validate_recovery_delta_records(
    records: list[tuple[str, tuple[str, ...]]],
    source_entries: dict[str, tuple[str, str] | None],
    main_entries: dict[str, tuple[str, str] | None],
) -> None:
    seen: set[str] = set()
    for status, paths in records:
        if status.startswith(("R", "C")):
            raise ValueError("recovery delta rejects rename/copy status")
        if len(paths) != 1:
            raise ValueError("recovery delta path record is ambiguous")
        path = paths[0]
        if path not in RECOVERY_ALLOWED_PATHS:
            raise ValueError(f"recovery delta contains non-approved path: {path}")
        if path in seen:
            raise ValueError(f"recovery delta contains duplicate path: {path}")
        seen.add(path)

        expected_status = "A" if path == RECOVERY_MANIFEST_PATH else "M"
        if status != expected_status:
            raise ValueError(
                f"recovery delta status for {path} must be {expected_status}, got {status}"
            )

    if RECOVERY_MANIFEST_PATH not in seen:
        raise ValueError("recovery manifest must be the one added recovery path")

    for path in RECOVERY_EXISTING_PATHS:
        source_entry = source_entries.get(path)
        main_entry = main_entries.get(path)
        if source_entry is None or main_entry is None:
            raise ValueError(f"approved existing recovery path must exist at both revisions: {path}")
        source_mode, source_type = source_entry
        main_mode, main_type = main_entry
        if source_type != "blob" or main_type != "blob":
            raise ValueError(f"approved recovery path must remain a Git blob: {path}")
        if source_mode not in REGULAR_GIT_MODES or main_mode not in REGULAR_GIT_MODES:
            raise ValueError(f"approved recovery path must remain a regular Git file: {path}")
        if source_mode != main_mode:
            raise ValueError(f"approved recovery path mode changed: {path}")

    if source_entries.get(RECOVERY_MANIFEST_PATH) is not None:
        raise ValueError("recovery manifest must not exist at the immutable source")
    if main_entries.get(RECOVERY_MANIFEST_PATH) != ("100644", "blob"):
        raise ValueError("recovery manifest must be a non-executable regular Git blob")


def require_recovery_delta(repo_root: Path, source_sha: str, main_sha: str) -> None:
    source = normalize_sha(source_sha, "recovery source SHA")
    main = normalize_sha(main_sha, "main SHA")
    completed = _run_git(
        repo_root,
        ["diff", "--name-status", "-z", "--find-renames", "--find-copies", source, main, "--"],
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"cannot inspect recovery delta: {detail or completed.returncode}")
    records = parse_name_status_z(completed.stdout)
    if not records:
        raise ValueError("recovery delta is empty")

    source_entries = {
        path: _tree_entry(repo_root, source, path)
        for path in RECOVERY_ALLOWED_PATHS
    }
    main_entries = {
        path: _tree_entry(repo_root, main, path)
        for path in RECOVERY_ALLOWED_PATHS
    }
    validate_recovery_delta_records(records, source_entries, main_entries)


def authorize_dispatch(
    workflow_sha: str,
    main_sha: str,
    requested_tag: str,
    firmware_version: str,
    tag_sha: str,
    main_rules_payload: object,
    main_check_runs_payload: dict[str, Any],
    main_statuses_payload: dict[str, Any],
    *,
    recovery_id: str = "",
    recovery_manifest_payload: object | None = None,
    source_check_runs_payload: dict[str, Any] | None = None,
    source_statuses_payload: dict[str, Any] | None = None,
    failed_run_payload: object | None = None,
    failed_jobs_payload: object | None = None,
    tag_immutability_ruleset_payload: object | None = None,
    release_state: str | None = None,
    legacy_workflow_text: str | None = None,
    legacy_workflow_metadata_payload: object | None = None,
    repo_root: Path = Path("."),
) -> tuple[str, str, bool]:
    workflow = require_exact_main(workflow_sha, main_sha)

    if not recovery_id:
        requested = authorize_release(
            workflow,
            main_sha,
            requested_tag,
            firmware_version,
            tag_sha,
            main_rules_payload,
            main_check_runs_payload,
            main_statuses_payload,
        )
        return requested, workflow, False

    if recovery_id != RECOVERY_ID:
        raise ValueError("recovery ID is not the single approved incident")

    requested = require_requested_tag(requested_tag, firmware_version)
    if requested != RECOVERY_TAG:
        raise ValueError("recovery tag is not the single approved incident tag")

    manifest = require_recovery_manifest(recovery_manifest_payload)
    source = normalize_sha(str(manifest["source_sha"]), "recovery source SHA")
    require_existing_tag_at_source(tag_sha, source)

    require_protected_main_checks(
        workflow,
        main_rules_payload,
        main_check_runs_payload,
        main_statuses_payload,
    )
    if source_check_runs_payload is None or source_statuses_payload is None:
        raise ValueError("exact-source current-required-check evidence is missing")
    require_protected_main_checks(
        source,
        main_rules_payload,
        source_check_runs_payload,
        source_statuses_payload,
    )

    require_failed_run(failed_run_payload, failed_jobs_payload)
    require_tag_immutability(tag_immutability_ruleset_payload)
    require_release_absent(release_state or "")
    if legacy_workflow_text is None:
        raise ValueError("legacy Release tombstone evidence is missing")
    require_legacy_release_tombstone(legacy_workflow_text)
    require_legacy_workflow_disabled(legacy_workflow_metadata_payload)

    require_recovery_ancestry(repo_root, source, main_sha)
    require_recovery_delta(repo_root, source, main_sha)
    return requested, source, True


def _load_json(path: Path | None, label: str) -> object:
    if path is None:
        raise ValueError(f"{label} path is required")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {exc}") from exc


def _write_github_output(
    output_path: Path,
    requested_tag: str,
    source_sha: str,
    recovery_mode: bool,
) -> None:
    with output_path.open("a", encoding="utf-8") as stream:
        stream.write(f"requested-tag={requested_tag}\n")
        stream.write(f"source-sha={source_sha}\n")
        stream.write(f"recovery-mode={'true' if recovery_mode else 'false'}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--main-sha", required=True)
    parser.add_argument("--requested-tag", required=True)
    parser.add_argument("--firmware-version", required=True)
    parser.add_argument("--tag-sha", required=True)
    parser.add_argument("--main-rules", type=Path, required=True)
    parser.add_argument("--main-check-runs", type=Path, required=True)
    parser.add_argument("--main-statuses", type=Path, required=True)
    parser.add_argument("--recovery-id", default="")
    parser.add_argument("--recovery-manifest", type=Path)
    parser.add_argument("--source-check-runs", type=Path)
    parser.add_argument("--source-statuses", type=Path)
    parser.add_argument("--failed-run", type=Path)
    parser.add_argument("--failed-run-jobs", type=Path)
    parser.add_argument("--tag-immutability-ruleset", type=Path)
    parser.add_argument("--release-state", choices=("absent", "present"))
    parser.add_argument("--legacy-workflow", type=Path)
    parser.add_argument("--legacy-workflow-metadata", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()

    try:
        main_rules_payload = _load_json(args.main_rules, "main-rules")
        main_check_runs_payload = _load_json(args.main_check_runs, "main check-runs")
        main_statuses_payload = _load_json(args.main_statuses, "main statuses")

        recovery_manifest_payload = None
        source_check_runs_payload = None
        source_statuses_payload = None
        failed_run_payload = None
        failed_jobs_payload = None
        tag_immutability_ruleset_payload = None
        legacy_workflow_text = None
        legacy_workflow_metadata_payload = None

        if args.recovery_id:
            recovery_manifest_payload = _load_json(args.recovery_manifest, "recovery manifest")
            source_check_runs_payload = _load_json(args.source_check_runs, "source check-runs")
            source_statuses_payload = _load_json(args.source_statuses, "source statuses")
            failed_run_payload = _load_json(args.failed_run, "failed run")
            failed_jobs_payload = _load_json(args.failed_run_jobs, "failed run jobs")
            tag_immutability_ruleset_payload = _load_json(
                args.tag_immutability_ruleset,
                "tag-immutability Ruleset",
            )
            if args.legacy_workflow is None:
                raise ValueError("legacy workflow path is required in recovery mode")
            legacy_workflow_text = args.legacy_workflow.read_text(encoding="utf-8")
            legacy_workflow_metadata_payload = _load_json(
                args.legacy_workflow_metadata,
                "legacy workflow metadata",
            )

        requested, source, recovery_mode = authorize_dispatch(
            args.workflow_sha,
            args.main_sha,
            args.requested_tag,
            args.firmware_version,
            args.tag_sha,
            main_rules_payload,
            main_check_runs_payload,
            main_statuses_payload,
            recovery_id=args.recovery_id,
            recovery_manifest_payload=recovery_manifest_payload,
            source_check_runs_payload=source_check_runs_payload,
            source_statuses_payload=source_statuses_payload,
            failed_run_payload=failed_run_payload,
            failed_jobs_payload=failed_jobs_payload,
            tag_immutability_ruleset_payload=tag_immutability_ruleset_payload,
            release_state=args.release_state,
            legacy_workflow_text=legacy_workflow_text,
            legacy_workflow_metadata_payload=legacy_workflow_metadata_payload,
            repo_root=args.repo_root,
        )
        _write_github_output(args.github_output, requested, source, recovery_mode)
    except (OSError, ValueError) as exc:
        print(f"Release authorization failed: {exc}")
        return 1

    print(requested)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
