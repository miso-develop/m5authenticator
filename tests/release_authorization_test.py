from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import release_authorization


SOURCE_SHA = "a" * 40
OTHER_SHA = "b" * 40
WORKFLOW_SHA = "c" * 40
ACTIONS_APP_ID = 15368
FIRMWARE_VERSION = "0.2.0"
REQUESTED_TAG = "v0.2.0"


def main_rules(
    *,
    checks: list[dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    if checks is None:
        checks = [{"context": "security:scan", "integration_id": ACTIONS_APP_ID}]
    return [
        {"type": "deletion"},
        {
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": False,
                "do_not_enforce_on_create": False,
                "required_status_checks": checks,
            },
        },
    ]


def check_runs(
    *,
    source_sha: str = SOURCE_SHA,
    context: str = "security:scan",
    status: str = "completed",
    conclusion: str = "success",
    app_id: int = ACTIONS_APP_ID,
    include_required: bool = True,
) -> dict[str, object]:
    runs: list[dict[str, object]] = []
    if include_required:
        runs.append(
            {
                "name": context,
                "head_sha": source_sha,
                "status": status,
                "conclusion": conclusion,
                "app": {"id": app_id},
            }
        )
    return {"check_runs": runs}


def statuses(
    *,
    context: str = "external-status",
    state: str = "success",
) -> dict[str, object]:
    return {
        "state": state,
        "statuses": [{"context": context, "state": state}],
    }


def authorize(
    *,
    source_sha: str = SOURCE_SHA,
    main_sha: str = SOURCE_SHA,
    requested_tag: str = REQUESTED_TAG,
    firmware_version: str = FIRMWARE_VERSION,
    tag_sha: str = SOURCE_SHA,
    rules: object | None = None,
    runs: dict[str, object] | None = None,
    status_payload: dict[str, object] | None = None,
) -> str:
    return release_authorization.authorize_release(
        source_sha,
        main_sha,
        requested_tag,
        firmware_version,
        tag_sha,
        main_rules() if rules is None else rules,
        check_runs() if runs is None else runs,
        statuses() if status_payload is None else status_payload,
    )


def recovery_manifest() -> dict[str, object]:
    return dict(release_authorization.RECOVERY_MANIFEST)


def failed_run() -> dict[str, object]:
    return {
        "id": release_authorization.RECOVERY_FAILED_RUN_ID,
        "workflow_id": release_authorization.RECOVERY_WORKFLOW_ID,
        "path": release_authorization.RECOVERY_WORKFLOW_PATH,
        "event": "repository_dispatch",
        "run_attempt": 1,
        "head_branch": "main",
        "head_sha": release_authorization.RECOVERY_SOURCE_SHA,
        "conclusion": "failure",
        "repository": {"full_name": release_authorization.RECOVERY_REPOSITORY},
    }


def failed_jobs() -> dict[str, object]:
    conclusions = {
        "authorize-protected-main-release": "failure",
        "build-firmware-unprivileged": "skipped",
        "verify-firmware-unprivileged": "skipped",
        "attest-verified-release-assets": "skipped",
        "publish-verified-release": "skipped",
        "cleanup-transient-release-artifacts": "success",
    }
    return {
        "jobs": [
            {"name": name, "conclusion": conclusion}
            for name, conclusion in conclusions.items()
        ]
    }


def legacy_workflow_metadata(
    *,
    state: str = release_authorization.LEGACY_WORKFLOW_DISABLED_STATE,
) -> dict[str, object]:
    return {
        "id": 123456,
        "name": release_authorization.LEGACY_WORKFLOW_NAME,
        "path": release_authorization.LEGACY_WORKFLOW_PATH,
        "state": state,
    }


def tag_immutability_ruleset() -> dict[str, object]:
    return {
        "name": "SemVer tag immutability",
        "target": "tag",
        "enforcement": "active",
        "conditions": {
            "ref_name": {
                "include": ["refs/tags/v*.*.*"],
                "exclude": [],
            }
        },
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "update"},
        ],
        "bypass_actors": [],
    }


def recovery_authorize(**overrides: object) -> tuple[str, str, bool]:
    arguments: dict[str, object] = {
        "workflow_sha": WORKFLOW_SHA,
        "main_sha": WORKFLOW_SHA,
        "requested_tag": release_authorization.RECOVERY_TAG,
        "firmware_version": "1.0.0",
        "tag_sha": release_authorization.RECOVERY_SOURCE_SHA,
        "main_rules_payload": main_rules(),
        "main_check_runs_payload": check_runs(source_sha=WORKFLOW_SHA),
        "main_statuses_payload": statuses(),
        "recovery_id": release_authorization.RECOVERY_ID,
        "recovery_manifest_payload": recovery_manifest(),
        "source_check_runs_payload": check_runs(
            source_sha=release_authorization.RECOVERY_SOURCE_SHA
        ),
        "source_statuses_payload": statuses(),
        "failed_run_payload": failed_run(),
        "failed_jobs_payload": failed_jobs(),
        "tag_immutability_ruleset_payload": tag_immutability_ruleset(),
        "release_state": "absent",
        "legacy_workflow_text": release_authorization.EXPECTED_LEGACY_RELEASE_WORKFLOW,
        "legacy_workflow_metadata_payload": legacy_workflow_metadata(),
        "repo_root": ROOT,
    }
    arguments.update(overrides)
    with (
        mock.patch.object(release_authorization, "require_recovery_ancestry"),
        mock.patch.object(release_authorization, "require_recovery_delta"),
    ):
        return release_authorization.authorize_dispatch(**arguments)


def regular_tree_entries() -> tuple[
    dict[str, tuple[str, str] | None],
    dict[str, tuple[str, str] | None],
]:
    source = {
        path: ("100644", "blob")
        for path in release_authorization.RECOVERY_EXISTING_PATHS
    }
    source[release_authorization.RECOVERY_MANIFEST_PATH] = None
    main = dict(source)
    main[release_authorization.RECOVERY_MANIFEST_PATH] = ("100644", "blob")
    return source, main


class ReleaseAuthorizationTest(unittest.TestCase):
    def test_exact_main_existing_tag_and_all_active_ruleset_checks_pass(self) -> None:
        self.assertEqual(authorize(), REQUESTED_TAG)

    def test_requested_tag_must_be_exact_semver_and_match_release_profile(self) -> None:
        for requested in ("0.2.0", "v0.2", "v0.2.0-rc.1", "v00.2.0", "refs/tags/v0.2.0"):
            with self.subTest(requested=requested):
                with self.assertRaisesRegex(ValueError, "vX.Y.Z"):
                    authorize(requested_tag=requested)

        with self.assertRaisesRegex(ValueError, "does not match release profile"):
            authorize(requested_tag="v0.2.1")

    def test_off_main_or_stale_main_source_fails_closed(self) -> None:
        for main_sha in (OTHER_SHA, "d" * 40):
            with self.subTest(main_sha=main_sha):
                with self.assertRaisesRegex(ValueError, "exact current protected-main HEAD"):
                    authorize(main_sha=main_sha)

    def test_existing_tag_must_resolve_to_exact_current_main(self) -> None:
        with self.assertRaisesRegex(ValueError, "existing release tag resolves"):
            authorize(tag_sha=OTHER_SHA)

    def test_missing_or_failed_required_security_check_fails_closed(self) -> None:
        payloads = (
            check_runs(include_required=False),
            check_runs(status="in_progress", conclusion="success"),
            check_runs(conclusion="failure"),
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ValueError, "security:scan"):
                    authorize(runs=payload)

    def test_all_active_required_checks_must_pass(self) -> None:
        rules = main_rules(
            checks=[
                {"context": "security:scan", "integration_id": ACTIONS_APP_ID},
                {"context": "second-required-check", "integration_id": ACTIONS_APP_ID},
            ]
        )
        with self.assertRaisesRegex(ValueError, "second-required-check"):
            authorize(rules=rules)

    def test_required_check_must_belong_to_ruleset_integration(self) -> None:
        with self.assertRaisesRegex(ValueError, "security:scan"):
            authorize(runs=check_runs(app_id=99999))

    def test_required_check_must_be_for_exact_release_sha(self) -> None:
        with self.assertRaisesRegex(ValueError, "security:scan"):
            authorize(runs=check_runs(source_sha=OTHER_SHA))

    def test_unbound_required_context_may_be_satisfied_by_commit_status(self) -> None:
        rules = main_rules(checks=[{"context": "external-status", "integration_id": None}])
        self.assertEqual(
            authorize(
                rules=rules,
                runs=check_runs(include_required=False),
                status_payload=statuses(context="external-status", state="success"),
            ),
            REQUESTED_TAG,
        )

    def test_unbound_required_context_may_be_satisfied_by_check_run_only(self) -> None:
        rules = main_rules(checks=[{"context": "external-status", "integration_id": None}])
        self.assertEqual(
            authorize(
                rules=rules,
                runs=check_runs(context="external-status"),
                status_payload={"state": "pending", "statuses": []},
            ),
            REQUESTED_TAG,
        )

    def test_unbound_required_context_requires_both_same_name_mechanisms_to_pass(self) -> None:
        rules = main_rules(checks=[{"context": "external-status", "integration_id": None}])
        with self.assertRaisesRegex(ValueError, "external-status"):
            authorize(
                rules=rules,
                runs=check_runs(context="external-status"),
                status_payload=statuses(context="external-status", state="failure"),
            )
        with self.assertRaisesRegex(ValueError, "external-status"):
            authorize(
                rules=rules,
                runs=check_runs(context="external-status", conclusion="failure"),
                status_payload=statuses(context="external-status", state="success"),
            )
        self.assertEqual(
            authorize(
                rules=rules,
                runs=check_runs(context="external-status"),
                status_payload=statuses(context="external-status", state="success"),
            ),
            REQUESTED_TAG,
        )

    def test_failed_classic_status_fails_closed(self) -> None:
        rules = main_rules(checks=[{"context": "external-status", "integration_id": None}])
        with self.assertRaisesRegex(ValueError, "external-status"):
            authorize(
                rules=rules,
                runs=check_runs(include_required=False),
                status_payload=statuses(context="external-status", state="failure"),
            )

    def test_no_active_required_status_checks_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "no required status checks"):
            authorize(rules=[{"type": "deletion"}])

    def test_full_commit_sha_is_required_for_source_main_and_tag(self) -> None:
        with self.assertRaisesRegex(ValueError, "full 40-character"):
            authorize(source_sha="abcdef0", main_sha="abcdef0", tag_sha="abcdef0")
        with self.assertRaisesRegex(ValueError, "tag SHA"):
            authorize(tag_sha="abcdef0")

    def test_normal_no_recovery_dispatch_preserves_exact_main_semantics(self) -> None:
        requested, source, recovery = release_authorization.authorize_dispatch(
            SOURCE_SHA,
            SOURCE_SHA,
            REQUESTED_TAG,
            FIRMWARE_VERSION,
            SOURCE_SHA,
            main_rules(),
            check_runs(),
            statuses(),
        )
        self.assertEqual(requested, REQUESTED_TAG)
        self.assertEqual(source, SOURCE_SHA)
        self.assertFalse(recovery)

        with self.assertRaisesRegex(ValueError, "exact current protected-main HEAD"):
            release_authorization.authorize_dispatch(
                SOURCE_SHA,
                OTHER_SHA,
                REQUESTED_TAG,
                FIRMWARE_VERSION,
                SOURCE_SHA,
                main_rules(),
                check_runs(),
                statuses(),
            )

    def test_exact_incident_recovery_derives_historical_source_from_reviewed_tuple(self) -> None:
        requested, source, recovery = recovery_authorize()
        self.assertEqual(requested, release_authorization.RECOVERY_TAG)
        self.assertEqual(source, release_authorization.RECOVERY_SOURCE_SHA)
        self.assertNotEqual(source, WORKFLOW_SHA)
        self.assertTrue(recovery)

    def test_unknown_recovery_id_fails_without_fallback(self) -> None:
        with self.assertRaisesRegex(ValueError, "recovery ID"):
            recovery_authorize(recovery_id="another-incident")

    def test_recovery_manifest_requires_exact_schema_types_and_tuple(self) -> None:
        with self.assertRaisesRegex(ValueError, "JSON object"):
            release_authorization.require_recovery_manifest(None)

        for mutation in (
            lambda payload: payload.pop("failed_run_id"),
            lambda payload: payload.update({"extra": True}),
            lambda payload: payload.update({"format": "1"}),
            lambda payload: payload.update({"recovery_id": "other"}),
            lambda payload: payload.update({"tag": "v1.0.1"}),
            lambda payload: payload.update({"source_sha": "d" * 40}),
            lambda payload: payload.update({"failed_run_id": 1}),
        ):
            payload = recovery_manifest()
            mutation(payload)
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    release_authorization.require_recovery_manifest(payload)

    def test_recovery_current_and_source_required_checks_both_must_pass(self) -> None:
        with self.assertRaisesRegex(ValueError, "security:scan"):
            recovery_authorize(
                main_check_runs_payload=check_runs(
                    source_sha=WORKFLOW_SHA,
                    conclusion="failure",
                )
            )
        with self.assertRaisesRegex(ValueError, "security:scan"):
            recovery_authorize(
                source_check_runs_payload=check_runs(
                    source_sha=release_authorization.RECOVERY_SOURCE_SHA,
                    conclusion="failure",
                )
            )

    def test_failed_run_metadata_and_job_results_are_authorization_facts(self) -> None:
        bad_run = failed_run()
        bad_run["workflow_id"] = 1
        with self.assertRaisesRegex(ValueError, "workflow_id"):
            recovery_authorize(failed_run_payload=bad_run)

        bad_jobs = failed_jobs()
        bad_jobs["jobs"][1]["conclusion"] = "success"
        with self.assertRaisesRegex(ValueError, "build-firmware-unprivileged"):
            recovery_authorize(failed_jobs_payload=bad_jobs)

    def test_recovery_tag_release_immutability_and_legacy_gates_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "existing release tag"):
            recovery_authorize(tag_sha=OTHER_SHA)

        with self.assertRaisesRegex(ValueError, "already exists"):
            recovery_authorize(release_state="present")

        bad_ruleset = tag_immutability_ruleset()
        bad_ruleset["enforcement"] = "disabled"
        with self.assertRaisesRegex(ValueError, "not active"):
            recovery_authorize(tag_immutability_ruleset_payload=bad_ruleset)

        excluded_ruleset = tag_immutability_ruleset()
        excluded_ruleset["conditions"]["ref_name"]["exclude"] = ["refs/tags/v1.0.0"]
        with self.assertRaisesRegex(ValueError, "no ref exclusions"):
            recovery_authorize(tag_immutability_ruleset_payload=excluded_ruleset)

        with self.assertRaisesRegex(ValueError, "retired tombstone"):
            recovery_authorize(legacy_workflow_text="name: Release\n")

        with self.assertRaisesRegex(ValueError, "metadata mismatch: state"):
            recovery_authorize(
                legacy_workflow_metadata_payload=legacy_workflow_metadata(state="active")
            )

        bad_legacy_identity = legacy_workflow_metadata()
        bad_legacy_identity["path"] = ".github/workflows/other.yml"
        with self.assertRaisesRegex(ValueError, "metadata mismatch: path"):
            recovery_authorize(
                legacy_workflow_metadata_payload=bad_legacy_identity
            )

    def test_recovery_ancestry_and_delta_failures_are_not_bypassed(self) -> None:
        arguments = {
            "workflow_sha": WORKFLOW_SHA,
            "main_sha": WORKFLOW_SHA,
            "requested_tag": release_authorization.RECOVERY_TAG,
            "firmware_version": "1.0.0",
            "tag_sha": release_authorization.RECOVERY_SOURCE_SHA,
            "main_rules_payload": main_rules(),
            "main_check_runs_payload": check_runs(source_sha=WORKFLOW_SHA),
            "main_statuses_payload": statuses(),
            "recovery_id": release_authorization.RECOVERY_ID,
            "recovery_manifest_payload": recovery_manifest(),
            "source_check_runs_payload": check_runs(
                source_sha=release_authorization.RECOVERY_SOURCE_SHA
            ),
            "source_statuses_payload": statuses(),
            "failed_run_payload": failed_run(),
            "failed_jobs_payload": failed_jobs(),
            "tag_immutability_ruleset_payload": tag_immutability_ruleset(),
            "release_state": "absent",
            "legacy_workflow_text": release_authorization.EXPECTED_LEGACY_RELEASE_WORKFLOW,
            "legacy_workflow_metadata_payload": legacy_workflow_metadata(),
            "repo_root": ROOT,
        }
        with (
            mock.patch.object(
                release_authorization,
                "require_recovery_ancestry",
                side_effect=ValueError("approved recovery source is not an ancestor"),
            ),
            mock.patch.object(release_authorization, "require_recovery_delta"),
        ):
            with self.assertRaisesRegex(ValueError, "not an ancestor"):
                release_authorization.authorize_dispatch(**arguments)

        with (
            mock.patch.object(release_authorization, "require_recovery_ancestry"),
            mock.patch.object(
                release_authorization,
                "require_recovery_delta",
                side_effect=ValueError("non-approved path"),
            ),
        ):
            with self.assertRaisesRegex(ValueError, "non-approved path"):
                release_authorization.authorize_dispatch(**arguments)

    def test_recovery_delta_accepts_only_closed_regular_six_path_surface(self) -> None:
        source, main = regular_tree_entries()
        records = [
            ("M", (path,))
            for path in sorted(release_authorization.RECOVERY_EXISTING_PATHS)
        ]
        records.append(("A", (release_authorization.RECOVERY_MANIFEST_PATH,)))
        release_authorization.validate_recovery_delta_records(records, source, main)

        with self.subTest("seventh path"):
            with self.assertRaisesRegex(ValueError, "non-approved path"):
                release_authorization.validate_recovery_delta_records(
                    records + [("M", ("README.md",))],
                    source,
                    main,
                )

        for status in ("D", "T", "U"):
            with self.subTest(status=status):
                changed = list(records)
                changed[0] = (status, changed[0][1])
                with self.assertRaisesRegex(ValueError, "status"):
                    release_authorization.validate_recovery_delta_records(
                        changed,
                        source,
                        main,
                    )

        for status in ("R100", "C100"):
            with self.subTest(status=status):
                with self.assertRaisesRegex(ValueError, "rename/copy"):
                    release_authorization.validate_recovery_delta_records(
                        [(status, ("scripts/release_authorization.py", "README.md"))],
                        source,
                        main,
                    )

    def test_recovery_delta_rejects_mode_symlink_gitlink_and_manifest_surprises(self) -> None:
        records = [
            ("M", (path,))
            for path in sorted(release_authorization.RECOVERY_EXISTING_PATHS)
        ]
        records.append(("A", (release_authorization.RECOVERY_MANIFEST_PATH,)))

        source, main = regular_tree_entries()
        target = "scripts/release_authorization.py"
        main[target] = ("100755", "blob")
        with self.assertRaisesRegex(ValueError, "mode changed"):
            release_authorization.validate_recovery_delta_records(records, source, main)

        source, main = regular_tree_entries()
        main[target] = ("120000", "blob")
        with self.assertRaisesRegex(ValueError, "regular Git file"):
            release_authorization.validate_recovery_delta_records(records, source, main)

        source, main = regular_tree_entries()
        main[target] = ("160000", "commit")
        with self.assertRaisesRegex(ValueError, "Git blob"):
            release_authorization.validate_recovery_delta_records(records, source, main)

        source, main = regular_tree_entries()
        main[release_authorization.RECOVERY_MANIFEST_PATH] = ("100755", "blob")
        with self.assertRaisesRegex(ValueError, "non-executable"):
            release_authorization.validate_recovery_delta_records(records, source, main)

        source, main = regular_tree_entries()
        source[release_authorization.RECOVERY_MANIFEST_PATH] = ("100644", "blob")
        with self.assertRaisesRegex(ValueError, "must not exist"):
            release_authorization.validate_recovery_delta_records(records, source, main)

    def test_name_status_parser_retains_rename_copy_delete_and_type_statuses(self) -> None:
        payload = (
            b"R100\0old\0new\0"
            b"C100\0src\0copy\0"
            b"D\0deleted\0"
            b"T\0typed\0"
            b"M\0modified\0"
        )
        self.assertEqual(
            release_authorization.parse_name_status_z(payload),
            [
                ("R100", ("old", "new")),
                ("C100", ("src", "copy")),
                ("D", ("deleted",)),
                ("T", ("typed",)),
                ("M", ("modified",)),
            ],
        )


if __name__ == "__main__":
    unittest.main()
