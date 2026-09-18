from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import release_authorization


SOURCE_SHA = "a" * 40
OTHER_SHA = "b" * 40
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
        for main_sha in (OTHER_SHA, "c" * 40):
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

        with self.subTest("successful check run plus failed classic status"):
            with self.assertRaisesRegex(ValueError, "external-status"):
                authorize(
                    rules=rules,
                    runs=check_runs(
                        context="external-status",
                        status="completed",
                        conclusion="success",
                    ),
                    status_payload=statuses(
                        context="external-status",
                        state="failure",
                    ),
                )

        with self.subTest("failed check run plus successful classic status"):
            with self.assertRaisesRegex(ValueError, "external-status"):
                authorize(
                    rules=rules,
                    runs=check_runs(
                        context="external-status",
                        status="completed",
                        conclusion="failure",
                    ),
                    status_payload=statuses(
                        context="external-status",
                        state="success",
                    ),
                )

        with self.subTest("both same-name mechanisms successful"):
            self.assertEqual(
                authorize(
                    rules=rules,
                    runs=check_runs(
                        context="external-status",
                        status="completed",
                        conclusion="success",
                    ),
                    status_payload=statuses(
                        context="external-status",
                        state="success",
                    ),
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


if __name__ == "__main__":
    unittest.main()
