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


class ReleaseAuthorizationTest(unittest.TestCase):
    def test_exact_main_with_all_active_ruleset_checks_passes(self) -> None:
        self.assertEqual(
            release_authorization.authorize_release(
                SOURCE_SHA,
                SOURCE_SHA,
                main_rules(),
                check_runs(),
                statuses(),
            ),
            SOURCE_SHA,
        )

    def test_off_main_or_stale_main_source_fails_closed(self) -> None:
        for main_sha in (OTHER_SHA, "c" * 40):
            with self.subTest(main_sha=main_sha):
                with self.assertRaisesRegex(ValueError, "exact current protected-main HEAD"):
                    release_authorization.authorize_release(
                        SOURCE_SHA,
                        main_sha,
                        main_rules(),
                        check_runs(),
                        statuses(),
                    )

    def test_missing_or_failed_required_security_check_fails_closed(self) -> None:
        payloads = (
            check_runs(include_required=False),
            check_runs(status="in_progress", conclusion="success"),
            check_runs(conclusion="failure"),
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ValueError, "security:scan"):
                    release_authorization.authorize_release(
                        SOURCE_SHA,
                        SOURCE_SHA,
                        main_rules(),
                        payload,
                        statuses(),
                    )

    def test_all_active_required_checks_must_pass(self) -> None:
        rules = main_rules(
            checks=[
                {"context": "security:scan", "integration_id": ACTIONS_APP_ID},
                {"context": "second-required-check", "integration_id": ACTIONS_APP_ID},
            ]
        )
        with self.assertRaisesRegex(ValueError, "second-required-check"):
            release_authorization.authorize_release(
                SOURCE_SHA,
                SOURCE_SHA,
                rules,
                check_runs(),
                statuses(),
            )

    def test_required_check_must_belong_to_ruleset_integration(self) -> None:
        with self.assertRaisesRegex(ValueError, "security:scan"):
            release_authorization.authorize_release(
                SOURCE_SHA,
                SOURCE_SHA,
                main_rules(),
                check_runs(app_id=99999),
                statuses(),
            )

    def test_required_check_must_be_for_exact_release_sha(self) -> None:
        with self.assertRaisesRegex(ValueError, "security:scan"):
            release_authorization.authorize_release(
                SOURCE_SHA,
                SOURCE_SHA,
                main_rules(),
                check_runs(source_sha=OTHER_SHA),
                statuses(),
            )

    def test_unbound_required_context_may_be_satisfied_by_commit_status(self) -> None:
        rules = main_rules(checks=[{"context": "external-status", "integration_id": None}])
        self.assertEqual(
            release_authorization.authorize_release(
                SOURCE_SHA,
                SOURCE_SHA,
                rules,
                check_runs(include_required=False),
                statuses(context="external-status", state="success"),
            ),
            SOURCE_SHA,
        )

    def test_failed_classic_status_fails_closed(self) -> None:
        rules = main_rules(checks=[{"context": "external-status", "integration_id": None}])
        with self.assertRaisesRegex(ValueError, "external-status"):
            release_authorization.authorize_release(
                SOURCE_SHA,
                SOURCE_SHA,
                rules,
                check_runs(include_required=False),
                statuses(context="external-status", state="failure"),
            )

    def test_no_active_required_status_checks_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "no required status checks"):
            release_authorization.authorize_release(
                SOURCE_SHA,
                SOURCE_SHA,
                [{"type": "deletion"}],
                check_runs(),
                statuses(),
            )

    def test_full_commit_sha_is_required(self) -> None:
        with self.assertRaisesRegex(ValueError, "full 40-character"):
            release_authorization.authorize_release(
                "abcdef0",
                "abcdef0",
                main_rules(),
                check_runs(source_sha="abcdef0"),
                statuses(),
            )


if __name__ == "__main__":
    unittest.main()
