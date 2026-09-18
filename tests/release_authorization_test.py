from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import release_authorization


SOURCE_SHA = "a" * 40
OTHER_SHA = "b" * 40


def check_runs(
    *,
    source_sha: str = SOURCE_SHA,
    status: str = "completed",
    conclusion: str = "success",
    app_id: int = 15368,
    include_required: bool = True,
) -> dict[str, object]:
    runs: list[dict[str, object]] = []
    if include_required:
        runs.append(
            {
                "name": "security:scan",
                "head_sha": source_sha,
                "status": status,
                "conclusion": conclusion,
                "app": {"id": app_id},
            }
        )
    return {"check_runs": runs}


class ReleaseAuthorizationTest(unittest.TestCase):
    def test_exact_main_with_required_security_check_passes(self) -> None:
        self.assertEqual(
            release_authorization.authorize_release(
                SOURCE_SHA,
                SOURCE_SHA,
                check_runs(),
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
                        check_runs(),
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
                        payload,
                    )

    def test_required_check_must_belong_to_expected_github_actions_integration(self) -> None:
        with self.assertRaisesRegex(ValueError, "security:scan"):
            release_authorization.authorize_release(
                SOURCE_SHA,
                SOURCE_SHA,
                check_runs(app_id=99999),
            )

    def test_required_check_must_be_for_exact_release_sha(self) -> None:
        with self.assertRaisesRegex(ValueError, "security:scan"):
            release_authorization.authorize_release(
                SOURCE_SHA,
                SOURCE_SHA,
                check_runs(source_sha=OTHER_SHA),
            )

    def test_full_commit_sha_is_required(self) -> None:
        with self.assertRaisesRegex(ValueError, "full 40-character"):
            release_authorization.authorize_release(
                "abcdef0",
                "abcdef0",
                check_runs(source_sha="abcdef0"),
            )


if __name__ == "__main__":
    unittest.main()
