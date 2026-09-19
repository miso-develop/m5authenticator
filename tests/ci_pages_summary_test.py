from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import ci_pages_summary


class PagesCandidateSummaryTests(unittest.TestCase):
    def test_candidate_authorization_summary_records_exact_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            ci_pages_summary.append_candidate_authorization_summary(
                summary,
                source_ref="refs/heads/main",
                source_sha="a" * 40,
                candidate_sha="a" * 40,
                current_main="a" * 40,
            )
            self.assertEqual(
                summary.read_text(encoding="utf-8"),
                "## PRE-RELEASE Pages candidate\n"
                "\n"
                "- source ref: `refs/heads/main`\n"
                f"- source SHA: `{'a' * 40}`\n"
                f"- candidate SHA: `{'a' * 40}`\n"
                f"- current main: `{'a' * 40}`\n"
                "- this deployment is a mutable public candidate, not an immutable GitHub Release\n",
            )

    def test_candidate_build_identity_records_non_exact_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            ci_pages_summary.append_candidate_build_identity(
                summary,
                version="1.0.0",
                build_commit="b" * 40,
                exact_release="false",
            )
            self.assertEqual(
                summary.read_text(encoding="utf-8"),
                "\n"
                "### Candidate build identity\n"
                "- Web/Firmware version: `v1.0.0`\n"
                f"- build commit: `{'b' * 40}`\n"
                "- exact release: `false`\n",
            )

    def test_cli_preserves_shell_metacharacters_as_literal_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = root / "summary.md"
            backtick_sentinel = root / "backtick-executed"
            dollar_sentinel = root / "dollar-executed"
            source_ref = (
                "refs/heads/main"
                f"`touch {backtick_sentinel}`"
                f"$(touch {dollar_sentinel})"
            )

            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "ci_pages_summary.py"),
                    "candidate-authorization",
                    "--summary-path",
                    str(summary),
                    "--source-ref",
                    source_ref,
                    "--source-sha",
                    "c" * 40,
                    "--candidate-sha",
                    "c" * 40,
                    "--current-main",
                    "c" * 40,
                ],
                cwd=REPO_ROOT,
                check=True,
            )

            rendered = summary.read_text(encoding="utf-8")
            self.assertIn("refs/heads/main", rendered)
            self.assertIn("$(touch ", rendered)
            self.assertIn("\\`touch ", rendered)
            self.assertFalse(backtick_sentinel.exists())
            self.assertFalse(dollar_sentinel.exists())


if __name__ == "__main__":
    unittest.main()
