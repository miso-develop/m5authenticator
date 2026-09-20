import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import ci_change_impact


class ChangeImpactClassificationTests(unittest.TestCase):
    def assert_heavy(self, result, *, web, firmware):
        self.assertEqual(result["web"], web)
        self.assertEqual(result["firmware"], firmware)
        self.assertEqual(result["uncertain"], False)

    def test_regression_matrix(self) -> None:
        cases = (
            (["README.md"], False, False, True),
            (["README.md", "docs/assets/hero.jpg"], False, False, True),
            ([".agent/BOOTSTRAP.md", ".agent/WORK-TRACKING.md"], False, False, True),
            ([".agent/PROJECT.md", ".agents/skills/README.md"], False, False, True),
            (["docs/ARCHITECTURE.md"], False, False, True),
            (["web/src/main.ts"], True, False, False),
            (["firmware/main/main.cpp"], False, True, False),
            (["scripts/package_firmware.py"], True, True, False),
            ([".github/workflows/foundation.yml"], True, True, False),
            (["brand-new-top-level.file"], True, True, False),
        )
        for paths, web, firmware, process_docs_only in cases:
            with self.subTest(paths=paths):
                result = ci_change_impact.classify_paths(paths)
                self.assert_heavy(result, web=web, firmware=firmware)
                self.assertEqual(result["process_docs_only"], process_docs_only)

    def test_retired_agent_and_project_paths_fail_safe_heavy(self) -> None:
        retired_paths = (
            "agent" + "/" + "WORK-TRACKING.md",
            "PROJECT" + ".md",
        )
        for path in retired_paths:
            with self.subTest(path=path):
                result = ci_change_impact.classify_paths([path])
                self.assertFalse(result["process_docs_only"])
                self.assertTrue(result["web"])
                self.assertTrue(result["firmware"])
                self.assertTrue(result["pages"])
                self.assertTrue(result["security_release_shared"])
                self.assertFalse(result["uncertain"])

    def test_web_and_shared_paths_drive_pages_semantics(self) -> None:
        web = ci_change_impact.classify_paths(["web/src/main.ts"])
        self.assertTrue(web["web"])
        self.assertTrue(web["pages"])
        self.assertFalse(web["firmware"])

        shared = ci_change_impact.classify_paths(["scripts/validate_release.py"])
        self.assertTrue(shared["web"])
        self.assertTrue(shared["firmware"])
        self.assertTrue(shared["pages"])
        self.assertTrue(shared["security_release_shared"])

    def test_snapshot_docs_and_agents_are_lightweight_only(self) -> None:
        for path in (
            "AGENTS.md",
            "docs/testing/screen-snapshot-diagnostics.md",
            "scripts/windows/build-screen-snapshot.cmd",
            "tools/diagnostics/screen_snapshot.py",
            "tests/screen_snapshot_usage_contract_test.py",
        ):
            with self.subTest(path=path):
                result = ci_change_impact.classify_paths([path])
                self.assertTrue(result["snapshot_contract"])
                self.assertFalse(result["snapshot_build"])
                self.assertFalse(result["web"])
                self.assertFalse(result["firmware"])

    def test_snapshot_firmware_inputs_request_contract_and_build(self) -> None:
        for path in (
            "firmware/CMakeLists.txt",
            "firmware/sdkconfig.defaults",
            "firmware/main/main.cpp",
            "firmware/components/m5auth_device_sticks3/ui_model.cpp",
            "firmware/components/m5auth_time/trusted_time.cpp",
            "firmware/components/m5auth_session/session_crypto.cpp",
            "firmware/components/m5auth_vault_runtime/runtime.cpp",
            "scripts/esp_idf_build_image.py",
            "tests/esp_idf_image_pin_contract_test.py",
            ".github/workflows/issue117-screen-snapshot.yml",
        ):
            with self.subTest(path=path):
                result = ci_change_impact.classify_paths([path])
                self.assertTrue(result["snapshot_contract"])
                self.assertTrue(result["snapshot_build"])

    def test_classifier_change_exercises_snapshot_build_semantics(self) -> None:
        result = ci_change_impact.classify_paths(["scripts/ci_change_impact.py"])
        self.assertTrue(result["snapshot_contract"])
        self.assertTrue(result["snapshot_build"])
        self.assertTrue(result["web"])
        self.assertTrue(result["firmware"])
        self.assertTrue(result["security_release_shared"])

    def test_unknown_and_empty_inputs_fail_safe(self) -> None:
        unknown = ci_change_impact.classify_paths(["unknown/new-surface.xyz"])
        self.assertTrue(unknown["web"])
        self.assertTrue(unknown["firmware"])
        self.assertTrue(unknown["security_release_shared"])

        empty = ci_change_impact.classify_paths([])
        self.assertTrue(empty["uncertain"])
        self.assertTrue(empty["web"])
        self.assertTrue(empty["firmware"])
        self.assertTrue(empty["snapshot_build"])

    def test_event_range_uses_pr_base_head_and_push_before_after(self) -> None:
        base = "a" * 40
        head = "b" * 40
        self.assertEqual(
            ci_change_impact.resolve_event_range(
                "pull_request",
                {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}},
            ),
            (base, head),
        )
        self.assertEqual(
            ci_change_impact.resolve_event_range("push", {"before": base, "after": head}),
            (base, head),
        )

    def test_all_zero_push_base_fails_safe(self) -> None:
        with self.assertRaises(ci_change_impact.ImpactError):
            ci_change_impact.resolve_event_range(
                "push",
                {"before": ci_change_impact.ZERO_SHA, "after": "b" * 40},
            )

    def test_rename_and_delete_changed_paths_include_old_and_new_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "ci@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "CI"], cwd=root, check=True)
            (root / "firmware").mkdir()
            (root / "firmware" / "old.cpp").write_text("old\n", encoding="utf-8")
            (root / "README.md").write_text("docs\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()

            (root / "web").mkdir()
            subprocess.run(["git", "mv", "firmware/old.cpp", "web/new.ts"], cwd=root, check=True)
            (root / "README.md").unlink()
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "change"], cwd=root, check=True)
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()

            paths = ci_change_impact.changed_paths(base, head, repo_root=root)
            self.assertIn("firmware/old.cpp", paths)
            self.assertIn("web/new.ts", paths)
            self.assertIn("README.md", paths)

    def test_unavailable_diff_is_all_heavy_uncertain(self) -> None:
        result, paths, reason = ci_change_impact.classify_event(
            "push",
            {"before": "a" * 40, "after": "b" * 40},
            repo_root=Path("/definitely/missing/repository"),
        )
        self.assertTrue(result["uncertain"])
        self.assertTrue(result["web"])
        self.assertTrue(result["firmware"])
        self.assertTrue(result["snapshot_build"])
        self.assertEqual(paths, [])
        self.assertIsInstance(reason, str)


class AgentDocumentationMigrationTests(unittest.TestCase):
    TRANSLATED = (
        "AGENTS.md",
        ".agent/PROJECT.md",
        ".agent/PARALLEL-WORK-CHECKLIST.md",
        ".agent/PARALLEL-WORK.md",
        ".agent/WORK-TRACKING.md",
    )
    CJK = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff]")

    def tracked_text(self) -> dict[str, str]:
        output = subprocess.check_output(
            ["git", "ls-files", "-z"],
            cwd=REPO_ROOT,
        )
        result: dict[str, str] = {}
        for raw in output.split(b"\0"):
            if not raw:
                continue
            path = raw.decode("utf-8")
            try:
                result[path] = (REPO_ROOT / path).read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
        return result

    def test_agent_layout_and_language_are_canonical(self) -> None:
        self.assertTrue((REPO_ROOT / "AGENTS.md").is_file())
        self.assertTrue((REPO_ROOT / "SECURITY.md").is_file())
        self.assertFalse((REPO_ROOT / ("PROJECT" + ".md")).exists())
        self.assertFalse((REPO_ROOT / "agent").exists())
        for path in self.TRANSLATED[1:]:
            self.assertTrue((REPO_ROOT / path).is_file(), path)
        self.assertTrue((REPO_ROOT / ".agents" / "skills").is_dir())

        for path in self.TRANSLATED:
            text = (REPO_ROOT / path).read_text(encoding="utf-8")
            match = self.CJK.search(text)
            self.assertIsNone(
                match,
                f"Japanese/CJK normative prose remains in {path} at offset "
                f"{match.start() if match else 'n/a'}",
            )

    def test_tracked_files_have_no_retired_canonical_references(self) -> None:
        tracked = self.tracked_text()
        retired_root = "agent" + "/"
        retired_root_pattern = re.compile(
            r"(?<![A-Za-z0-9_.-])" + re.escape(retired_root)
        )
        failures: list[str] = []
        for path, text in tracked.items():
            for match in retired_root_pattern.finditer(text):
                failures.append(
                    f"{path}: retired root Agent directory reference at {match.start()}"
                )
            for match in re.finditer(r"(?<!\.agent/)PROJECT\.md", text):
                failures.append(f"{path}: retired root project reference at {match.start()}")
        self.assertEqual(failures, [])

class ChangeImpactWorkflowContractTests(unittest.TestCase):
    FOUNDATION = REPO_ROOT / ".github" / "workflows" / "foundation.yml"
    SECURITY = REPO_ROOT / ".github" / "workflows" / "security.yml"
    PAGES = REPO_ROOT / ".github" / "workflows" / "pages.yml"
    SNAPSHOT = REPO_ROOT / ".github" / "workflows" / "issue117-screen-snapshot.yml"
    RELEASE = REPO_ROOT / ".github" / "workflows" / "release-authorized.yml"

    def test_required_security_context_remains_unfiltered(self) -> None:
        text = self.SECURITY.read_text(encoding="utf-8")
        header = text[: text.index("permissions:")]
        self.assertIn("pull_request:", header)
        self.assertIn("branches:\n      - main", header)
        self.assertNotIn("paths:", header)
        self.assertIn("name: security:scan", text)
        security_job = text[text.index("security-scan:") :]
        self.assertNotIn("\n    if:", security_job)

    def test_foundation_uses_always_run_classifier_and_conditions_heavy_jobs(self) -> None:
        text = self.FOUNDATION.read_text(encoding="utf-8")
        self.assertIn("classify:", text)
        self.assertIn("scripts/ci_change_impact.py", text)
        self.assertIn("fetch-depth: 0", text)
        self.assertIn("needs: classify", text)
        self.assertIn("needs.classify.outputs.web == 'true'", text)
        self.assertIn("needs.classify.outputs.firmware == 'true'", text)

    def test_pages_has_no_main_push_and_retains_tag_manual_cleanup(self) -> None:
        text = self.PAGES.read_text(encoding="utf-8")
        header = text[: text.index("permissions:")]
        self.assertIn("tags:", header)
        self.assertIn("'v*.*.*'", header)
        self.assertNotIn("branches:", header)
        self.assertIn("workflow_dispatch:", header)
        self.assertIn("candidate_sha:", header)
        self.assertIn("candidate_ack:", header)
        self.assertIn("refs/heads/main", text)
        self.assertIn("retention-days: 1", text)
        self.assertIn("actions/artifacts/$PAGES_ARTIFACT_ID", text)
        self.assertIn("GITHUB_STEP_SUMMARY", text)
        self.assertIn("python scripts/ci_pages_summary.py candidate-authorization", text)
        self.assertIn("python scripts/ci_pages_summary.py candidate-build-identity", text)
        self.assertNotRegex(text, r'echo\s+"[^"\n]*`')

    def test_release_authorized_artifact_boundary_is_unchanged(self) -> None:
        text = self.RELEASE.read_text(encoding="utf-8")
        self.assertIn("repository_dispatch:", text)
        self.assertIn("publish_semver_release", text)
        self.assertIn("retention-days: 1", text)
        self.assertIn("actions: write", text)
        self.assertNotIn("pages: write", text)

    def test_snapshot_workflow_splits_contract_and_build_jobs(self) -> None:
        text = self.SNAPSHOT.read_text(encoding="utf-8")
        header = text[: text.index("permissions:")]
        self.assertIn('      - "scripts/ci_change_impact.py"', header)
        self.assertIn("snapshot-contract:", text)
        self.assertIn("snapshot-build:", text)
        self.assertIn("needs.classify.outputs.snapshot_contract == 'true'", text)
        self.assertIn("needs.classify.outputs.snapshot_build == 'true'", text)


if __name__ == "__main__":
    unittest.main()
