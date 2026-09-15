import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WINDOWS_SCRIPTS = ROOT / "scripts" / "windows"
BUILD = WINDOWS_SCRIPTS / "build-screen-snapshot.cmd"
REBUILD = WINDOWS_SCRIPTS / "rebuild-screen-snapshot.cmd"
FLASH = WINDOWS_SCRIPTS / "flash-screen-snapshot.cmd"
DOCS = ROOT / "docs" / "testing" / "screen-snapshot-diagnostics.md"
AGENTS = ROOT / "AGENTS.md"


class WindowsDiagnosticsScriptContractTest(unittest.TestCase):
    def _text(self, path: Path) -> str:
        self.assertTrue(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")
        return path.read_text(encoding="utf-8")

    def _assert_cmd_crlf(self, path: Path) -> None:
        self.assertTrue(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")
        data = path.read_bytes()
        self.assertIn(b"\r\n", data)
        self.assertNotIn(b"\n", data.replace(b"\r\n", b""))

    def _assert_no_forbidden_actions(self, text: str) -> None:
        lowered = text.lower()
        for token in ("erase-flash", "factory reset", "efuse", "provisioning", "re-provision"):
            self.assertNotIn(token, lowered)

    def _assert_no_command_chain(self, text: str) -> None:
        self.assertNotIn("&&", text)

    def _assert_guarded_command(self, text: str, command_fragment: str) -> None:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        index = next(
            (i for i, line in enumerate(lines) if command_fragment.lower() in line.lower()),
            None,
        )
        self.assertIsNotNone(index, f"missing command: {command_fragment}")
        self.assertLess(index + 1, len(lines), f"missing errorlevel guard after: {command_fragment}")
        self.assertTrue(
            lines[index + 1].lower().startswith("if errorlevel 1"),
            f"command is not immediately guarded: {command_fragment}",
        )

    def test_required_cmd_files_exist_and_use_crlf(self) -> None:
        for path in (BUILD, REBUILD, FLASH):
            self._assert_cmd_crlf(path)

    def test_all_scripts_are_location_independent_and_avoid_command_chaining(self) -> None:
        for path in (BUILD, REBUILD, FLASH):
            text = self._text(path)
            self.assertIn("%~dp0", text)
            self.assertIn("firmware", text.lower())
            self._assert_no_command_chain(text)
            self._assert_no_forbidden_actions(text)
            self.assertNotIn("screen_snapshot.py", text.lower())
            self.assertNotRegex(text.lower(), r"\bidf\.py\b[^\r\n]*\bmonitor\b")

    def test_incremental_build_does_not_flash_and_verifies_diagnostics_on(self) -> None:
        text = self._text(BUILD)
        lowered = text.lower()
        self.assertIn("idf.py --version", lowered)
        self.assertIn("-b build-screen-snapshot", lowered)
        self.assertIn("-dm5auth_test_screen_snapshot=on build", lowered)
        self.assertIn('findstr /c:"m5auth_test_screen_snapshot:bool=on" build-screen-snapshot\\cmakecache.txt', lowered)
        self.assertNotRegex(lowered, r"\bidf\.py\b[^\r\n]*\sflash(?:\s|$)")
        self._assert_guarded_command(text, "idf.py --version")
        self._assert_guarded_command(text, "-DM5AUTH_TEST_SCREEN_SNAPSHOT=ON build")

    def test_rebuild_follows_clean_profile_sequence_and_never_flashes(self) -> None:
        text = self._text(REBUILD)
        lowered = text.lower()
        required = [
            "git rev-parse head",
            "idf.py --version",
            "idf.py -b build-screen-snapshot set-target esp32s3",
            "idf.py -b build-screen-snapshot -dm5auth_test_screen_snapshot=on build",
            'findstr /c:"m5auth_test_screen_snapshot:bool=on" build-screen-snapshot\\cmakecache.txt',
        ]
        positions = [lowered.index(item) for item in required]
        self.assertEqual(positions, sorted(positions))
        for item in required:
            self._assert_guarded_command(text, item)
        self.assertNotRegex(lowered, r"\bidf\.py\b[^\r\n]*\sflash(?:\s|$)")
        self.assertIn("pass", lowered)
        self.assertIn("fail", lowered)

    def test_flash_requires_port_and_checks_diagnostics_before_flash(self) -> None:
        text = self._text(FLASH)
        lowered = text.lower()
        self.assertIn('if "%~1"==""', lowered)
        self.assertIn("usage:", lowered)
        self.assertRegex(lowered, r"exit /b [1-9][0-9]*")
        guard = 'findstr /c:"m5auth_test_screen_snapshot:bool=on" build-screen-snapshot\\cmakecache.txt'
        flash = 'idf.py -b build-screen-snapshot -p "%port%" flash'
        self.assertIn(guard, lowered)
        self.assertIn(flash, lowered)
        self.assertLess(lowered.index(guard), lowered.index(flash))
        self._assert_guarded_command(text, guard)
        self._assert_guarded_command(text, flash)
        self.assertNotIn("set-target", lowered)
        command_lines = [line.strip().lower() for line in text.splitlines()]
        self.assertFalse(any(line.endswith(" build") and "idf.py" in line for line in command_lines))

    def test_windows_documentation_uses_scripts_but_keeps_human_gate_separate(self) -> None:
        docs = self._text(DOCS).lower()
        self.assertIn("scripts\\windows\\rebuild-screen-snapshot.cmd", docs)
        self.assertIn("scripts\\windows\\flash-screen-snapshot.cmd com8", docs)
        self.assertIn("screen_snapshot.py", docs)
        self.assertIn("integration", docs)
        self.assertRegex(docs, r"screen_snapshot\.py[\s\S]{0,1200}(one|1).{0,40}(run|invocation|回)")

    def test_project_command_chaining_policy_is_durable(self) -> None:
        agents = self._text(AGENTS).lower()
        self.assertIn("command chaining", agents)
        self.assertIn("&&", agents)
        self.assertIn("build", agents)
        self.assertIn("flash", agents)
        self.assertIn("monitor", agents)
        self.assertIn("human gate", agents)


if __name__ == "__main__":
    unittest.main()
