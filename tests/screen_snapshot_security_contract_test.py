from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_MAIN = ROOT / "firmware/main/app_main.cpp"
APP_MAIN_CMAKE = ROOT / "firmware/main/CMakeLists.txt"
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"
PAGES_WORKFLOW = ROOT / ".github/workflows/pages.yml"


class ScreenSnapshotSecurityContractTest(unittest.TestCase):
    def test_compile_time_flag_is_default_off(self) -> None:
        cmake = APP_MAIN_CMAKE.read_text(encoding="utf-8")
        app = APP_MAIN.read_text(encoding="utf-8")
        option = re.search(
            r"option\(\s*M5AUTH_TEST_SCREEN_SNAPSHOT[\s\S]+?OFF\s*\)",
            cmake,
        )
        self.assertIsNotNone(option)
        self.assertIn(
            "target_compile_definitions(${COMPONENT_LIB} PRIVATE M5AUTH_TEST_SCREEN_SNAPSHOT=1)",
            cmake,
        )
        self.assertIn("#ifndef M5AUTH_TEST_SCREEN_SNAPSHOT", app)
        self.assertIn("#define M5AUTH_TEST_SCREEN_SNAPSHOT 0", app)
        self.assertIn(
            "constexpr bool kTestScreenSnapshotEnabled = M5AUTH_TEST_SCREEN_SNAPSHOT == 1;",
            app,
        )

    def test_release_and_pages_builds_never_enable_test_snapshot(self) -> None:
        for workflow in (RELEASE_WORKFLOW, PAGES_WORKFLOW):
            text = workflow.read_text(encoding="utf-8")
            self.assertNotIn("M5AUTH_TEST_SCREEN_SNAPSHOT=ON", text)
            self.assertNotIn("M5AUTH_TEST_SCREEN_SNAPSHOT=1", text)

    def test_diagnostic_operation_is_preprocessor_guarded(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        diagnostic = 'diagnostics.screen_snapshot'
        self.assertIn(diagnostic, app)
        first = app.index(diagnostic)
        guard = app.rfind("#if M5AUTH_TEST_SCREEN_SNAPSHOT", 0, first)
        end = app.find("#endif", first)
        self.assertNotEqual(-1, guard)
        self.assertNotEqual(-1, end)
        self.assertLess(guard, first)
        self.assertGreater(end, first)

    def test_response_surface_contains_no_secret_bearing_json_keys(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        start = app.index("std::string screen_snapshot_response(")
        end = app.index("\n#endif", start)
        response = app[start:end].lower()
        for forbidden_key in (
            "device_id",
            "attempt_id",
            "credential",
            "issuer",
            "account",
            "display_name",
            "totp",
            "secret",
            "passphrase",
            "recovery_package",
            "vmk",
            "kek",
            "buk",
            "brk",
            "session_key",
            "wifi",
            "vault_id",
            "ciphertext",
            "generation",
        ):
            self.assertNotIn(f'\\"{forbidden_key}\\"', response)

    def test_diagnostics_add_no_efuse_or_unsolicited_logging_surface(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        cmake = APP_MAIN_CMAKE.read_text(encoding="utf-8")
        self.assertNotIn("efuse", app.lower())
        self.assertNotIn("efuse", cmake.lower())
        self.assertNotIn("ESP_LOG", app)
        self.assertNotIn("std::puts(", app)
        self.assertNotIn("std::printf(", app)


if __name__ == "__main__":
    unittest.main()
