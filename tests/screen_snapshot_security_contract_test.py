from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_MAIN = ROOT / "firmware/main/app_main.cpp"
FIRMWARE_CMAKE = ROOT / "firmware/CMakeLists.txt"
APP_MAIN_CMAKE = ROOT / "firmware/main/CMakeLists.txt"
DEVICE_CMAKE = ROOT / "firmware/components/m5auth_device_sticks3/CMakeLists.txt"
DEVICE_HEADER = ROOT / "firmware/components/m5auth_device_sticks3/include/m5auth/device/sticks3/canonical_device.hpp"
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"
PAGES_WORKFLOW = ROOT / ".github/workflows/pages.yml"


class ScreenSnapshotSecurityContractTest(unittest.TestCase):
    def test_compile_time_flag_is_root_default_off_and_reaches_both_components(self) -> None:
        root_cmake = FIRMWARE_CMAKE.read_text(encoding="utf-8")
        app_cmake = APP_MAIN_CMAKE.read_text(encoding="utf-8")
        device_cmake = DEVICE_CMAKE.read_text(encoding="utf-8")
        app = APP_MAIN.read_text(encoding="utf-8")
        header = DEVICE_HEADER.read_text(encoding="utf-8")

        option = re.search(
            r"option\(\s*M5AUTH_TEST_SCREEN_SNAPSHOT[\s\S]+?OFF\s*\)",
            root_cmake,
        )
        self.assertIsNotNone(option)
        for cmake in (app_cmake, device_cmake):
            self.assertIn("if(M5AUTH_TEST_SCREEN_SNAPSHOT)", cmake)
            self.assertIn(
                "target_compile_definitions(${COMPONENT_LIB} PRIVATE M5AUTH_TEST_SCREEN_SNAPSHOT=1)",
                cmake,
            )
        self.assertIn("#ifndef M5AUTH_TEST_SCREEN_SNAPSHOT", app)
        self.assertIn("#define M5AUTH_TEST_SCREEN_SNAPSHOT 0", app)
        self.assertIn("#ifndef M5AUTH_TEST_SCREEN_SNAPSHOT", header)
        self.assertIn("#define M5AUTH_TEST_SCREEN_SNAPSHOT 0", header)
        self.assertIn(
            "constexpr bool kTestScreenSnapshotEnabled = M5AUTH_TEST_SCREEN_SNAPSHOT == 1;",
            app,
        )

    def test_release_and_pages_builds_never_enable_test_snapshot(self) -> None:
        for workflow in (RELEASE_WORKFLOW, PAGES_WORKFLOW):
            text = workflow.read_text(encoding="utf-8")
            self.assertNotIn("M5AUTH_TEST_SCREEN_SNAPSHOT=ON", text)
            self.assertNotIn("M5AUTH_TEST_SCREEN_SNAPSHOT=1", text)

    def test_diagnostic_transport_and_device_api_are_preprocessor_guarded(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        header = DEVICE_HEADER.read_text(encoding="utf-8")

        diagnostic = 'diagnostics.screen_snapshot'
        self.assertIn(diagnostic, app)
        first = app.index(diagnostic)
        guard = app.rfind("#if M5AUTH_TEST_SCREEN_SNAPSHOT", 0, first)
        end = app.find("#endif", first)
        self.assertNotEqual(-1, guard)
        self.assertNotEqual(-1, end)
        self.assertLess(guard, first)
        self.assertGreater(end, first)

        for symbol in (
            "enum class ScreenMode",
            "struct ScreenSnapshot",
            "bool screen_snapshot(ScreenSnapshot* output) const;",
            "ScreenSnapshot last_rendered_snapshot_{};",
            "bool rendered_snapshot_ready_{false};",
        ):
            index = header.index(symbol)
            api_guard = header.rfind("#if M5AUTH_TEST_SCREEN_SNAPSHOT", 0, index)
            api_end = header.find("#endif", index)
            self.assertNotEqual(-1, api_guard)
            self.assertNotEqual(-1, api_end)
            self.assertLess(api_guard, index)
            self.assertGreater(api_end, index)

    def test_snapshot_structure_is_an_exact_allowlist(self) -> None:
        header = DEVICE_HEADER.read_text(encoding="utf-8")
        start = header.index("struct ScreenSnapshot {")
        end = header.index("\n};", start)
        fields = [
            line.strip()
            for line in header[start:end].splitlines()[1:]
            if line.strip() and not line.lstrip().startswith("//")
        ]
        self.assertEqual(
            [
                "vault_runtime::State runtime_state{vault_runtime::State::kUnprovisioned};",
                "time::Readiness trusted_time_readiness{time::Readiness::kNotSynced};",
                "PresenceView presence{};",
                "ScreenMode screen_mode{ScreenMode::kOpenWeb};",
            ],
            fields,
        )

    def test_response_surface_is_an_exact_json_key_allowlist(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        start = app.index("std::string screen_snapshot_response(")
        end = app.index("\n#endif", start)
        response = app[start:end].lower()
        success_keys = set(re.findall(r'\\\"([a-z_]+)\\\"\s*:', response))
        self.assertEqual(
            {
                "v",
                "id",
                "ok",
                "data",
                "runtime_state",
                "trusted_time_readiness",
                "presence",
                "active",
                "confirmed",
                "operation",
                "screen_mode",
            },
            success_keys,
        )
        self.assertIn('screen_snapshot_error_response(request_id, "internal_error")', response)
        self.assertNotIn('\\"id\\":9002', response)
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
        root_cmake = FIRMWARE_CMAKE.read_text(encoding="utf-8")
        app_cmake = APP_MAIN_CMAKE.read_text(encoding="utf-8")
        device_cmake = DEVICE_CMAKE.read_text(encoding="utf-8")
        self.assertNotIn("efuse", app.lower())
        self.assertNotIn("efuse", root_cmake.lower())
        self.assertNotIn("efuse", app_cmake.lower())
        self.assertNotIn("efuse", device_cmake.lower())
        self.assertNotIn("ESP_LOG", app)
        self.assertNotIn("std::puts(", app)
        self.assertNotIn("std::printf(", app)


if __name__ == "__main__":
    unittest.main()
