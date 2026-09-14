from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_MAIN = ROOT / "firmware/main/app_main.cpp"
DEVICE_HEADER = ROOT / "firmware/components/m5auth_device_sticks3/include/m5auth/device/sticks3/canonical_device.hpp"
DEVICE_CPP = ROOT / "firmware/components/m5auth_device_sticks3/canonical_device.cpp"

EXPECTED_REQUEST = '{"v":2,"id":9002,"op":"diagnostics.screen_snapshot","params":{}}'


def extract_braced_block(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated C++ block for {signature}")


class ScreenSnapshotRuntimeContractTest(unittest.TestCase):
    def test_request_is_exact_bounded_protocol2_line(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        parsed = json.loads(EXPECTED_REQUEST)
        self.assertEqual(
            parsed,
            {"v": 2, "id": 9002, "op": "diagnostics.screen_snapshot", "params": {}},
        )
        self.assertNotIn("\n", EXPECTED_REQUEST)
        self.assertIn(
            'constexpr std::string_view kScreenSnapshotRequest = R"({"v":2,"id":9002,"op":"diagnostics.screen_snapshot","params":{}})";',
            app,
        )
        matcher = extract_braced_block(app, "bool is_screen_snapshot_query(std::string_view line)")
        self.assertIn("kTestScreenSnapshotEnabled", matcher)
        self.assertIn("line == kScreenSnapshotRequest", matcher)
        self.assertNotIn(".find(", matcher)

        def matches(line: str, enabled: bool = True) -> bool:
            return enabled and line == EXPECTED_REQUEST

        self.assertTrue(matches(EXPECTED_REQUEST))
        self.assertFalse(matches(EXPECTED_REQUEST, enabled=False))
        for invalid in (
            "",
            "not-json",
            EXPECTED_REQUEST + "x",
            EXPECTED_REQUEST + "\n",
            '{"v":2,"id":9001,"op":"diagnostics.screen_snapshot","params":{}}',
            '{"v":2,"id":9002,"op":"diagnostics.screen_snapshotx","params":{}}',
            '{"v":2,"id":9002,"op":"diagnostics.screen_snapshot","params":{"x":1}}',
            '{"id":9002,"v":2,"op":"diagnostics.screen_snapshot","params":{}}',
            '{ "v": 2, "id": 9002, "op": "diagnostics.screen_snapshot", "params": {} }',
        ):
            self.assertFalse(matches(invalid), invalid)

    def test_snapshot_type_is_allowlist_only_and_has_no_secret_bearing_fields(self) -> None:
        header = DEVICE_HEADER.read_text(encoding="utf-8")
        snapshot = extract_braced_block(header, "struct ScreenSnapshot")
        self.assertIn("vault_runtime::State runtime_state", snapshot)
        self.assertIn("time::Readiness trusted_time_readiness", snapshot)
        self.assertIn("PresenceView presence", snapshot)
        self.assertIn("ScreenMode screen_mode", snapshot)
        for forbidden in (
            "std::string",
            "std::vector",
            "credential_id",
            "issuer",
            "account",
            "display_name",
            "device_id",
            "attempt_id",
            "secret",
            "passphrase",
            "ciphertext",
            "vmk",
            "kek",
            "buk",
            "brk",
            "wifi",
            "revealed_code",
        ):
            self.assertNotIn(forbidden, snapshot.lower())

    def test_snapshot_api_is_compile_gated_with_the_test_flag(self) -> None:
        header = DEVICE_HEADER.read_text(encoding="utf-8")
        self.assertIn("#if M5AUTH_TEST_SCREEN_SNAPSHOT\nenum class ScreenMode", header)
        method = "ScreenSnapshot screen_snapshot() const;"
        method_index = header.index(method)
        guard_index = header.rfind("#if M5AUTH_TEST_SCREEN_SNAPSHOT", 0, method_index)
        end_index = header.find("#endif", method_index)
        self.assertNotEqual(-1, guard_index)
        self.assertNotEqual(-1, end_index)
        self.assertLess(guard_index, method_index)
        self.assertGreater(end_index, method_index)
        cache_index = header.index("ScreenSnapshot last_rendered_snapshot_{};")
        cache_guard = header.rfind("#if M5AUTH_TEST_SCREEN_SNAPSHOT", 0, cache_index)
        cache_end = header.find("#endif", cache_index)
        self.assertLess(cache_guard, cache_index)
        self.assertGreater(cache_end, cache_index)

    def test_snapshot_returns_only_last_rendered_cache_under_view_lock(self) -> None:
        ui = DEVICE_CPP.read_text(encoding="utf-8")
        snapshot = extract_braced_block(
            ui,
            "ScreenSnapshot CanonicalUiController::screen_snapshot() const",
        )
        self.assertIn("std::lock_guard<std::mutex> view(view_mutex_);", snapshot)
        self.assertIn("return last_rendered_snapshot_;", snapshot)
        for forbidden in (
            "time_service_",
            "presence_",
            "runtime_state_",
            "storage_error_",
            "vault_visible_",
            "credentials_",
            "reveal_active_",
            "revealed_code_",
            "display_label(",
            "runtime_",
            "generator_",
        ):
            self.assertNotIn(forbidden, snapshot)

    def test_render_commits_snapshot_from_exact_state_used_for_lcd(self) -> None:
        ui = DEVICE_CPP.read_text(encoding="utf-8")
        render = extract_braced_block(ui, "void CanonicalUiController::render()")

        # External live state is captured once at the start of the render and
        # both the LCD path and the sanitized snapshot use those locals.
        self.assertEqual(1, render.count("time_service_.status()"))
        self.assertEqual(1, render.count("presence_.view()"))
        self.assertIn("const time::Snapshot time_status = time_service_.status();", render)
        self.assertIn("const PresenceView presence = presence_.view();", render)
        self.assertIn("rendered_snapshot.trusted_time_readiness = time_status.readiness;", render)
        self.assertIn("rendered_snapshot.presence = presence;", render)
        self.assertIn('readiness_text(time_status.readiness)', render)
        self.assertIn('presence_operation_text(presence.operation)', render)

        # Cache publication is after the LCD writes, so a reader serialized by
        # view_mutex_ sees either the prior completed render or the new one.
        commit = "last_rendered_snapshot_ = rendered_snapshot;"
        self.assertEqual(1, render.count(commit))
        self.assertGreater(render.index(commit), render.index('M5.Display.println("M5 Authenticator")'))
        self.assertGreater(render.index(commit), render.rindex("M5.Display."))

        # No secret-bearing display material is copied into the sanitized cache.
        snapshot_setup_end = render.index("M5.Display.clear();")
        snapshot_setup = render[:snapshot_setup_end]
        for forbidden in (
            "revealed_code_",
            "display_label(",
            ".issuer",
            ".account",
            ".display_name",
            "credential_id",
            "selected_index_",
            "reveal_deadline_ms_",
        ):
            self.assertNotIn(forbidden, snapshot_setup)

    def test_protocol_side_changes_cannot_publish_until_render_commit(self) -> None:
        ui = DEVICE_CPP.read_text(encoding="utf-8")
        snapshot = extract_braced_block(
            ui,
            "ScreenSnapshot CanonicalUiController::screen_snapshot() const",
        )
        render = extract_braced_block(ui, "void CanonicalUiController::render()")
        run = extract_braced_block(ui, "void CanonicalUiController::run()")
        security_clear = extract_braced_block(
            ui,
            "void CanonicalUiController::security_boundary_clear()",
        )

        # Diagnostic reads cannot observe protocol-side presence/time directly.
        self.assertNotIn("presence_.view()", snapshot)
        self.assertNotIn("time_service_.status()", snapshot)

        # The two paths that call render hold view_mutex_ for the whole render.
        self.assertIn("std::lock_guard<std::mutex> view(view_mutex_);", security_clear)
        self.assertIn("render();", security_clear)
        self.assertIn("std::lock_guard<std::mutex> view(view_mutex_);", run)
        self.assertIn("if (dirty) render();", run)
        self.assertIn("last_rendered_snapshot_ = rendered_snapshot;", render)

    def test_serializer_has_only_allowlisted_keys_and_coarse_modes(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        response = extract_braced_block(
            app,
            "std::string screen_snapshot_response(",
        )
        for key in (
            "runtime_state",
            "trusted_time_readiness",
            "presence",
            "active",
            "confirmed",
            "operation",
            "screen_mode",
        ):
            self.assertIn(f'\\"{key}\\"', response)

        for forbidden_key in (
            "device_id",
            "attempt_id",
            "totp",
            "credential",
            "issuer",
            "account",
            "display_name",
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
            "selected_index",
            "reveal_deadline",
        ):
            self.assertNotIn(f'\\"{forbidden_key}\\"', response.lower())

        self.assertIn('return "otp_revealed";', app)
        self.assertNotIn("revealed_code_", response)
        self.assertNotIn("display_label", response)
        self.assertNotIn("credentials_", response)
        self.assertNotIn("\\n", response)

    def test_dispatch_is_read_only_and_bypasses_session_protocol_state(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        dispatch = extract_braced_block(app, "if (is_screen_snapshot_query(request))")
        self.assertIn("const auto snapshot = ui.screen_snapshot();", dispatch)
        self.assertIn("screen_snapshot_response(snapshot)", dispatch)
        self.assertIn("m5auth::vault_runtime::secure_zero(input.data(), input.size());", dispatch)
        self.assertIn("buffered_input = 0;", dispatch)
        self.assertIn("write_response(", dispatch)
        self.assertIn("continue;", dispatch)

        for forbidden in (
            "protocol.handle_line",
            "session_handler",
            "coordinator",
            "runtime.",
            "registration.",
            "time_service.",
            "presence.",
            "vmk_sink",
            "security_boundary_clear",
        ):
            self.assertNotIn(forbidden, dispatch)

        diagnostic_index = app.index("if (is_screen_snapshot_query(request))")
        protocol_index = app.index("protocol.handle_line(", diagnostic_index)
        self.assertLess(diagnostic_index, protocol_index)
        self.assertGreater(
            diagnostic_index,
            app.index("if (length > m5auth::provisioning::kMaxCanonicalV2MessageBytes)"),
        )

    def test_response_uses_only_existing_one_line_fsync_writer(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        writer = extract_braced_block(app, "void write_response(")
        self.assertIn("std::fwrite(response.data(), 1, response.size(), stdout)", writer)
        self.assertIn("std::fputc('\\n', stdout)", writer)
        self.assertIn("std::fflush(stdout)", writer)
        self.assertIn("::fsync(STDOUT_FILENO)", writer)
        self.assertLess(writer.index("std::fwrite("), writer.index("std::fputc('\\n', stdout)"))
        self.assertLess(writer.index("std::fputc('\\n', stdout)"), writer.index("std::fflush(stdout)"))
        self.assertLess(writer.index("std::fflush(stdout)"), writer.index("::fsync(STDOUT_FILENO)"))

        without_writer = app.replace(writer, "")
        self.assertNotIn("stdout", without_writer)
        self.assertNotIn("std::puts(", without_writer)
        self.assertNotIn("std::printf(", without_writer)

    def test_flag_on_path_does_not_replace_normal_protocol_v2_dispatch(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        diagnostic_index = app.index("if (is_screen_snapshot_query(request))")
        timing_index = app.index("const TimingOperation timing_operation", diagnostic_index)
        protocol_index = app.index("protocol.handle_line(", timing_index)
        writer_index = app.index("write_response(response, timing_operation);", protocol_index)
        self.assertLess(diagnostic_index, timing_index)
        self.assertLess(timing_index, protocol_index)
        self.assertLess(protocol_index, writer_index)


if __name__ == "__main__":
    unittest.main()
