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

    def test_snapshot_reads_ui_state_under_view_lock_without_mutation(self) -> None:
        ui = DEVICE_CPP.read_text(encoding="utf-8")
        snapshot = extract_braced_block(
            ui,
            "ScreenSnapshot CanonicalUiController::screen_snapshot() const",
        )
        self.assertIn("std::lock_guard<std::mutex> view(view_mutex_);", snapshot)
        self.assertIn("time_service_.status().readiness", snapshot)
        self.assertIn("presence_.view()", snapshot)
        self.assertIn("runtime_state_", snapshot)
        self.assertIn("reveal_active_", snapshot)
        for forbidden in (
            "revealed_code_",
            "display_label(",
            ".issuer",
            ".account",
            ".display_name",
            "credential_id",
            "runtime_.",
            "generator_.",
            "hide_reveal(",
            "clear_private_view(",
            "refresh_credentials(",
            "persist_selection(",
            "select_next(",
            "select_previous(",
            "reveal_selected(",
            "cancel_presence(",
            "button_pressed(",
            "time_service_.sync",
        ):
            self.assertNotIn(forbidden, snapshot)

        security_clear = extract_braced_block(
            ui,
            "void CanonicalUiController::security_boundary_clear()",
        )
        self.assertIn("std::lock_guard<std::mutex> view(view_mutex_);", security_clear)

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
