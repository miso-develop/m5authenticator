from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_MAIN = ROOT / "firmware/main/app_main.cpp"
TRANSPORT_CPP = ROOT / "firmware/main/usb_protocol_transport.cpp"
DEVICE_HEADER = ROOT / "firmware/components/m5auth_device_sticks3/include/m5auth/device/sticks3/canonical_device.hpp"
DEVICE_CPP = ROOT / "firmware/components/m5auth_device_sticks3/canonical_device.cpp"


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
    def test_snapshot_type_is_allowlist_only_and_compile_gated(self) -> None:
        header = DEVICE_HEADER.read_text(encoding="utf-8")
        snapshot = extract_braced_block(header, "struct ScreenSnapshot")
        for field in (
            "vault_runtime::State runtime_state",
            "time::Readiness trusted_time_readiness",
            "PresenceView presence",
            "ScreenMode screen_mode",
        ):
            self.assertIn(field, snapshot)
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

        method = "bool screen_snapshot(ScreenSnapshot* output) const;"
        method_index = header.index(method)
        self.assertLess(header.rfind("#if M5AUTH_TEST_SCREEN_SNAPSHOT", 0, method_index), method_index)
        self.assertGreater(header.find("#endif", method_index), method_index)
        self.assertIn("ScreenSnapshot last_rendered_snapshot_{};", header)
        self.assertIn("bool rendered_snapshot_ready_{false};", header)

    def test_default_cache_cannot_be_reported_before_first_render(self) -> None:
        ui = DEVICE_CPP.read_text(encoding="utf-8")
        accessor = extract_braced_block(
            ui,
            "bool CanonicalUiController::screen_snapshot(ScreenSnapshot* output) const",
        )
        self.assertIn("if (output == nullptr) return false;", accessor)
        self.assertIn("std::lock_guard<std::mutex> view(view_mutex_);", accessor)
        self.assertIn("if (!rendered_snapshot_ready_) return false;", accessor)
        self.assertIn("*output = last_rendered_snapshot_;", accessor)
        self.assertIn("return true;", accessor)
        for forbidden in (
            "time_service_",
            "presence_",
            "runtime_state_",
            "storage_error_",
            "vault_visible_",
            "credentials_",
            "reveal_active_",
            "revealed_code_",
            "runtime_",
            "generator_",
        ):
            self.assertNotIn(forbidden, accessor)

    def test_only_completed_render_marks_snapshot_ready(self) -> None:
        ui = DEVICE_CPP.read_text(encoding="utf-8")
        render = extract_braced_block(ui, "void CanonicalUiController::render()")
        source_without_render = ui.replace(render, "")
        self.assertNotIn("rendered_snapshot_ready_ = true;", source_without_render)

        self.assertEqual(1, render.count("time_service_.status()"))
        self.assertEqual(1, render.count("presence_.view()"))
        self.assertIn("const time::Snapshot time_status = time_service_.status();", render)
        self.assertIn("const PresenceView presence = presence_.view();", render)
        self.assertIn("rendered_snapshot.trusted_time_readiness = time_status.readiness;", render)
        self.assertIn("rendered_snapshot.presence = presence;", render)

        snapshot_commit = "last_rendered_snapshot_ = rendered_snapshot;"
        ready_commit = "rendered_snapshot_ready_ = true;"
        self.assertEqual(1, render.count(snapshot_commit))
        self.assertEqual(1, render.count(ready_commit))
        self.assertGreater(render.index(snapshot_commit), render.rindex("M5.Display."))
        self.assertGreater(render.index(ready_commit), render.index(snapshot_commit))

        run = extract_braced_block(ui, "void CanonicalUiController::run()")
        security_clear = extract_braced_block(
            ui,
            "void CanonicalUiController::security_boundary_clear()",
        )
        self.assertIn("std::lock_guard<std::mutex> view(view_mutex_);", run)
        self.assertIn("if (dirty) {", run)
        self.assertIn("render();", run)
        self.assertIn("else if (label_scroll_changed)", run)
        scroll_start = run.index("else if (label_scroll_changed)")
        scroll_end = run.index("vTaskDelay(kUiPollInterval)", scroll_start)
        scroll_branch = run[scroll_start:scroll_end]
        self.assertIn("render_account_label();", scroll_branch)
        self.assertNotIn("render();", scroll_branch)
        self.assertNotIn("rendered_snapshot_ready_", scroll_branch)
        self.assertIn("std::lock_guard<std::mutex> view(view_mutex_);", security_clear)
        self.assertIn("render();", security_clear)

    def test_ui_task_failure_or_not_started_leaves_snapshot_not_ready(self) -> None:
        header = DEVICE_HEADER.read_text(encoding="utf-8")
        ui = DEVICE_CPP.read_text(encoding="utf-8")
        start = extract_braced_block(ui, "bool CanonicalUiController::start()")
        self.assertIn("bool rendered_snapshot_ready_{false};", header)
        self.assertNotIn("rendered_snapshot_ready_", start)
        self.assertIn("== pdPASS", start)

    def test_diagnostic_parser_is_strict_and_dynamic_id_based(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        parser = extract_braced_block(
            app,
            "ScreenSnapshotRequestParse parse_screen_snapshot_request(std::string_view line)",
        )
        self.assertIn("cJSON_ParseWithLengthOpts", parser)
        self.assertIn("kScreenSnapshotOperation", parser)
        self.assertIn("seen_v", parser)
        self.assertIn("seen_id", parser)
        self.assertIn("seen_op", parser)
        self.assertIn("seen_params", parser)
        self.assertIn("if (seen_v)", parser)
        self.assertIn("if (seen_id)", parser)
        self.assertIn("if (seen_op)", parser)
        self.assertIn("if (seen_params)", parser)
        self.assertIn("child->child != nullptr", parser)
        self.assertIn("valid = false;", parser)
        self.assertIn("read_nonnegative_json_int", parser)
        self.assertIn("request_id_valid ? request_id : 0", parser)
        self.assertNotIn('"id":9002', parser)
        self.assertIn("raw_intent_hint", parser)
        self.assertIn("kInvalidDiagnostic", parser)

    def test_request_id_is_echoed_for_success_and_not_ready_error(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        success = extract_braced_block(app, "std::string screen_snapshot_response(")
        error = extract_braced_block(app, "std::string screen_snapshot_error_response(")
        self.assertIn('"{\\\"v\\\":2,\\\"id\\\":%d,', success)
        self.assertIn("request_id,", success)
        self.assertIn('"{\\\"v\\\":2,\\\"id\\\":%d,', error)
        self.assertIn("request_id,", error)
        self.assertIn('"snapshot_not_ready"', app)

    def test_dispatch_fails_closed_before_first_render_and_is_read_only(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        marker = "const ScreenSnapshotRequestParse snapshot_request = parse_screen_snapshot_request(request);"
        start = app.index(marker)
        end = app.index("const TimingOperation timing_operation", start)
        dispatch = app[start:end]
        self.assertIn("kInvalidDiagnostic", dispatch)
        self.assertIn('screen_snapshot_error_response(snapshot_request.id, "invalid_request")', dispatch)
        self.assertIn("if (!ui.screen_snapshot(&snapshot))", dispatch)
        self.assertIn('"snapshot_not_ready"', dispatch)
        self.assertIn("screen_snapshot_response(snapshot_request.id, snapshot)", dispatch)
        self.assertIn("write_response(response)", dispatch)
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

        oversized = app.index("if (length > m5auth::provisioning::kMaxCanonicalV2MessageBytes)")
        diagnostic = app.index(marker)
        protocol = app.index("protocol.handle_line(", diagnostic)
        self.assertLess(oversized, diagnostic)
        self.assertLess(diagnostic, protocol)

    def test_serializer_has_only_allowlisted_snapshot_fields(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        response = extract_braced_block(app, "std::string screen_snapshot_response(")
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
        for forbidden in (
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
            self.assertNotIn(f'\\"{forbidden}\\"', response.lower())

    def test_response_uses_protocol_owned_driver_writer(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        transport = TRANSPORT_CPP.read_text(encoding="utf-8")
        writer = extract_braced_block(app, "bool write_response(")
        self.assertIn("g_protocol_transport.write_frame(response)", writer)
        for forbidden in (
            "stdout",
            "std::fwrite",
            "std::fflush",
            "::fsync",
            "flockfile",
            "funlockfile",
        ):
            self.assertNotIn(forbidden, writer)
        self.assertIn("frame.push_back('\\n')", transport)
        self.assertIn("usb_serial_jtag_write_bytes", transport)
        self.assertIn("usb_serial_jtag_wait_tx_done", transport)


if __name__ == "__main__":
    unittest.main()
