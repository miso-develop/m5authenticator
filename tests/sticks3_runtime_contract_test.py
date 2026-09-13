from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SDKCONFIG = ROOT / "firmware" / "sdkconfig.defaults"
RELEASE_DEVICE_CPP = ROOT / "firmware" / "components" / "m5auth_device_sticks3" / "release_device.cpp"
CANONICAL_DEVICE_CPP = ROOT / "firmware" / "components" / "m5auth_device_sticks3" / "canonical_device.cpp"
APP_MAIN = ROOT / "firmware" / "main" / "app_main.cpp"
APP_MAIN_CMAKE = ROOT / "firmware" / "main" / "CMakeLists.txt"
CANONICAL_PROTOCOL = ROOT / "firmware" / "components" / "m5auth_provisioning" / "canonical_protocol_v2.cpp"


class StickS3RuntimeContractTests(unittest.TestCase):
    def test_main_task_stack_is_pinned_to_8192(self) -> None:
        text = SDKCONFIG.read_text(encoding="utf-8")
        matches = re.findall(r"^CONFIG_ESP_MAIN_TASK_STACK_SIZE=(\d+)$", text, re.MULTILINE)
        self.assertEqual(["8192"], matches)

    def test_unused_audio_is_disabled_before_and_after_m5_begin(self) -> None:
        text = RELEASE_DEVICE_CPP.read_text(encoding="utf-8")
        speaker_config = text.index("config.internal_spk = false;")
        mic_config = text.index("config.internal_mic = false;")
        begin = text.index("M5.begin(config);")
        speaker_end = text.index("M5.Speaker.end();")

        self.assertLess(speaker_config, begin)
        self.assertLess(mic_config, begin)
        self.assertLess(begin, speaker_end)

    def test_display_scale_contract_is_readable(self) -> None:
        text = CANONICAL_DEVICE_CPP.read_text(encoding="utf-8")
        self.assertRegex(text, r"kReadableTextSize\s*=\s*2;")
        self.assertRegex(text, r"kOtpTextSize\s*=\s*4;")
        self.assertIn("M5.Display.setTextWrap(false);", text)
        self.assertIn("M5.Display.setTextSize(kOtpTextSize);", text)
        self.assertIn("M5.Display.setTextSize(kReadableTextSize);", text)

    def test_transport_teardown_preserves_active_runtime_but_explicit_lock_wipes_it(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        protocol = CANONICAL_PROTOCOL.read_text(encoding="utf-8")

        teardown = re.search(r"void teardown_transport_session\([^}]+\}\n", app, re.MULTILINE)
        self.assertIsNotNone(teardown)
        self.assertIn("protocol.disconnect();", teardown.group(0))
        self.assertNotIn("runtime.lock", teardown.group(0))
        self.assertNotIn("runtime_.lock", teardown.group(0))

        self.assertIn('operation == "device.lock"', protocol)
        self.assertIn("time_service_.with_secret_boundary", protocol)
        self.assertIn("result = runtime_.lock();", protocol)
        self.assertIn("notify_security_boundary();", protocol)

    def test_security_boundary_wipes_ui_cache_before_protocol_returns(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        protocol = CANONICAL_PROTOCOL.read_text(encoding="utf-8")
        ui = CANONICAL_DEVICE_CPP.read_text(encoding="utf-8")
        self.assertIn("[&ui]() { ui.security_boundary_clear(); }", app)
        self.assertIn("void CanonicalUiController::security_boundary_clear()", ui)
        self.assertIn("(void)clear_private_view();", ui)
        self.assertIn("render();", ui)
        self.assertIn("notify_security_boundary();", protocol)

    def test_recovery_factory_reset_uses_destructive_presence(self) -> None:
        protocol = CANONICAL_PROTOCOL.read_text(encoding="utf-8")
        ui = CANONICAL_DEVICE_CPP.read_text(encoding="utf-8")
        self.assertIn("session::PresenceOperation::kFactoryReset", protocol)
        self.assertIn('M5.Display.println("ERASE DEVICE DATA");', ui)

    def test_idle_usb_runs_housekeeping_without_becoming_disconnect(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        self.assertIn("protocol.housekeeping(monotonic_ms());", app)
        self.assertIn("usb_serial_jtag_is_connected()", app)
        idle_branch = re.search(
            r"if \(std::fgets\([\s\S]+?== nullptr\) \{([\s\S]+?)continue;\n        \}",
            app,
        )
        self.assertIsNotNone(idle_branch)
        self.assertIn("if (!usb_serial_jtag_is_connected())", idle_branch.group(1))
        self.assertIn("teardown_transport_session(protocol);", idle_branch.group(1))

    def test_canonical_presence_requires_neutral_and_quarantines_authorizing_gesture(self) -> None:
        text = CANONICAL_DEVICE_CPP.read_text(encoding="utf-8")
        self.assertIn("presence_.observe_button_state(M5.BtnA.isPressed());", text)
        self.assertIn("presence_gesture_quarantine_.begin(now_ms, M5.BtnA.getHoldThresh());", text)
        self.assertIn("M5.BtnA.wasDecideClickCount()", text)
        self.assertIn("!presence_gesture_quarantine_.active()", text)

    def test_issue_86_timing_diagnostics_are_compile_gated_and_default_off(self) -> None:
        cmake = APP_MAIN_CMAKE.read_text(encoding="utf-8")
        app = APP_MAIN.read_text(encoding="utf-8")

        option = re.search(
            r"option\(\s*M5AUTH_TIMING_DIAGNOSTICS[\s\S]+?OFF\s*\)",
            cmake,
        )
        self.assertIsNotNone(option)
        self.assertIn(
            "target_compile_definitions(${COMPONENT_LIB} PRIVATE M5AUTH_TIMING_DIAGNOSTICS=1)",
            cmake,
        )
        self.assertIn("#ifdef M5AUTH_TIMING_DIAGNOSTICS", app)
        self.assertIn('"op":"diagnostics.timing"', app)
        self.assertIn('"op":"session.complete"', app)
        self.assertIn('"op":"vault.install"', app)
        self.assertIn('"op":"hello"', app)
        self.assertIn('"last_us"', app)
        self.assertIn('"max_us"', app)
        self.assertNotIn("ESP_LOG", app)
        self.assertNotIn("timing_diagnostics_response(request", app)


if __name__ == "__main__":
    unittest.main()
