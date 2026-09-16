from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SDKCONFIG = ROOT / "firmware" / "sdkconfig.defaults"
PARTITIONS = ROOT / "firmware" / "partitions.csv"
RELEASE_DEVICE_CPP = ROOT / "firmware" / "components" / "m5auth_device_sticks3" / "release_device.cpp"
CANONICAL_DEVICE_CPP = ROOT / "firmware" / "components" / "m5auth_device_sticks3" / "canonical_device.cpp"
CANONICAL_DEVICE_HPP = ROOT / "firmware" / "components" / "m5auth_device_sticks3" / "include" / "m5auth" / "device" / "sticks3" / "canonical_device.hpp"
APP_MAIN = ROOT / "firmware" / "main" / "app_main.cpp"
APP_MAIN_CMAKE = ROOT / "firmware" / "main" / "CMakeLists.txt"
CANONICAL_PROTOCOL = ROOT / "firmware" / "components" / "m5auth_provisioning" / "canonical_protocol_v2.cpp"
REGISTRATION_CPP = ROOT / "firmware" / "components" / "m5auth_registration" / "registration.cpp"
VAULT_PERSISTENCE_CPP = ROOT / "firmware" / "components" / "m5auth_vault_runtime" / "nvs_persistence.cpp"
VAULT_RUNTIME_CPP = ROOT / "firmware" / "components" / "m5auth_vault_runtime" / "runtime.cpp"


def parse_partition_table() -> dict[str, tuple[str, str, int, int]]:
    entries: dict[str, tuple[str, str, int, int]] = {}
    for raw_line in PARTITIONS.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = [field.strip() for field in line.split(",")]
        if len(fields) < 5:
            raise AssertionError(f"invalid partition row: {raw_line}")
        name, partition_type, subtype, offset_text, size_text = fields[:5]
        entries[name] = (
            partition_type,
            subtype,
            int(offset_text, 0),
            int(size_text, 0),
        )
    return entries


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
        startup = RELEASE_DEVICE_CPP.read_text(encoding="utf-8")
        self.assertRegex(text, r"kReadableTextSize\s*=\s*2;")
        self.assertRegex(text, r"kOtpTextSize\s*=\s*4;")
        self.assertNotIn("kCompactTextSize", text)
        self.assertNotRegex(text, r"setTextSize\(\s*1\s*\)")
        self.assertIn("M5.Display.setTextWrap(false);", text)
        self.assertIn("M5.Display.setTextSize(kOtpTextSize);", text)
        self.assertIn("M5.Display.setTextSize(kReadableTextSize);", text)
        self.assertIn('draw_line("M5Authenticator", kHeaderY);', text)
        self.assertNotIn('"M5 Authenticator"', text)
        self.assertIn('M5.Display.println("M5Authenticator");', startup)
        self.assertNotIn('"M5 Authenticator"', startup)
        self.assertIn("M5.Display.setTextSize(2);", startup)

    def test_issue_139_single_click_hides_active_otp_before_next_navigation(self) -> None:
        text = CANONICAL_DEVICE_CPP.read_text(encoding="utf-8")
        start = text.index("else if (M5.BtnA.wasSingleClicked())")
        end = text.index("dirty = true;", start)
        block = text[start:end]
        self.assertIn("if (reveal_active_)", block)
        self.assertIn("hide_reveal();", block)
        self.assertIn("select_next();", block)
        self.assertLess(block.index("hide_reveal();"), block.index("select_next();"))

    def test_issue_139_hold_double_single_precedence_is_preserved(self) -> None:
        text = CANONICAL_DEVICE_CPP.read_text(encoding="utf-8")
        hold = text.index("if (M5.BtnA.wasHold())")
        double = text.index("else if (M5.BtnA.wasDoubleClicked())")
        single = text.index("else if (M5.BtnA.wasSingleClicked())")
        self.assertLess(hold, double)
        self.assertLess(double, single)
        self.assertIn("reveal_selected(now_ms);", text[hold:double])
        self.assertIn("select_previous();", text[double:single])
        self.assertIn("kOtpRevealDurationMs = 10'000;", text)

    def test_issue_139_long_label_scroll_is_repeating_transient_and_fit_aware(self) -> None:
        cpp = CANONICAL_DEVICE_CPP.read_text(encoding="utf-8")
        hpp = CANONICAL_DEVICE_HPP.read_text(encoding="utf-8")
        self.assertIn("kLabelScrollDelayMs = 2'000;", cpp)
        self.assertIn("kLabelScrollEndDelayMs = 2'000;", cpp)
        self.assertIn("label_scroll::cycle_offset_px(", cpp)
        self.assertIn("M5.Display.textWidth(label.c_str())", cpp)
        self.assertIn("label_width <= viewport_width", cpp)
        self.assertIn("label_scroll_epoch_ms_", hpp)
        self.assertIn("label_scroll_offset_px_", hpp)
        self.assertNotIn("label_scroll_text_", hpp)
        self.assertGreaterEqual(cpp.count("reset_label_scroll("), 5)
        self.assertIn("label_scroll::on_screen_hidden_changed(", cpp)

    def test_issue_139_scroll_only_tick_does_not_clear_whole_screen(self) -> None:
        text = CANONICAL_DEVICE_CPP.read_text(encoding="utf-8")
        self.assertIn("M5Canvas* account_label_canvas()", text)
        self.assertIn("canvas.createSprite(", text)
        self.assertIn("canvas->pushSprite(&M5.Display, 0, kAccountLabelY);", text)
        self.assertIn("canvas->clear(0x0000);", text)
        self.assertIn("label_scroll_changed = update_label_scroll(now_ms);", text)
        self.assertIn("else if (label_scroll_changed)", text)
        self.assertIn("render_account_label();", text)
        self.assertNotIn("dirty = update_label_scroll(now_ms) || dirty;", text)
        scroll_branch = text[text.index("else if (label_scroll_changed)") :]
        scroll_branch = scroll_branch[: scroll_branch.index("vTaskDelay(kUiPollInterval)")]
        self.assertNotIn("M5.Display.clear();", scroll_branch)
        self.assertNotIn("render();", scroll_branch)

    def test_issue_139_otp_spacing_and_readable_hint_contract(self) -> None:
        text = CANONICAL_DEVICE_CPP.read_text(encoding="utf-8")
        self.assertIn("constexpr int kOtpY = 101;", text)
        self.assertIn("kOtpDigitGapPx = 3;", text)
        self.assertIn("const int group_gap = digit_width / 2;", text)
        self.assertIn("if (index == 2)", text)
        self.assertIn("M5.Display.print(otp[index]);", text)
        self.assertIn('draw_line("click: 1x next", kHelpFirstY);', text)
        self.assertIn('draw_line("2x prev / hold OTP", kHelpSecondY);', text)
        self.assertNotIn('"1x next / 2x prev / hold OTP"', text)
        self.assertNotIn('"Click: next"', text)
        self.assertNotIn('"2x: previous"', text)
        self.assertNotIn('"Hold: reveal OTP"', text)

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
        self.assertIn('draw_line("ERASE DEVICE DATA"', ui)

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

    def test_usb_serial_fragments_are_buffered_until_newline_and_wiped_on_disconnect(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")

        self.assertIn("std::size_t buffered_input = 0;", app)
        self.assertIn("bool discard_oversized_input = false;", app)
        self.assertIn("input.data() + buffered_input", app)
        self.assertIn("input.size() - buffered_input", app)
        self.assertIn("buffered_input += std::strlen(input.data() + buffered_input);", app)
        self.assertIn("buffered_input > 0 && input[buffered_input - 1] == '\\n'", app)
        self.assertIn("USB Serial/JTAG VFS reads are non-blocking", app)
        self.assertIn("discard_oversized_input = true;", app)
        self.assertRegex(
            app,
            r"if \(!usb_serial_jtag_is_connected\(\)\) \{\s*"
            r"teardown_transport_session\(protocol\);\s*"
            r"m5auth::vault_runtime::secure_zero\(input\.data\(\), input\.size\(\)\);\s*"
            r"buffered_input = 0;\s*\}",
        )
        self.assertNotIn("discard_line_remainder", app)

    def test_canonical_presence_requires_neutral_and_quarantines_authorizing_gesture(self) -> None:
        text = CANONICAL_DEVICE_CPP.read_text(encoding="utf-8")
        self.assertIn("presence_.observe_button_state(M5.BtnA.isPressed());", text)
        self.assertIn("presence_gesture_quarantine_.begin(now_ms, M5.BtnA.getHoldThresh());", text)
        self.assertIn("M5.BtnA.wasDecideClickCount()", text)
        self.assertIn("!presence_gesture_quarantine_.active()", text)

    def test_issue_107_normal_update_preserves_registration_and_vault_partitions(self) -> None:
        partition_text = PARTITIONS.read_text(encoding="utf-8")
        sdkconfig = SDKCONFIG.read_text(encoding="utf-8")
        entries = parse_partition_table()

        self.assertIn("# NORMAL_UPDATE_PRESERVE: nvs,auth_nvs", partition_text)
        self.assertIn("CONFIG_PARTITION_TABLE_CUSTOM=y", sdkconfig)
        self.assertIn('CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"', sdkconfig)
        self.assertEqual(("data", "nvs", 0x9000, 0x6000), entries["nvs"])
        self.assertEqual(("data", "nvs", 0x7D0000, 0x30000), entries["auth_nvs"])

        for persistent_name in ("nvs", "auth_nvs"):
            _, _, persistent_start, persistent_size = entries[persistent_name]
            persistent_end = persistent_start + persistent_size
            for app_name in ("ota_0", "ota_1"):
                _, _, app_start, app_size = entries[app_name]
                app_end = app_start + app_size
                self.assertTrue(
                    app_end <= persistent_start or persistent_end <= app_start,
                    f"{app_name} overlaps persistent partition {persistent_name}",
                )

    def test_issue_107_registration_identity_stays_in_ordinary_nvs(self) -> None:
        registration = REGISTRATION_CPP.read_text(encoding="utf-8")

        self.assertIn('constexpr char kNamespace[] = "m5auth_reg2";', registration)
        self.assertIn("const esp_err_t nvs_status = nvs_flash_init();", registration)
        self.assertIn("nvs_open(kNamespace, mode, handle)", registration)
        self.assertIn("separate from the dedicated auth_nvs encrypted-Vault replica", registration)
        self.assertNotIn("nvs_open_from_partition", registration)
        self.assertNotIn("nvs_flash_init_partition", registration)

    def test_issue_107_canonical_vault_stays_in_auth_nvs(self) -> None:
        persistence = VAULT_PERSISTENCE_CPP.read_text(encoding="utf-8")

        self.assertIn('constexpr char kPartitionLabel[] = "auth_nvs";', persistence)
        self.assertIn("nvs_flash_init_partition(kPartitionLabel)", persistence)
        self.assertIn("nvs_open_from_partition(", persistence)
        self.assertIn("kPartitionLabel, kNamespace, mode", persistence)

    def test_issue_107_reboot_with_persisted_vault_starts_locked_without_vmk(self) -> None:
        runtime = VAULT_RUNTIME_CPP.read_text(encoding="utf-8")
        start = runtime.index("Status Runtime::initialize()")
        end = runtime.index("\nStatus Runtime::reload_after_persistence()", start)
        initialize = runtime[start:end]
        clear_start = runtime.index("void Runtime::clear_unlock_session_state()")
        clear_end = runtime.index("\nvoid Runtime::begin_unlock_session(", clear_start)
        clear = runtime[clear_start:clear_end]

        self.assertIn("clear_unlock_session_state();", initialize)
        self.assertIn("wipe_vmk();", clear)
        self.assertIn("if (!snapshot.has_vault) return Status::kUnprovisioned;", initialize)
        self.assertIn("has_vault_ = true;", initialize)
        self.assertIn("state_ = State::kLocked;", initialize)
        self.assertNotIn("State::kUnlocked", initialize)
        self.assertLess(initialize.index("has_vault_ = true;"), initialize.index("state_ = State::kLocked;"))

    def test_issue_86_timing_diagnostics_are_compiled_but_runtime_gated_and_default_off(self) -> None:
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
        self.assertNotIn("nvs_flash", cmake)
        self.assertIn("#define M5AUTH_TIMING_DIAGNOSTICS 0", app)
        self.assertIn("constexpr bool kTimingDiagnosticsEnabled = M5AUTH_TIMING_DIAGNOSTICS == 1;", app)
        self.assertIn("is_timing_diagnostics_query(request)", app)
        self.assertIn("diagnostics.timing", app)
        self.assertIn("session.begin", app)
        self.assertIn("session.authorize", app)
        self.assertIn("session.status", app)
        self.assertIn("session.complete", app)
        self.assertIn("vault.install", app)
        self.assertIn("hello", app)
        self.assertIn("session_begin", app)
        self.assertIn("session_authorize", app)
        self.assertIn("session_status", app)
        self.assertIn("last_us", app)
        self.assertIn("max_us", app)
        self.assertIn("tx_write", app)
        self.assertIn("fwrite_ok", app)
        self.assertIn("newline_ok", app)
        self.assertIn("fflush_ok", app)
        self.assertIn("ferror", app)
        self.assertIn("reset_reason", app)
        self.assertNotIn("ESP_LOG", app)
        self.assertNotIn("timing_diagnostics_response(request", app)

    def test_issue_86_response_write_diagnostics_do_not_overwrite_themselves(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")

        self.assertIn("const std::size_t fwrite_bytes = std::fwrite", app)
        self.assertIn("frame.push_back('\\n')", app)
        self.assertNotIn("const int newline_result = std::fputc", app)
        self.assertIn("const int fflush_result = std::fflush(stdout);", app)
        self.assertIn("const int ferror_value = std::ferror(stdout);", app)
        self.assertIn("write_response(response, timing_operation);", app)
        self.assertIn("write_response(timing_diagnostics_response());", app)
        self.assertIn(
            "const bool measure = kTimingDiagnosticsEnabled && operation != TimingOperation::kNone;",
            app,
        )
        self.assertIn('case TimingOperation::kSessionStatus: return "session.status";', app)

    def test_issue_86_response_writer_drains_usb_vfs_after_stdio_flush(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        start = app.index("void write_response(")
        end = app.index("\nstd::string timing_diagnostics_response()", start)
        writer = app[start:end]

        self.assertIn("#include <unistd.h>", app)
        self.assertEqual(1, writer.count("::fsync(STDOUT_FILENO)"))
        self.assertIn("::flockfile(stdout)", writer)
        self.assertIn("std::fwrite(frame.data(), 1, frame.size(), stdout)", writer)
        self.assertNotIn("std::fputc", writer)
        self.assertIn("::funlockfile(stdout)", writer)
        self.assertLess(writer.index("::flockfile(stdout)"), writer.index("std::fwrite("))
        self.assertLess(writer.index("std::fwrite("), writer.index("std::fflush(stdout)"))
        self.assertLess(writer.index("std::fflush(stdout)"), writer.index("::fsync(STDOUT_FILENO)"))
        self.assertLess(writer.index("::fsync(STDOUT_FILENO)"), writer.index("std::ferror(stdout)"))
        self.assertLess(writer.index("std::ferror(stdout)"), writer.index("::funlockfile(stdout)"))

    def test_issue_86_timing_snapshot_uses_rtc_noinit_not_flash(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")

        self.assertIn("RTC_NOINIT_ATTR RtcTimingDiagnostics g_rtc_timing_diagnostics;", app)
        self.assertIn("persist_timing_diagnostics_to_rtc();", app)
        self.assertIn("initialize_timing_diagnostics_persistence();", app)
        self.assertIn("kTimingRtcMagic", app)
        self.assertIn("M5AUTH_BUILD_COMMIT", app)
        self.assertIn("std::uint64_t values[27];", app)
        self.assertNotIn("nvs_open", app)
        self.assertNotIn("nvs_set_blob", app)
        self.assertNotIn("nvs_commit", app)
        self.assertRegex(
            app,
            r"if \(timing_recorded\) \{\s*persist_timing_diagnostics_to_rtc\(\);\s*\}\s*\n\s*m5auth::vault_runtime::secure_zero",
        )
        self.assertNotIn("request.data()", app)


if __name__ == "__main__":
    unittest.main()