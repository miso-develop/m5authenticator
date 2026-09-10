from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeviceIdentityGuardTest(unittest.TestCase):
    def test_runtime_board_check_is_sticks3_specific(self) -> None:
        source = (ROOT / "firmware" / "components" / "m5auth_device_sticks3" / "hardware_identity.cpp").read_text(encoding="utf-8")
        self.assertIn("M5.getBoard() == m5::board_t::board_M5StickS3", source)
        self.assertIn("halt_unexpected_hardware", source)

    def test_guard_runs_before_storage_or_efuse_backend_construction(self) -> None:
        source = (ROOT / "firmware" / "main" / "app_main.cpp").read_text(encoding="utf-8")
        guard = source.index("is_expected_hardware()")
        halt = source.index("halt_unexpected_hardware()")
        production_backend = source.index("HmacEfuseSecurityBackend")
        store = source.index("storage::Store store")

        self.assertLess(guard, production_backend)
        self.assertLess(halt, production_backend)
        self.assertLess(guard, store)
        self.assertLess(halt, store)

    def test_main_task_stack_has_m5unified_initialization_headroom(self) -> None:
        defaults = (ROOT / "firmware" / "sdkconfig.defaults").read_text(encoding="utf-8")
        self.assertIn("CONFIG_ESP_MAIN_TASK_STACK_SIZE=8192", defaults)


class DeviceStartupContractTest(unittest.TestCase):
    def setUp(self) -> None:
        device_path = ROOT / "firmware" / "components" / "m5auth_device_sticks3" / "device.cpp"
        production_path = ROOT / "firmware" / "components" / "m5auth_device_sticks3" / "production_security.cpp"
        self.device_source = device_path.read_text(encoding="utf-8")
        self.production_source = production_path.read_text(encoding="utf-8")

    def test_unused_audio_path_is_disabled_at_startup(self) -> None:
        speaker_config = self.device_source.index("config.internal_spk = false;")
        microphone_config = self.device_source.index("config.internal_mic = false;")
        begin = self.device_source.index("M5.begin(config);")
        speaker_end = self.device_source.index("M5.Speaker.end();")

        self.assertLess(speaker_config, begin)
        self.assertLess(microphone_config, begin)
        self.assertLess(begin, speaker_end)

    def test_sticks3_text_uses_readable_scale(self) -> None:
        self.assertIn("constexpr std::uint8_t kReadableTextSize = 2;", self.device_source)
        self.assertIn("constexpr std::uint8_t kOtpTextSize = 4;", self.device_source)
        self.assertIn("constexpr std::uint8_t kReadableTextSize = 2;", self.production_source)
        self.assertNotIn("M5.Display.setTextSize(1)", self.device_source)
        self.assertNotIn("M5.Display.setTextSize(1)", self.production_source)

    def test_production_setup_keeps_safety_state_visible(self) -> None:
        self.assertIn('heading("PRODUCTION SETUP")', self.production_source)
        self.assertIn('M5.Display.println("eFuse unchanged")', self.production_source)
        self.assertIn('heading("IRREVERSIBLE EFUSE")', self.production_source)


if __name__ == "__main__":
    unittest.main()
