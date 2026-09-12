from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SDKCONFIG = ROOT / "firmware" / "sdkconfig.defaults"
DEVICE_CPP = (
    ROOT
    / "firmware"
    / "components"
    / "m5auth_device_sticks3"
    / "device.cpp"
)
CANONICAL_DEVICE_CPP = (
    ROOT
    / "firmware"
    / "components"
    / "m5auth_device_sticks3"
    / "canonical_device.cpp"
)
APP_MAIN = ROOT / "firmware" / "main" / "app_main.cpp"
CANONICAL_PROTOCOL = (
    ROOT
    / "firmware"
    / "components"
    / "m5auth_provisioning"
    / "canonical_protocol_v2.cpp"
)


class StickS3RuntimeContractTests(unittest.TestCase):
    def test_main_task_stack_is_pinned_to_8192(self) -> None:
        text = SDKCONFIG.read_text(encoding="utf-8")
        matches = re.findall(r"^CONFIG_ESP_MAIN_TASK_STACK_SIZE=(\d+)$", text, re.MULTILINE)
        self.assertEqual(["8192"], matches)

    def test_unused_audio_is_disabled_before_and_after_m5_begin(self) -> None:
        text = DEVICE_CPP.read_text(encoding="utf-8")
        speaker_config = text.index("config.internal_spk = false;")
        mic_config = text.index("config.internal_mic = false;")
        begin = text.index("M5.begin(config);")
        speaker_end = text.index("M5.Speaker.end();")

        self.assertLess(speaker_config, begin)
        self.assertLess(mic_config, begin)
        self.assertLess(begin, speaker_end)

    def test_display_scale_contract_is_readable(self) -> None:
        text = DEVICE_CPP.read_text(encoding="utf-8")
        self.assertRegex(text, r"kReadableTextSize\s*=\s*2;")
        self.assertRegex(text, r"kOtpTextSize\s*=\s*4;")
        self.assertIn("M5.Display.setTextWrap(false);", text)
        self.assertIn("M5.Display.setTextSize(kOtpTextSize);", text)
        self.assertIn("M5.Display.setTextSize(kReadableTextSize);", text)

    def test_transport_teardown_preserves_active_runtime_but_explicit_lock_wipes_it(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        protocol = CANONICAL_PROTOCOL.read_text(encoding="utf-8")

        teardown = re.search(
            r"void teardown_transport_session\([^}]+\}\n",
            app,
            re.MULTILINE,
        )
        self.assertIsNotNone(teardown)
        self.assertIn("protocol.disconnect();", teardown.group(0))
        self.assertNotIn("runtime.lock", teardown.group(0))
        self.assertNotIn("runtime_.lock", teardown.group(0))

        self.assertIn('operation == "device.lock"', protocol)
        self.assertIn("status = runtime_.lock();", protocol)

    def test_canonical_presence_requires_neutral_and_quarantines_authorizing_gesture(self) -> None:
        text = CANONICAL_DEVICE_CPP.read_text(encoding="utf-8")
        self.assertIn("presence_.observe_button_state(M5.BtnA.isPressed());", text)
        self.assertIn("presence_gesture_quarantine_.begin(now_ms, M5.BtnA.getHoldThresh());", text)
        self.assertIn("M5.BtnA.wasDecideClickCount()", text)
        self.assertIn("!presence_gesture_quarantine_.active()", text)


if __name__ == "__main__":
    unittest.main()
