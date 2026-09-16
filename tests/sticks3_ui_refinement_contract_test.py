from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEVICE_CPP = ROOT / "firmware" / "components" / "m5auth_device_sticks3" / "canonical_device.cpp"
DEVICE_HPP = (
    ROOT
    / "firmware"
    / "components"
    / "m5auth_device_sticks3"
    / "include"
    / "m5auth"
    / "device"
    / "sticks3"
    / "canonical_device.hpp"
)


class StickS3UiRefinementContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cpp = DEVICE_CPP.read_text(encoding="utf-8")
        self.hpp = DEVICE_HPP.read_text(encoding="utf-8")

    def test_existing_reveal_timeout_remains_ten_seconds(self) -> None:
        self.assertRegex(self.cpp, r"kOtpRevealDurationMs\s*=\s*10'000;")
        self.assertIn("now_ms >= reveal_deadline_ms_", self.cpp)

    def test_single_click_hides_reveal_before_normal_next_navigation(self) -> None:
        gesture = re.search(
            r"else if \(M5\.BtnA\.wasSingleClicked\(\)\) \{([\s\S]+?)\n\s*\}",
            self.cpp,
        )
        self.assertIsNotNone(gesture)
        block = gesture.group(1)
        self.assertIn("if (reveal_active_)", block)
        self.assertIn("hide_reveal();", block)
        self.assertIn("select_next();", block)
        self.assertLess(block.index("hide_reveal();"), block.index("select_next();"))

    def test_double_click_and_hold_precedence_are_preserved(self) -> None:
        hold = self.cpp.index("if (M5.BtnA.wasHold())")
        double = self.cpp.index("else if (M5.BtnA.wasDoubleClicked())")
        single = self.cpp.index("else if (M5.BtnA.wasSingleClicked())")
        self.assertLess(hold, double)
        self.assertLess(double, single)
        self.assertIn("reveal_selected(now_ms);", self.cpp[hold:double])
        self.assertIn("select_previous();", self.cpp[double:single])

    def test_label_scroll_waits_before_moving_and_does_not_store_label_copy(self) -> None:
        self.assertRegex(self.cpp, r"kLabelScrollDelayMs\s*=\s*2'000;")
        self.assertIn("M5.Display.textWidth(label.c_str())", self.cpp)
        self.assertIn("label_width <= viewport_width", self.cpp)
        self.assertIn("label_scroll_offset_px_", self.hpp)
        self.assertIn("label_scroll_epoch_ms_", self.hpp)
        self.assertNotIn("label_scroll_text_", self.hpp)

    def test_scroll_resets_on_navigation_and_screen_state_changes(self) -> None:
        self.assertGreaterEqual(self.cpp.count("reset_label_scroll("), 5)
        self.assertIn("reset_label_scroll(now_ms);", self.cpp)

    def test_otp_is_drawn_with_inter_digit_and_three_plus_three_spacing(self) -> None:
        self.assertRegex(self.cpp, r"kOtpDigitGapPx\s*=\s*\d+;")
        self.assertIn("const int group_gap = digit_width / 2;", self.cpp)
        self.assertIn("if (index == 2)", self.cpp)
        self.assertIn("M5.Display.print(otp[index]);", self.cpp)

    def test_compact_control_hint_replaces_three_full_lines(self) -> None:
        self.assertIn('"1x next / 2x prev / hold OTP"', self.cpp)
        self.assertNotIn('"Click: next"', self.cpp)
        self.assertNotIn('"2x: previous"', self.cpp)
        self.assertNotIn('"Hold: reveal OTP"', self.cpp)


if __name__ == "__main__":
    unittest.main()
