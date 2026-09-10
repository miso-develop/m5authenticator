from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import inspect_production_efuse


def summary_for_slot(
    key_id: int,
    *,
    purpose: str,
    readable: bool,
    writeable: bool,
    purpose_writeable: bool,
    raw_value: str,
) -> dict[str, object]:
    return {
        f"KEY_PURPOSE_{key_id}": {
            "value": purpose,
            "writeable": purpose_writeable,
        },
        f"BLOCK_KEY{key_id}": {
            "readable": readable,
            "writeable": writeable,
            "raw_value": raw_value,
        },
    }


def six_slot_summary() -> dict[str, object]:
    summary: dict[str, object] = {}
    for key_id in range(6):
        summary.update(
            summary_for_slot(
                key_id,
                purpose="USER",
                readable=True,
                writeable=True,
                purpose_writeable=True,
                raw_value="0x" + "00" * 32,
            )
        )
    return summary


class ProductionEfuseInspectionTest(unittest.TestCase):
    def test_free_slot_is_candidate(self) -> None:
        summary = six_slot_summary()
        slots = [inspect_production_efuse.classify_slot(summary, key_id) for key_id in range(6)]
        self.assertEqual(slots[0].state, "free")
        verdict, _ = inspect_production_efuse.evaluate(slots, 0)
        self.assertEqual(verdict, "first-time-init-candidate")

    def test_fully_protected_hmac_is_reusable(self) -> None:
        summary = six_slot_summary()
        summary.update(
            summary_for_slot(
                0,
                purpose="HMAC_UP",
                readable=False,
                writeable=False,
                purpose_writeable=False,
                raw_value="0x" + "00" * 32,
            )
        )
        slot = inspect_production_efuse.classify_slot(summary, 0)
        self.assertEqual(slot.state, "reusable")
        self.assertTrue(slot.read_protected)
        self.assertTrue(slot.key_write_protected)
        self.assertTrue(slot.purpose_write_protected)

    def test_partially_protected_hmac_is_incompatible(self) -> None:
        summary = six_slot_summary()
        summary.update(
            summary_for_slot(
                0,
                purpose="HMAC_UP",
                readable=False,
                writeable=True,
                purpose_writeable=False,
                raw_value="0x" + "00" * 32,
            )
        )
        slot = inspect_production_efuse.classify_slot(summary, 0)
        self.assertEqual(slot.state, "incompatible")
        verdict, _ = inspect_production_efuse.evaluate(
            [inspect_production_efuse.classify_slot(summary, key_id) for key_id in range(6)],
            0,
        )
        self.assertEqual(verdict, "blocked")

    def test_nonzero_user_slot_is_not_free(self) -> None:
        summary = six_slot_summary()
        summary.update(
            summary_for_slot(
                0,
                purpose="USER",
                readable=True,
                writeable=True,
                purpose_writeable=True,
                raw_value="0x01" + "00" * 31,
            )
        )
        self.assertEqual(inspect_production_efuse.classify_slot(summary, 0).state, "incompatible")

    def test_other_hmac_blocks_new_burn_candidate(self) -> None:
        summary = six_slot_summary()
        summary.update(
            summary_for_slot(
                1,
                purpose="HMAC_UP",
                readable=False,
                writeable=False,
                purpose_writeable=False,
                raw_value="0x" + "00" * 32,
            )
        )
        slots = [inspect_production_efuse.classify_slot(summary, key_id) for key_id in range(6)]
        verdict, detail = inspect_production_efuse.evaluate(slots, 0)
        self.assertEqual(verdict, "blocked-review-existing-hmac")
        self.assertIn("KEY1", detail)

    def test_report_never_contains_raw_key_value(self) -> None:
        marker = "deadbeef" * 8
        summary = six_slot_summary()
        summary.update(
            summary_for_slot(
                0,
                purpose="USER",
                readable=True,
                writeable=True,
                purpose_writeable=True,
                raw_value="0x" + marker,
            )
        )
        slots = [inspect_production_efuse.classify_slot(summary, key_id) for key_id in range(6)]
        report = inspect_production_efuse.format_report(slots, 0).lower()
        self.assertNotIn(marker, report)
        self.assertNotIn("raw_value", report)

    def test_python_script_entrypoint_uses_current_interpreter(self) -> None:
        self.assertEqual(
            inspect_production_efuse._tool_prefix("C:/esp/espefuse.py"),
            [sys.executable, "C:/esp/espefuse.py"],
        )
        self.assertEqual(
            inspect_production_efuse._tool_prefix("C:/esp/espefuse.exe"),
            ["C:/esp/espefuse.exe"],
        )

    def test_port_prefers_cli_and_falls_back_to_environment(self) -> None:
        with patch.dict(os.environ, {"M5AUTH_PORT": "COM4"}, clear=False):
            self.assertEqual(inspect_production_efuse.resolve_port(None), "COM4")
            self.assertEqual(inspect_production_efuse.resolve_port("COM9"), "COM9")

    def test_port_is_required_when_environment_is_missing(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(inspect_production_efuse.InspectionError):
                inspect_production_efuse.resolve_port(None)


if __name__ == "__main__":
    unittest.main()
