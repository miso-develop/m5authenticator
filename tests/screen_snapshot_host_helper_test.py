from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/diagnostics/screen_snapshot.py"

spec = importlib.util.spec_from_file_location("screen_snapshot_helper", HELPER)
assert spec is not None and spec.loader is not None
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class ScreenSnapshotHostHelperTest(unittest.TestCase):
    def valid_response(self) -> dict:
        return {
            "v": 2,
            "id": 9002,
            "ok": True,
            "data": {
                "runtime_state": "locked",
                "trusted_time_readiness": "not_synced",
                "presence": {
                    "active": False,
                    "confirmed": False,
                    "operation": "none",
                },
                "screen_mode": "open_web",
            },
        }

    def test_exact_request_is_single_read_only_diagnostic_line(self) -> None:
        self.assertEqual(
            '{"v":2,"id":9002,"op":"diagnostics.screen_snapshot","params":{}}',
            helper.REQUEST_TEXT,
        )
        self.assertEqual((helper.REQUEST_TEXT + "\n").encode("ascii"), helper.REQUEST_BYTES)
        for forbidden in (
            "session.",
            "vault.",
            "time.sync",
            "device.lock",
            "factory_reset",
        ):
            self.assertNotIn(forbidden, helper.REQUEST_TEXT)

    def test_valid_allowlisted_response_is_accepted(self) -> None:
        response = self.valid_response()
        self.assertIs(response, helper.validate_response(response))

    def test_extra_top_level_or_data_keys_are_rejected(self) -> None:
        response = self.valid_response()
        response["attempt_id"] = "synthetic"
        with self.assertRaises(ValueError):
            helper.validate_response(response)

        response = self.valid_response()
        response["data"]["credential_label"] = "synthetic"
        with self.assertRaises(ValueError):
            helper.validate_response(response)

        response = self.valid_response()
        response["data"]["totp"] = "000000"
        with self.assertRaises(ValueError):
            helper.validate_response(response)

    def test_extra_presence_keys_are_rejected(self) -> None:
        response = self.valid_response()
        response["data"]["presence"]["attempt_id"] = "synthetic"
        with self.assertRaises(ValueError):
            helper.validate_response(response)

    def test_wrong_protocol_identity_or_unknown_enum_is_rejected(self) -> None:
        response = self.valid_response()
        response["id"] = 9001
        with self.assertRaises(ValueError):
            helper.validate_response(response)

        response = self.valid_response()
        response["data"]["screen_mode"] = "raw_screen"
        with self.assertRaises(ValueError):
            helper.validate_response(response)

    def test_error_response_is_not_printed_as_sanitized_snapshot(self) -> None:
        with self.assertRaises(ValueError):
            helper.validate_response(
                {"v": 2, "id": 9002, "ok": False, "error": {"code": "internal_error"}}
            )


if __name__ == "__main__":
    unittest.main()
