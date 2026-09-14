from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/diagnostics/screen_snapshot.py"

spec = importlib.util.spec_from_file_location("screen_snapshot_helper", HELPER)
assert spec is not None and spec.loader is not None
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class FakePort:
    def __init__(self, lines: list[bytes]) -> None:
        self.lines = list(lines)

    def readline(self) -> bytes:
        if self.lines:
            return self.lines.pop(0)
        return b""


class AdvancingClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        self.value += 0.01
        return self.value


class ScreenSnapshotHostHelperTest(unittest.TestCase):
    def valid_response(self, request_id: int) -> dict:
        return {
            "v": 2,
            "id": request_id,
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

    @staticmethod
    def line(value: dict) -> bytes:
        return (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")

    def read(self, lines: list[bytes], request_id: int = 222) -> dict:
        return helper.read_matching_response(
            FakePort(lines),
            request_id,
            1.0,
            now=AdvancingClock(),
        )

    def test_fresh_request_id_generation_is_positive_and_not_fixed(self) -> None:
        with mock.patch.object(helper.secrets, "randbelow", side_effect=[0, 1, 123456]):
            self.assertEqual(1, helper.generate_request_id())
            self.assertEqual(2, helper.generate_request_id())
            self.assertEqual(123457, helper.generate_request_id())
        self.assertNotEqual(9002, 1)
        self.assertNotEqual(9002, 2)

    def test_request_echo_identity_is_dynamic_and_read_only(self) -> None:
        request_id = 182736451
        request = helper.build_request(request_id).decode("ascii")
        parsed = json.loads(request)
        self.assertEqual(
            {
                "v": 2,
                "id": request_id,
                "op": "diagnostics.screen_snapshot",
                "params": {},
            },
            parsed,
        )
        self.assertTrue(request.endswith("\n"))
        for forbidden in (
            "session.",
            "vault.",
            "time.sync",
            "device.lock",
            "factory_reset",
        ):
            self.assertNotIn(forbidden, request)

    def test_case_a_single_stale_wrong_id_is_never_accepted(self) -> None:
        stale = self.valid_response(111)
        current = self.valid_response(222)
        result = self.read([self.line(stale), self.line(current)])
        self.assertEqual(222, result["id"])

    def test_case_b_multiple_stale_lines_are_skipped_until_current_id(self) -> None:
        lines = [
            self.line(self.valid_response(10)),
            self.line(self.valid_response(11)),
            self.line(self.valid_response(12)),
            self.line(self.valid_response(222)),
        ]
        self.assertEqual(222, self.read(lines)["id"])

    def test_case_b_only_stale_lines_times_out_fail_closed(self) -> None:
        port = FakePort([
            self.line(self.valid_response(10)),
            self.line(self.valid_response(11)),
        ])
        with self.assertRaisesRegex(RuntimeError, "current request id"):
            helper.read_matching_response(port, 222, 0.08, now=AdvancingClock())

    def test_case_c_malformed_stale_line_does_not_block_current_response(self) -> None:
        lines = [
            b'{"v":2,"id":111,"ok":true,broken\n',
            self.line(self.valid_response(222)),
        ]
        self.assertEqual(222, self.read(lines)["id"])

    def test_case_d_current_id_error_is_explicit_failure(self) -> None:
        error = {
            "v": 2,
            "id": 222,
            "ok": False,
            "error": {"code": "snapshot_not_ready"},
        }
        with self.assertRaisesRegex(RuntimeError, "snapshot_not_ready"):
            self.read([self.line(error)])

    def test_case_e_current_id_extra_field_is_rejected(self) -> None:
        response = self.valid_response(222)
        response["data"]["credential_label"] = "synthetic"
        with self.assertRaisesRegex(RuntimeError, "allowlist"):
            self.read([self.line(response)])

    def test_current_id_top_level_extra_field_is_rejected(self) -> None:
        response = self.valid_response(222)
        response["device_id"] = "synthetic-not-a-real-device-id"
        with self.assertRaisesRegex(RuntimeError, "allowlist"):
            self.read([self.line(response)])

    def test_duplicate_json_keys_never_become_success_evidence(self) -> None:
        duplicate = (
            b'{"v":2,"id":222,"id":222,"ok":true,'
            b'"data":{"runtime_state":"locked","trusted_time_readiness":"not_synced",'
            b'"presence":{"active":false,"confirmed":false,"operation":"none"},'
            b'"screen_mode":"open_web"}}\n'
        )
        current = self.line(self.valid_response(222))
        self.assertEqual(222, self.read([duplicate, current])["id"])

    def test_valid_allowlisted_response_is_accepted_only_for_expected_id(self) -> None:
        response = self.valid_response(222)
        self.assertIs(response, helper.validate_success_response(response, 222))
        with self.assertRaises(ValueError):
            helper.validate_success_response(response, 223)

    def test_current_id_unknown_enum_is_rejected(self) -> None:
        response = self.valid_response(222)
        response["data"]["screen_mode"] = "raw_screen"
        with self.assertRaisesRegex(RuntimeError, "allowlist"):
            self.read([self.line(response)])


if __name__ == "__main__":
    unittest.main()
