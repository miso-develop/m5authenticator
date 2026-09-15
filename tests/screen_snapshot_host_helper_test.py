from __future__ import annotations

import importlib.util
import json
import math
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


class FakeSerialException(Exception):
    pass


class LifecycleSerialPort:
    def __init__(self, owner: "LifecycleSerialModule") -> None:
        self.owner = owner
        self.is_open = False
        self.port = None
        self.baudrate = None
        self.timeout = None
        self.write_timeout = None
        self.rtscts = None
        self.dsrdtr = None
        self._dtr = True
        self._rts = True
        self.request_written = False

    @property
    def dtr(self) -> bool:
        return self._dtr

    @dtr.setter
    def dtr(self, value: bool) -> None:
        self.owner.events.append(("dtr", value))
        self._dtr = value

    @property
    def rts(self) -> bool:
        return self._rts

    @rts.setter
    def rts(self, value: bool) -> None:
        self.owner.events.append(("rts", value))
        self._rts = value

    def open(self) -> None:
        self.owner.events.append(("open", self._dtr, self._rts))
        if self.owner.fail_stage == "open":
            raise FakeSerialException("synthetic-sensitive-open-detail")
        self.is_open = True

    def reset_input_buffer(self) -> None:
        self.owner.events.append(("reset_input_buffer",))

    def write(self, data: bytes) -> int:
        self.owner.events.append(("write", data))
        if self.owner.fail_stage == "write":
            raise FakeSerialException("synthetic write failure")
        self.request_written = True
        return len(data)

    def flush(self) -> None:
        self.owner.events.append(("flush",))
        if self.owner.fail_stage == "flush":
            raise FakeSerialException("synthetic flush failure")

    def readline(self) -> bytes:
        self.owner.events.append(("readline",))
        if self.owner.fail_stage == "readline":
            raise FakeSerialException("synthetic read failure")
        if not self.request_written:
            return b""
        if self.owner.lines:
            return self.owner.lines.pop(0)
        return b""

    def close(self) -> None:
        self.owner.events.append(("close",))
        if self.owner.fail_stage == "close":
            raise FakeSerialException("synthetic close failure")
        self.is_open = False


class LifecycleSerialModule:
    SerialException = FakeSerialException

    def __init__(self, lines: list[bytes] | None = None, fail_stage: str | None = None) -> None:
        self.lines = list(lines or [])
        self.fail_stage = fail_stage
        self.events: list[tuple] = []
        self.instance: LifecycleSerialPort | None = None

    def Serial(self, *args, **kwargs) -> LifecycleSerialPort:
        if args or kwargs:
            raise AssertionError("Serial must be constructed closed with no port arguments")
        self.instance = LifecycleSerialPort(self)
        self.events.append(("construct", args, kwargs, self.instance.is_open))
        return self.instance


class ScreenSnapshotHostHelperTest(unittest.TestCase):
    def setUp(self) -> None:
        helper._issued_request_ids.clear()
        helper._collection_count = 0

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

    def collect(self, module: LifecycleSerialModule, timeout: float = 1.0) -> dict:
        with mock.patch.object(helper, "generate_request_id", return_value=222):
            return helper._collect_snapshot(
                module,
                "COM_TEST",
                timeout,
                now=AdvancingClock(),
            )

    def test_fresh_request_id_generation_retries_collision_and_is_not_fixed(self) -> None:
        with mock.patch.object(
            helper.secrets,
            "randbelow",
            side_effect=[0, 0, 1, 123456],
        ):
            self.assertEqual(1, helper.generate_request_id())
            self.assertEqual(2, helper.generate_request_id())
            self.assertEqual(123457, helper.generate_request_id())
        self.assertEqual({1, 2, 123457}, helper._issued_request_ids)
        self.assertNotIn(9002, helper._issued_request_ids)

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

    def test_serial_is_closed_configured_inactive_then_synchronized_before_request(self) -> None:
        module = LifecycleSerialModule([self.line(self.valid_response(222))])
        result = self.collect(module)
        self.assertEqual(222, result["id"])

        names = [event[0] for event in module.events]
        readline_indices = [index for index, name in enumerate(names) if name == "readline"]
        self.assertEqual(("construct", (), {}, False), module.events[0])
        self.assertLess(names.index("dtr"), names.index("open"))
        self.assertLess(names.index("rts"), names.index("open"))
        self.assertLess(names.index("open"), names.index("reset_input_buffer"))
        self.assertLess(names.index("reset_input_buffer"), readline_indices[0])
        self.assertLess(readline_indices[0], names.index("write"))
        self.assertLess(names.index("write"), names.index("flush"))
        self.assertLess(names.index("flush"), readline_indices[-1])
        self.assertLess(readline_indices[-1], names.index("close"))
        self.assertIn(("dtr", False), module.events)
        self.assertIn(("rts", False), module.events)
        self.assertIn(("open", False, False), module.events)
        assert module.instance is not None
        self.assertEqual("COM_TEST", module.instance.port)
        self.assertEqual(115200, module.instance.baudrate)
        self.assertFalse(module.instance.rtscts)
        self.assertFalse(module.instance.dsrdtr)

    def test_snapshot_lifecycle_never_intentionally_asserts_dtr_or_rts(self) -> None:
        module = LifecycleSerialModule([self.line(self.valid_response(222))])
        self.collect(module)
        line_events = [event for event in module.events if event[0] in {"dtr", "rts"}]
        self.assertEqual([("dtr", False), ("rts", False)], line_events)
        self.assertNotIn(("dtr", True), module.events)
        self.assertNotIn(("rts", True), module.events)

    def test_open_failure_sends_no_request_and_never_returns_success(self) -> None:
        module = LifecycleSerialModule(fail_stage="open")
        with self.assertRaisesRegex(RuntimeError, "serial snapshot I/O failed") as raised:
            self.collect(module)
        self.assertNotIn("synthetic-sensitive-open-detail", str(raised.exception))
        names = [event[0] for event in module.events]
        self.assertIn("open", names)
        self.assertNotIn("write", names)
        self.assertNotIn("readline", names)

    def test_write_flush_and_read_failures_fail_closed_and_close(self) -> None:
        for stage in ("write", "flush", "readline"):
            with self.subTest(stage=stage):
                module = LifecycleSerialModule(
                    [self.line(self.valid_response(222))],
                    fail_stage=stage,
                )
                with self.assertRaisesRegex(RuntimeError, "serial snapshot I/O failed"):
                    self.collect(module)
                self.assertIn(("close",), module.events)

    def test_timeout_failure_closes_port_and_returns_no_snapshot(self) -> None:
        module = LifecycleSerialModule()
        with mock.patch.object(helper, "generate_request_id", return_value=222), mock.patch.object(
            helper,
            "read_matching_response",
            side_effect=RuntimeError("no valid response for the current request id before timeout"),
        ):
            with self.assertRaisesRegex(RuntimeError, "current request id"):
                helper._collect_snapshot(
                    module,
                    "COM_TEST",
                    1.0,
                    now=AdvancingClock(),
                )
        self.assertIn(("close",), module.events)

    def test_close_failure_discards_already_validated_snapshot(self) -> None:
        module = LifecycleSerialModule(
            [self.line(self.valid_response(222))],
            fail_stage="close",
        )
        with self.assertRaisesRegex(RuntimeError, "snapshot evidence discarded"):
            self.collect(module)
        self.assertIn(("readline",), module.events)
        self.assertIn(("close",), module.events)

    def test_timeout_must_be_finite_and_positive(self) -> None:
        for value in (0.0, -1.0, math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "finite positive"):
                    helper._validate_timeout_seconds(value)
                with self.assertRaisesRegex(RuntimeError, "finite positive"):
                    helper.read_snapshot("COM_TEST", value)

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

    def test_malformed_current_id_response_fails_closed(self) -> None:
        current_malformed = b'{"v":2,"id":222,"ok":true,broken\n'
        with self.assertRaisesRegex(RuntimeError, "current diagnostic response is malformed"):
            self.read([current_malformed, self.line(self.valid_response(222))])

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
        with self.assertRaisesRegex(RuntimeError, "current diagnostic response is malformed"):
            self.read([duplicate, current])

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
