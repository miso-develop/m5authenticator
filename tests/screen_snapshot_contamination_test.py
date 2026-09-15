from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/diagnostics/screen_snapshot.py"

spec = importlib.util.spec_from_file_location("screen_snapshot_contamination_helper", HELPER)
assert spec is not None and spec.loader is not None
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class FakePort:
    def __init__(self, reads: list[bytes]) -> None:
        self.reads = list(reads)

    def readline(self) -> bytes:
        if self.reads:
            return self.reads.pop(0)
        return b""


class AdvancingClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        self.value += 0.01
        return self.value


class ScreenSnapshotContaminationTest(unittest.TestCase):
    REQUEST_ID = 222
    NOISE = b"SYNTHETIC_CONSOLE_NOISE"

    @staticmethod
    def valid_response(request_id: int) -> dict:
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

    @classmethod
    def current_payload(cls) -> bytes:
        return json.dumps(
            cls.valid_response(cls.REQUEST_ID),
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def current_line(cls) -> bytes:
        return cls.current_payload() + b"\n"

    def read(self, reads: list[bytes]) -> dict:
        return helper.read_matching_response(
            FakePort(reads),
            self.REQUEST_ID,
            1.0,
            now=AdvancingClock(),
        )

    def assert_sanitized_malformed(self, reads: list[bytes], expected_shape: str) -> str:
        with self.assertRaises(RuntimeError) as raised:
            self.read(reads)
        message = str(raised.exception)
        self.assertIn("current diagnostic response is malformed", message)
        self.assertIn("frame_len=", message)
        self.assertIn("utf8=", message)
        self.assertIn("first_object=", message)
        self.assertIn("last_object=", message)
        self.assertIn("nul=", message)
        self.assertIn("control=", message)
        self.assertIn("json_error=", message)
        self.assertIn("id_position=", message)
        self.assertIn("object_starts=", message)
        self.assertIn("object_ends=", message)
        self.assertIn(f"shape={expected_shape}", message)
        self.assertNotIn(self.NOISE.decode("ascii"), message)
        self.assertNotIn(self.current_payload().decode("utf-8"), message)
        return message

    def test_valid_current_response_is_accepted(self) -> None:
        result = self.read([self.current_line()])
        self.assertEqual(self.REQUEST_ID, result["id"])

    def test_noise_without_newline_then_valid_response_is_prefix_contamination(self) -> None:
        self.assert_sanitized_malformed(
            [self.NOISE, self.current_line()],
            "prefix-contamination",
        )

    def test_text_prefix_plus_valid_json_is_prefix_contamination(self) -> None:
        self.assert_sanitized_malformed(
            [self.NOISE + self.current_line()],
            "prefix-contamination",
        )

    def test_valid_json_plus_text_suffix_is_suffix_contamination(self) -> None:
        self.assert_sanitized_malformed(
            [self.current_payload() + self.NOISE + b"\n"],
            "suffix-contamination",
        )

    def test_text_inserted_inside_valid_json_is_middle_interleave(self) -> None:
        payload = self.current_payload()
        split = payload.index(b'"trusted_time_readiness"')
        self.assert_sanitized_malformed(
            [payload[:split] + self.NOISE + payload[split:] + b"\n"],
            "middle-interleave-corruption",
        )

    def test_two_json_objects_without_newline_are_classified(self) -> None:
        stale = json.dumps(
            self.valid_response(111),
            separators=(",", ":"),
        ).encode("utf-8")
        message = self.assert_sanitized_malformed(
            [stale + self.current_payload() + b"\n"],
            "concatenated-objects",
        )
        self.assertIn("object_starts=multiple", message)
        self.assertIn("object_ends=multiple", message)

    def test_invalid_utf8_current_frame_is_classified_without_raw_bytes(self) -> None:
        payload = self.current_payload()
        split = payload.index(b'"ok"')
        message = self.assert_sanitized_malformed(
            [payload[:split] + b"\xff" + payload[split:] + b"\n"],
            "invalid-utf8",
        )
        self.assertIn("utf8=invalid", message)
        self.assertNotIn("ff", message.lower())

    def test_current_id_truncated_json_with_newline_is_truncated_looking(self) -> None:
        payload = self.current_payload()
        truncated = payload[: payload.index(b'"presence"')]
        self.assert_sanitized_malformed(
            [truncated + b"\n"],
            "truncated-looking",
        )

    def test_fragmented_valid_response_is_accepted(self) -> None:
        line = self.current_line()
        result = self.read([line[:23], line[23:81], b"", line[81:]])
        self.assertEqual(self.REQUEST_ID, result["id"])

    def test_fragmented_contaminated_completed_response_fails_closed(self) -> None:
        payload = self.current_payload()
        split = payload.index(b'"screen_mode"')
        contaminated = payload[:split] + self.NOISE + payload[split:] + b"\n"
        self.assert_sanitized_malformed(
            [contaminated[:64], b"", contaminated[64:]],
            "middle-interleave-corruption",
        )

    def test_malformed_current_then_valid_current_still_fails_first_frame(self) -> None:
        malformed = b'{"v":2,"id":222,"ok":true,' + self.NOISE + b"\n"
        with self.assertRaises(RuntimeError) as raised:
            self.read([malformed, self.current_line()])
        message = str(raised.exception)
        self.assertIn("current diagnostic response is malformed", message)
        self.assertNotIn(self.NOISE.decode("ascii"), message)


if __name__ == "__main__":
    unittest.main()
