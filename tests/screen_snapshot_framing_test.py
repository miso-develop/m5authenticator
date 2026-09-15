from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/diagnostics/screen_snapshot.py"

spec = importlib.util.spec_from_file_location("screen_snapshot_framing_helper", HELPER)
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


class ScreenSnapshotFramingTest(unittest.TestCase):
    REQUEST_ID = 222

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

    @staticmethod
    def line(value: dict, *, crlf: bool = False) -> bytes:
        terminator = "\r\n" if crlf else "\n"
        return (json.dumps(value, separators=(",", ":")) + terminator).encode("utf-8")

    def read(self, reads: list[bytes], *, timeout: float = 1.0) -> dict:
        return helper.read_matching_response(
            FakePort(reads),
            self.REQUEST_ID,
            timeout,
            now=AdvancingClock(),
        )

    def current_line(self, *, crlf: bool = False) -> bytes:
        return self.line(self.valid_response(self.REQUEST_ID), crlf=crlf)

    def test_complete_response_in_one_read_is_accepted(self) -> None:
        result = self.read([self.current_line()])
        self.assertEqual(self.REQUEST_ID, result["id"])

    def test_response_split_at_64_byte_boundary_is_reassembled(self) -> None:
        line = self.current_line()
        self.assertGreater(len(line), 64)
        result = self.read([line[:64], line[64:]])
        self.assertEqual(self.REQUEST_ID, result["id"])

    def test_response_split_across_three_fragments_is_reassembled(self) -> None:
        line = self.current_line()
        result = self.read([line[:17], line[17:89], line[89:]])
        self.assertEqual(self.REQUEST_ID, result["id"])

    def test_split_in_middle_of_json_token_waits_for_complete_line(self) -> None:
        line = self.current_line()
        split = line.index(b'"trusted_time_readiness"') + 9
        result = self.read([line[:split], line[split:]])
        self.assertEqual(self.REQUEST_ID, result["id"])

    def test_split_immediately_after_current_request_id_waits_for_newline(self) -> None:
        line = self.current_line()
        marker = b'"id":222,'
        split = line.index(marker) + len(marker)
        result = self.read([line[:split], line[split:]])
        self.assertEqual(self.REQUEST_ID, result["id"])

    def test_crlf_split_between_carriage_return_and_newline_is_accepted(self) -> None:
        line = self.current_line(crlf=True)
        self.assertTrue(line.endswith(b"\r\n"))
        result = self.read([line[:-1], line[-1:]])
        self.assertEqual(self.REQUEST_ID, result["id"])

    def test_completed_stale_line_then_fragmented_current_line(self) -> None:
        stale = self.line(self.valid_response(111))
        current = self.current_line()
        result = self.read([stale, current[:64], current[64:]])
        self.assertEqual(self.REQUEST_ID, result["id"])

    def test_multiple_stale_lines_then_fragmented_current_line(self) -> None:
        current = self.current_line()
        reads = [
            self.line(self.valid_response(10)),
            self.line(self.valid_response(11)),
            self.line(self.valid_response(12)),
            current[:31],
            current[31:97],
            current[97:],
        ]
        result = self.read(reads)
        self.assertEqual(self.REQUEST_ID, result["id"])

    def test_empty_timeout_read_between_fragments_does_not_discard_partial_line(self) -> None:
        current = self.current_line()
        result = self.read([current[:64], b"", current[64:]])
        self.assertEqual(self.REQUEST_ID, result["id"])

    def test_unterminated_line_fails_when_overall_deadline_expires(self) -> None:
        partial = self.current_line()[:-1]
        with self.assertRaisesRegex(RuntimeError, "incomplete") as raised:
            self.read([partial], timeout=0.08)
        self.assertNotIn(partial.decode("utf-8"), str(raised.exception))

    def test_line_exceeding_maximum_length_fails_with_sanitized_error(self) -> None:
        oversized = b"x" * 4097
        with self.assertRaisesRegex(RuntimeError, "maximum") as raised:
            self.read([oversized])
        self.assertNotIn("x" * 32, str(raised.exception))

    def test_malformed_completed_current_line_still_fails_closed(self) -> None:
        malformed = b'{"v":2,"id":222,"ok":true,broken\n'
        with self.assertRaisesRegex(RuntimeError, "current diagnostic response is malformed"):
            self.read([malformed])

    def test_unrelated_noise_line_is_skipped_before_current_response(self) -> None:
        result = self.read([b"unrelated boot noise\n", self.current_line()])
        self.assertEqual(self.REQUEST_ID, result["id"])


if __name__ == "__main__":
    unittest.main()
