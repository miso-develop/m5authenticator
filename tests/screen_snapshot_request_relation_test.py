from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/diagnostics/screen_snapshot.py"

spec = importlib.util.spec_from_file_location("screen_snapshot_relation_helper", HELPER)
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


class ScreenSnapshotRequestRelationTest(unittest.TestCase):
    REQUEST_ID = 1000
    SECRET_MARKER = b"SYNTHETIC_RAW_MARKER_DO_NOT_PRINT"

    @staticmethod
    def response_payload(request_id: int) -> bytes:
        value = {
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
        return json.dumps(value, separators=(",", ":")).encode("utf-8")

    def analyze(self, prefix: bytes, request_id: int | None = None, *, suffix_id: int | None = None):
        current_id = self.REQUEST_ID if request_id is None else request_id
        actual_suffix_id = current_id if suffix_id is None else suffix_id
        request = helper.build_request(current_id)
        raw = prefix + self.response_payload(actual_suffix_id) + b"\n"
        return helper._analyze_malformed_relation(raw, current_id, request)

    def test_request_lengths_cover_below_equal_and_above_64_bytes(self) -> None:
        self.assertLess(len(helper.build_request(1)), 64)
        self.assertEqual(64, len(helper.build_request(100)))
        self.assertGreater(len(helper.build_request(1000)), 64)

    def test_prefix_equal_request_first64_is_identified(self) -> None:
        request = helper.build_request(self.REQUEST_ID)
        relation = self.analyze(request[:64])
        self.assertEqual(64, relation["prefix_len"])
        self.assertEqual("yes", relation["prefix_equals_request_prefix"])
        self.assertEqual("yes", relation["prefix_equals_request_first64"])
        self.assertEqual("64", relation["request_prefix_match_len"])
        self.assertEqual("yes", relation["suffix_json_valid"])
        self.assertEqual("yes", relation["suffix_id_matches_current"])
        self.assertEqual("yes", relation["suffix_allowlist_valid"])

    def test_prefix_equal_64_byte_request_body_is_identified_without_raw_output(self) -> None:
        request = helper.build_request(self.REQUEST_ID)
        request_body = request.rstrip(b"\n")
        self.assertEqual(64, len(request_body))
        relation = self.analyze(request_body)
        self.assertEqual(64, relation["prefix_len"])
        self.assertEqual("yes", relation["prefix_equals_request_prefix"])
        self.assertEqual("yes", relation["prefix_equals_request_first64"])
        self.assertEqual("64", relation["request_prefix_match_len"])
        self.assertNotIn(request.decode("ascii"), helper._format_malformed_relation(relation))

    def test_prefix_equal_larger_request_body_is_bucketed_gt64(self) -> None:
        request_id = 10000
        request = helper.build_request(request_id)
        request_body = request.rstrip(b"\n")
        self.assertGreater(len(request_body), 64)
        relation = self.analyze(request_body, request_id=request_id)
        self.assertEqual(len(request_body), relation["prefix_len"])
        self.assertEqual("yes", relation["prefix_equals_request_prefix"])
        self.assertEqual("no", relation["prefix_equals_request_first64"])
        self.assertEqual("gt-64", relation["request_prefix_match_len"])

    def test_unrelated_64_byte_prefix_is_not_request_echo(self) -> None:
        relation = self.analyze(b"X" * 64)
        self.assertEqual(64, relation["prefix_len"])
        self.assertEqual("no", relation["prefix_equals_request_prefix"])
        self.assertEqual("no", relation["prefix_equals_request_first64"])
        self.assertEqual("none", relation["request_prefix_match_len"])

    def test_prefix_lengths_63_64_65_are_reported_exactly(self) -> None:
        for length in (63, 64, 65):
            with self.subTest(length=length):
                relation = self.analyze(b"X" * length)
                self.assertEqual(length, relation["prefix_len"])

    def test_valid_current_suffix_is_structurally_confirmed(self) -> None:
        relation = self.analyze(b"X" * 64)
        self.assertEqual("yes", relation["suffix_json_valid"])
        self.assertEqual("yes", relation["suffix_id_matches_current"])
        self.assertEqual("yes", relation["suffix_allowlist_valid"])

    def test_invalid_suffix_is_not_promoted_to_validity(self) -> None:
        request = helper.build_request(self.REQUEST_ID)
        raw = b"X" * 64 + b'{"v":2,"id":1000,"ok":true,broken\n'
        relation = helper._analyze_malformed_relation(raw, self.REQUEST_ID, request)
        self.assertEqual("no", relation["suffix_json_valid"])
        self.assertEqual("no", relation["suffix_id_matches_current"])
        self.assertEqual("no", relation["suffix_allowlist_valid"])

    def test_wrong_id_suffix_is_valid_json_but_not_current_or_allowlisted_for_current(self) -> None:
        relation = self.analyze(b"X" * 64, suffix_id=999)
        self.assertEqual("yes", relation["suffix_json_valid"])
        self.assertEqual("no", relation["suffix_id_matches_current"])
        self.assertEqual("no", relation["suffix_allowlist_valid"])

    def test_relation_diagnostics_never_expose_raw_prefix_request_or_suffix(self) -> None:
        request = helper.build_request(self.REQUEST_ID)
        raw = self.SECRET_MARKER + self.response_payload(self.REQUEST_ID) + b"\n"
        relation = helper._analyze_malformed_relation(raw, self.REQUEST_ID, request)
        summary = helper._format_malformed_relation(relation)
        self.assertNotIn(self.SECRET_MARKER.decode("ascii"), summary)
        self.assertNotIn(request.decode("ascii").strip(), summary)
        self.assertNotIn(self.response_payload(self.REQUEST_ID).decode("utf-8"), summary)
        for key in (
            "request_len=",
            "prefix_len=",
            "prefix_equals_request_prefix=",
            "prefix_equals_request_first64=",
            "request_prefix_match_len=",
            "suffix_json_valid=",
            "suffix_id_matches_current=",
            "suffix_allowlist_valid=",
        ):
            self.assertIn(key, summary)

    def test_malformed_relation_never_changes_fail_closed_result(self) -> None:
        request = helper.build_request(self.REQUEST_ID)
        raw = request[:64] + self.response_payload(self.REQUEST_ID) + b"\n"
        with self.assertRaisesRegex(RuntimeError, "current diagnostic response is malformed") as raised:
            helper.read_matching_response(
                FakePort([raw]),
                self.REQUEST_ID,
                1.0,
                now=AdvancingClock(),
                request=request,
                request_sent_at=0.0,
            )
        message = str(raised.exception)
        self.assertIn("prefix_equals_request_first64=yes", message)
        self.assertIn("suffix_allowlist_valid=yes", message)

    def test_clean_valid_response_still_passes_with_relation_context_enabled(self) -> None:
        request = helper.build_request(self.REQUEST_ID)
        result = helper.read_matching_response(
            FakePort([self.response_payload(self.REQUEST_ID) + b"\n"]),
            self.REQUEST_ID,
            1.0,
            now=AdvancingClock(),
            request=request,
            request_sent_at=0.0,
        )
        self.assertEqual(self.REQUEST_ID, result["id"])


if __name__ == "__main__":
    unittest.main()
