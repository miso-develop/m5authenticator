from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/diagnostics/screen_snapshot.py"

spec = importlib.util.spec_from_file_location("screen_snapshot_sync_helper", HELPER)
assert spec is not None and spec.loader is not None
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class StepClock:
    def __init__(self, step: float = 0.05) -> None:
        self.value = 0.0
        self.step = step

    def __call__(self) -> float:
        self.value += self.step
        return self.value


class SyncPort:
    def __init__(
        self,
        pre_reads: list[bytes],
        post_reads: list[bytes],
        *,
        pre_purge_waiting: int = 0,
    ) -> None:
        self.pre_reads = list(pre_reads)
        self.post_reads = list(post_reads)
        self._in_waiting = pre_purge_waiting
        self.request_written = False
        self.events: list[str] = []
        self.write_count = 0

    @property
    def in_waiting(self) -> int:
        return self._in_waiting

    def reset_input_buffer(self) -> None:
        self.events.append("purge")
        self._in_waiting = 0

    def readline(self) -> bytes:
        self.events.append("read-pre" if not self.request_written else "read-post")
        queue = self.post_reads if self.request_written else self.pre_reads
        if queue:
            return queue.pop(0)
        return b""

    def write(self, data: bytes) -> int:
        self.events.append("write")
        self.request_written = True
        self.write_count += 1
        return len(data)

    def flush(self) -> None:
        self.events.append("flush")


class LifecyclePort(SyncPort):
    def __init__(self, owner: "SerialModule") -> None:
        super().__init__(owner.pre_reads, owner.post_reads, pre_purge_waiting=owner.pre_purge_waiting)
        self.owner = owner
        self.is_open = False
        self.port = None
        self.baudrate = None
        self.timeout = None
        self.write_timeout = None
        self.rtscts = None
        self.dsrdtr = None
        self.dtr = True
        self.rts = True

    def open(self) -> None:
        self.owner.events.append("open")
        self.is_open = True

    def reset_input_buffer(self) -> None:
        self.owner.events.append("purge")
        super().reset_input_buffer()

    def readline(self) -> bytes:
        self.owner.events.append("read-pre" if not self.request_written else "read-post")
        return super().readline()

    def write(self, data: bytes) -> int:
        self.owner.events.append("write")
        return super().write(data)

    def flush(self) -> None:
        self.owner.events.append("flush")
        super().flush()

    def close(self) -> None:
        self.owner.events.append("close")
        self.is_open = False


class SerialModule:
    def __init__(
        self,
        pre_reads: list[bytes],
        post_reads: list[bytes],
        *,
        pre_purge_waiting: int = 0,
    ) -> None:
        self.pre_reads = list(pre_reads)
        self.post_reads = list(post_reads)
        self.pre_purge_waiting = pre_purge_waiting
        self.events: list[str] = []
        self.instance: LifecyclePort | None = None

    def Serial(self) -> LifecyclePort:
        self.instance = LifecyclePort(self)
        self.events.append("construct")
        return self.instance


class ScreenSnapshotPreRequestSyncTest(unittest.TestCase):
    REQUEST_ID = 222
    STALE = b"SYNTHETIC_STALE_PREFIX"

    def setUp(self) -> None:
        helper._issued_request_ids.clear()
        if hasattr(helper, "_collection_count"):
            helper._collection_count = 0

    @classmethod
    def current_line(cls) -> bytes:
        value = {
            "v": 2,
            "id": cls.REQUEST_ID,
            "ok": True,
            "data": {
                "runtime_state": "locked",
                "trusted_time_readiness": "not_synced",
                "presence": {"active": False, "confirmed": False, "operation": "none"},
                "screen_mode": "open_web",
            },
        }
        return (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")

    def synchronize(self, port: SyncPort):
        return helper._synchronize_before_request(port, now=StepClock())

    def collect(self, module: SerialModule, reports: list[str]):
        with mock.patch.object(helper, "generate_request_id", return_value=self.REQUEST_ID):
            return helper._collect_snapshot(
                module,
                "COM_TEST",
                1.0,
                now=StepClock(),
                sync_reporter=reports.append,
            )

    def test_open_with_preexisting_host_bytes_records_presence_before_purge(self) -> None:
        port = SyncPort([], [], pre_purge_waiting=17)
        sync = self.synchronize(port)
        self.assertEqual("yes", sync["pre_purge_waiting"])
        self.assertEqual("no", sync["pre_request_data"])
        self.assertEqual(0, sync["pre_request_bytes"])
        self.assertEqual("purge", port.events[0])

    def test_delayed_stale_prefix_after_purge_is_drained_before_request(self) -> None:
        port = SyncPort([self.STALE, b"", b"", b"", b""], [])
        sync = self.synchronize(port)
        self.assertEqual("yes", sync["pre_request_data"])
        self.assertEqual(len(self.STALE), sync["pre_request_bytes"])
        self.assertEqual("no", sync["pre_request_newline"])
        self.assertNotIn(self.STALE.decode("ascii"), helper._format_pre_request_sync(sync))

    def test_stale_complete_line_is_drained_and_newline_is_recorded(self) -> None:
        port = SyncPort([self.STALE + b"\n", b"", b"", b""], [])
        sync = self.synchronize(port)
        self.assertEqual("yes", sync["pre_request_data"])
        self.assertEqual("yes", sync["pre_request_newline"])

    def test_multiple_stale_fragments_restart_quiet_window(self) -> None:
        port = SyncPort([b"ONE", b"", b"TWO", b"THREE", b"", b"", b""], [])
        sync = self.synchronize(port)
        self.assertEqual("yes", sync["pre_request_data"])
        self.assertEqual(len(b"ONETWOTHREE"), sync["pre_request_bytes"])
        self.assertGreaterEqual(sync["quiet_ms"], 200)

    def test_valid_first_response_with_no_stale_data_sends_exactly_one_request(self) -> None:
        reports: list[str] = []
        module = SerialModule([b"", b"", b"", b""], [self.current_line()])
        result = self.collect(module, reports)
        self.assertEqual(self.REQUEST_ID, result["id"])
        assert module.instance is not None
        self.assertEqual(1, module.instance.write_count)
        self.assertTrue(reports)
        self.assertIn("pre_request_data=no", reports[0])
        self.assertIn("invocation=first", reports[0])
        self.assertLess(module.events.index("read-pre"), module.events.index("write"))
        self.assertLess(module.events.index("write"), module.events.index("read-post"))

    def test_stale_unterminated_fragment_then_valid_current_is_separated_before_request(self) -> None:
        reports: list[str] = []
        module = SerialModule([self.STALE, b"", b"", b"", b""], [self.current_line()])
        result = self.collect(module, reports)
        self.assertEqual(self.REQUEST_ID, result["id"])
        assert module.instance is not None
        self.assertEqual(1, module.instance.write_count)
        self.assertIn("pre_request_data=yes", reports[0])
        self.assertIn(f"pre_request_bytes={len(self.STALE)}", reports[0])
        self.assertNotIn(self.STALE.decode("ascii"), reports[0])

    def test_prefix_arriving_immediately_after_request_still_fails_closed(self) -> None:
        reports: list[str] = []
        module = SerialModule(
            [b"", b"", b"", b""],
            [self.STALE, self.current_line()],
        )
        with self.assertRaisesRegex(RuntimeError, "prefix-contamination") as raised:
            self.collect(module, reports)
        assert module.instance is not None
        self.assertEqual(1, module.instance.write_count)
        message = str(raised.exception)
        self.assertIn("pre_request_data=no", message)
        self.assertIn(f"prefix_len={len(self.STALE)}", message)
        self.assertNotIn(self.STALE.decode("ascii"), message)

    def test_malformed_current_response_is_not_skipped_or_retried(self) -> None:
        malformed = b'{"v":2,"id":222,"ok":true,broken\n'
        reports: list[str] = []
        module = SerialModule(
            [b"", b"", b"", b""],
            [malformed, self.current_line()],
        )
        with self.assertRaisesRegex(RuntimeError, "current diagnostic response is malformed"):
            self.collect(module, reports)
        assert module.instance is not None
        self.assertEqual(1, module.instance.write_count)
        self.assertTrue(module.instance.post_reads, "later valid frame must remain unread")

    def test_sync_is_pre_request_only_and_never_writes(self) -> None:
        port = SyncPort([self.STALE, b"", b"", b"", b""], [])
        self.synchronize(port)
        self.assertEqual(0, port.write_count)
        self.assertNotIn("write", port.events)

    def test_sync_diagnostics_never_expose_raw_payload(self) -> None:
        port = SyncPort([self.STALE, b"", b"", b"", b""], [])
        summary = helper._format_pre_request_sync(self.synchronize(port))
        self.assertNotIn(self.STALE.decode("ascii"), summary)
        for required in (
            "pre_purge_waiting=",
            "pre_request_data=",
            "pre_request_bytes=",
            "pre_request_newline=",
            "first_byte=",
            "quiet_ms=",
            "invocation=",
        ):
            self.assertIn(required, summary)


if __name__ == "__main__":
    unittest.main()
