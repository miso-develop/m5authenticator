import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_MAIN = ROOT / "firmware" / "main" / "app_main.cpp"
SDKCONFIG_DEFAULTS = ROOT / "firmware" / "sdkconfig.defaults"

TX_FLUSH_TIMEOUT_US = 50_000


class UsbCdcTransactionModel:
    """Small behavioral model for the ESP32-S3 64-byte CDC transaction edge."""

    PACKET_SIZE = 64

    def __init__(self) -> None:
        self.listener_open = False
        self.unterminated = bytearray()
        self.terminated_backlog = bytearray()
        self.host_queue = bytearray()

    def emit_flushed_transfer(self, payload: bytes) -> None:
        if self.unterminated:
            payload = bytes(self.unterminated) + payload
            self.unterminated.clear()

        if payload and len(payload) % self.PACKET_SIZE == 0:
            self.unterminated.extend(payload)
            return

        self._publish(payload)

    def finalize_with_zlp(self) -> None:
        payload = bytes(self.unterminated)
        self.unterminated.clear()
        self._publish(payload)

    def open_listener(self) -> None:
        self.listener_open = True
        self.host_queue.extend(self.terminated_backlog)
        self.terminated_backlog.clear()

    def purge_host_queue(self) -> bytes:
        removed = bytes(self.host_queue)
        self.host_queue.clear()
        return removed

    def read_host_queue(self) -> bytes:
        result = bytes(self.host_queue)
        self.host_queue.clear()
        return result

    def _publish(self, payload: bytes) -> None:
        if self.listener_open:
            self.host_queue.extend(payload)
        else:
            self.terminated_backlog.extend(payload)


def idf_fsync_no_driver_model(
    *,
    now_us: int,
    last_tx_ts_us: int,
    writable_samples: list[bool],
) -> tuple[bool, int]:
    """Model the v5.5.5 wait loop whose deadline is based on last_tx_ts."""
    checks = 0
    sample_index = 0
    while (now_us - last_tx_ts_us) < TX_FLUSH_TIMEOUT_US:
        checks += 1
        writable = (
            writable_samples[sample_index]
            if sample_index < len(writable_samples)
            else False
        )
        sample_index += 1
        if writable:
            return True, checks
        now_us += 1_000
    return False, checks


def idf_tx_char_no_driver_model(
    *,
    now_us: int,
    last_tx_ts_us: int,
    initially_writable: bool,
) -> bool:
    """Model the first no-driver tx_char attempt and stale-timestamp drop edge."""
    if initially_writable:
        return True
    return (now_us - last_tx_ts_us) < TX_FLUSH_TIMEOUT_US


def fresh_local_deadline_wait_model(
    *,
    samples: list[bool],
    timeout_us: int = TX_FLUSH_TIMEOUT_US,
    poll_us: int = 1_000,
) -> tuple[bool, int]:
    """Wait from a fresh local start; deliberately has no last_tx_ts input."""
    elapsed = 0
    checks = 0
    sample_index = 0
    while elapsed < timeout_us:
        checks += 1
        writable = samples[sample_index] if sample_index < len(samples) else False
        sample_index += 1
        if writable:
            return True, checks
        elapsed += poll_us
    return False, checks


class EspIdfStaleLastTxTimestampModelTest(unittest.TestCase):
    def test_last_tx_ts_fresh_allows_existing_fsync_to_observe_writable(self) -> None:
        ok, checks = idf_fsync_no_driver_model(
            now_us=1_000_000,
            last_tx_ts_us=999_000,
            writable_samples=[True],
        )
        self.assertTrue(ok)
        self.assertEqual(1, checks)

    def test_last_tx_ts_stale_makes_existing_fsync_fail_before_writable_check(self) -> None:
        ok, checks = idf_fsync_no_driver_model(
            now_us=2_000_000,
            last_tx_ts_us=1_000_000,
            writable_samples=[True],
        )
        self.assertFalse(ok)
        self.assertEqual(0, checks)

    def test_stale_last_tx_ts_can_make_tx_char_drop_when_fifo_is_still_full(self) -> None:
        sent = idf_tx_char_no_driver_model(
            now_us=2_000_000,
            last_tx_ts_us=1_000_000,
            initially_writable=False,
        )
        self.assertFalse(sent)

    def test_fresh_local_deadline_waits_independently_of_last_tx_ts(self) -> None:
        ok, checks = fresh_local_deadline_wait_model(samples=[False, False, True])
        self.assertTrue(ok)
        self.assertEqual(3, checks)

    def test_fresh_local_deadline_is_bounded_when_fifo_never_becomes_writable(self) -> None:
        ok, checks = fresh_local_deadline_wait_model(samples=[])
        self.assertFalse(ok)
        self.assertEqual(TX_FLUSH_TIMEOUT_US // 1_000, checks)


class Exact64UsbBoundaryModelTest(unittest.TestCase):
    RESPONSE = b'{"v":2,"id":7,"ok":true,"data":{"screen":"LOCKED"}}\n'

    def _stale(self, length: int) -> bytes:
        return b"S" * length

    def test_exactly_64_byte_stale_tx_can_join_later_valid_response(self) -> None:
        model = UsbCdcTransactionModel()
        model.emit_flushed_transfer(self._stale(64))
        model.open_listener()
        self.assertEqual(model.purge_host_queue(), b"")
        model.emit_flushed_transfer(self.RESPONSE)
        self.assertEqual(model.read_host_queue(), self._stale(64) + self.RESPONSE)

    def test_63_byte_stale_tx_is_terminated_and_host_purgeable(self) -> None:
        model = UsbCdcTransactionModel()
        model.emit_flushed_transfer(self._stale(63))
        model.open_listener()
        self.assertEqual(model.purge_host_queue(), self._stale(63))
        model.emit_flushed_transfer(self.RESPONSE)
        self.assertEqual(model.read_host_queue(), self.RESPONSE)

    def test_65_byte_stale_tx_is_terminated_and_host_purgeable(self) -> None:
        model = UsbCdcTransactionModel()
        model.emit_flushed_transfer(self._stale(65))
        model.open_listener()
        self.assertEqual(model.purge_host_queue(), self._stale(65))
        model.emit_flushed_transfer(self.RESPONSE)
        self.assertEqual(model.read_host_queue(), self.RESPONSE)

    def test_exactly_64_byte_stale_tx_plus_zlp_becomes_purgeable(self) -> None:
        model = UsbCdcTransactionModel()
        model.emit_flushed_transfer(self._stale(64))
        model.finalize_with_zlp()
        model.open_listener()
        self.assertEqual(model.purge_host_queue(), self._stale(64))
        model.emit_flushed_transfer(self.RESPONSE)
        self.assertEqual(model.read_host_queue(), self.RESPONSE)

    def test_listener_after_stale64_plus_fresh_wait_and_delimiter_separates_frames(self) -> None:
        model = UsbCdcTransactionModel()
        model.emit_flushed_transfer(self._stale(64))
        model.open_listener()
        self.assertEqual(model.purge_host_queue(), b"")

        writable, _ = fresh_local_deadline_wait_model(samples=[False, True])
        self.assertTrue(writable)
        model.emit_flushed_transfer(b"\n")
        self.assertEqual(model.read_host_queue(), self._stale(64) + b"\n")

        model.emit_flushed_transfer(self.RESPONSE)
        self.assertEqual(model.read_host_queue(), self.RESPONSE)

    def test_fifo_never_writable_fails_closed_without_current_response(self) -> None:
        model = UsbCdcTransactionModel()
        model.emit_flushed_transfer(self._stale(64))
        model.open_listener()
        writable, _ = fresh_local_deadline_wait_model(samples=[])
        self.assertFalse(writable)
        self.assertEqual(model.read_host_queue(), b"")

    def test_clean_response_is_unchanged(self) -> None:
        model = UsbCdcTransactionModel()
        model.open_listener()
        writable, _ = fresh_local_deadline_wait_model(samples=[True])
        self.assertTrue(writable)
        model.emit_flushed_transfer(b"\n")
        self.assertEqual(model.read_host_queue(), b"\n")
        model.emit_flushed_transfer(self.RESPONSE)
        self.assertEqual(model.read_host_queue(), self.RESPONSE)


class ScreenSnapshotTransportBoundarySourceContractTest(unittest.TestCase):
    def test_fix_does_not_disable_production_logging_or_burn_rom_log_efuse(self) -> None:
        defaults = SDKCONFIG_DEFAULTS.read_text(encoding="utf-8")
        self.assertNotIn("CONFIG_BOOTLOADER_LOG_LEVEL_NONE=y", defaults)
        self.assertNotIn("CONFIG_LOG_DEFAULT_LEVEL_NONE=y", defaults)
        self.assertNotIn("CONFIG_BOOT_ROM_LOG_ALWAYS_OFF=y", defaults)

    def test_diagnostics_boundary_uses_fresh_ll_deadline_before_stdio_delimiter(self) -> None:
        source = APP_MAIN.read_text(encoding="utf-8")
        self.assertIn("wait_for_screen_snapshot_tx_fifo_writable", source)
        self.assertIn("usb_serial_jtag_ll_txfifo_writable()", source)
        self.assertIn("kScreenSnapshotTxBoundaryTimeoutUs", source)
        self.assertIn("esp_timer_get_time()", source)

        boundary_start = source.index("bool synchronize_screen_snapshot_response_boundary")
        boundary_end = source.index("enum class ScreenSnapshotRequestKind", boundary_start)
        boundary = source[boundary_start:boundary_end]
        wait_call = boundary.index("wait_for_screen_snapshot_tx_fifo_writable()")
        delimiter = boundary.index("fputc('\\n', stdout)")
        fflush_call = boundary.index("fflush(stdout)", delimiter)
        fsync_call = boundary.index("fsync(STDOUT_FILENO)", fflush_call)
        self.assertLess(wait_call, delimiter)
        self.assertLess(delimiter, fflush_call)
        self.assertLess(fflush_call, fsync_call)
        self.assertNotIn("pre_fsync_result", boundary)

    def test_sticky_file_error_is_not_cleared_or_used_as_fresh_boundary_evidence(self) -> None:
        source = APP_MAIN.read_text(encoding="utf-8")
        boundary_start = source.index("bool synchronize_screen_snapshot_response_boundary")
        boundary_end = source.index("enum class ScreenSnapshotRequestKind", boundary_start)
        boundary = source[boundary_start:boundary_end]
        self.assertNotIn("clearerr(stdout)", boundary)
        self.assertNotIn("ferror(stdout)", boundary)

    def test_diagnostics_boundary_is_test_only_and_fail_closed(self) -> None:
        source = APP_MAIN.read_text(encoding="utf-8")
        self.assertIn("synchronize_screen_snapshot_response_boundary", source)
        self.assertIn("if (!synchronize_screen_snapshot_response_boundary())", source)
        diagnostics_start = source.index("#if M5AUTH_TEST_SCREEN_SNAPSHOT")
        boundary_def = source.index("synchronize_screen_snapshot_response_boundary")
        diagnostics_end = source.index("#endif", boundary_def)
        self.assertLess(diagnostics_start, boundary_def)
        self.assertLess(boundary_def, diagnostics_end)

    def test_boundary_precedes_current_response_without_changing_response_body(self) -> None:
        source = APP_MAIN.read_text(encoding="utf-8")
        call = source.index("if (!synchronize_screen_snapshot_response_boundary())")
        write = source.index("write_response(response", call)
        self.assertLess(call, write)
        self.assertIn("return;", source[call:write])

    def test_production_default_off_boundary_remains_present(self) -> None:
        source = APP_MAIN.read_text(encoding="utf-8")
        self.assertIn("#if M5AUTH_TEST_SCREEN_SNAPSHOT", source)
        self.assertIn("#ifndef M5AUTH_TEST_SCREEN_SNAPSHOT", source)
        self.assertIn("#define M5AUTH_TEST_SCREEN_SNAPSHOT 0", source)


if __name__ == "__main__":
    unittest.main()
