import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_MAIN = ROOT / "firmware" / "main" / "app_main.cpp"
SDKCONFIG_DEFAULTS = ROOT / "firmware" / "sdkconfig.defaults"


class UsbCdcTransactionModel:
    """Small behavioral model for the ESP32-S3 64-byte CDC transaction edge.

    A transfer whose last packet is exactly 64 bytes remains unterminated until
    a short packet or ZLP is emitted. A terminated transfer can become visible
    when a host listener opens; an unterminated full packet cannot be purged by
    the host because it is not yet in the host serial receive queue.
    """

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

    def test_finalize_after_listener_open_allows_host_purge_before_response(self) -> None:
        model = UsbCdcTransactionModel()
        model.emit_flushed_transfer(self._stale(64))
        model.open_listener()
        self.assertEqual(model.purge_host_queue(), b"")

        model.finalize_with_zlp()
        self.assertEqual(model.purge_host_queue(), self._stale(64))
        model.emit_flushed_transfer(self.RESPONSE)
        self.assertEqual(model.read_host_queue(), self.RESPONSE)

    def test_listener_time_delimiter_separates_stale_packet_from_response(self) -> None:
        model = UsbCdcTransactionModel()
        model.emit_flushed_transfer(self._stale(64))
        model.open_listener()

        model.emit_flushed_transfer(b"\n")
        first_line = model.read_host_queue()
        self.assertEqual(first_line, self._stale(64) + b"\n")

        model.emit_flushed_transfer(self.RESPONSE)
        self.assertEqual(model.read_host_queue(), self.RESPONSE)

    def test_clean_response_is_unchanged(self) -> None:
        model = UsbCdcTransactionModel()
        model.open_listener()
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

    def test_diagnostics_boundary_is_test_only_and_fail_closed(self) -> None:
        source = APP_MAIN.read_text(encoding="utf-8")
        self.assertIn("synchronize_screen_snapshot_response_boundary", source)
        self.assertIn("fputc('\\n', stdout)", source)
        self.assertIn("fflush(stdout)", source)
        self.assertIn("fsync(STDOUT_FILENO)", source)
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
