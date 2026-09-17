import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_MAIN = ROOT / "firmware" / "main" / "app_main.cpp"
TRANSPORT_CPP = ROOT / "firmware" / "main" / "usb_protocol_transport.cpp"
MAIN_CMAKE = ROOT / "firmware" / "main" / "CMakeLists.txt"
SDKCONFIG_DEFAULTS = ROOT / "firmware" / "sdkconfig.defaults"

TX_FLUSH_TIMEOUT_US = 50_000


class UsbCdcTransactionModel:
    """Historical model for the no-driver 64-byte USB transfer edge."""

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
    """Historical model of the v5.5.5 no-driver last_tx_ts failure mode."""
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
    if initially_writable:
        return True
    return (now_us - last_tx_ts_us) < TX_FLUSH_TIMEOUT_US


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


class Exact64UsbBoundaryModelTest(unittest.TestCase):
    RESPONSE = b'{"v":2,"id":7,"ok":true,"data":{"screen":"LOCKED"}}\n'

    def _stale(self, length: int) -> bytes:
        return b"S" * length

    def test_exactly_64_byte_stale_tx_can_join_later_valid_response_without_zlp(self) -> None:
        model = UsbCdcTransactionModel()
        model.emit_flushed_transfer(self._stale(64))
        model.open_listener()
        self.assertEqual(model.purge_host_queue(), b"")
        model.emit_flushed_transfer(self.RESPONSE)
        self.assertEqual(model.read_host_queue(), self._stale(64) + self.RESPONSE)

    def test_exactly_64_byte_stale_tx_plus_zlp_becomes_purgeable(self) -> None:
        model = UsbCdcTransactionModel()
        model.emit_flushed_transfer(self._stale(64))
        model.finalize_with_zlp()
        model.open_listener()
        self.assertEqual(model.purge_host_queue(), self._stale(64))
        model.emit_flushed_transfer(self.RESPONSE)
        self.assertEqual(model.read_host_queue(), self.RESPONSE)


class ScreenSnapshotTransportBoundarySourceContractTest(unittest.TestCase):
    def test_production_console_and_software_logging_are_disabled_without_efuse(self) -> None:
        defaults = SDKCONFIG_DEFAULTS.read_text(encoding="utf-8")
        self.assertIn("CONFIG_ESP_CONSOLE_NONE=y", defaults)
        self.assertIn("CONFIG_ESP_CONSOLE_SECONDARY_NONE=y", defaults)
        self.assertIn("CONFIG_BOOTLOADER_LOG_LEVEL_NONE=y", defaults)
        self.assertIn("CONFIG_LOG_DEFAULT_LEVEL_NONE=y", defaults)
        self.assertNotIn("CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y", defaults)
        self.assertNotIn("CONFIG_BOOT_ROM_LOG_ALWAYS_OFF=y", defaults)
        self.assertNotIn("efuse", defaults.lower())

    def test_snapshot_transport_uses_public_driver_not_private_hal_or_stdio(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        transport = TRANSPORT_CPP.read_text(encoding="utf-8")
        cmake = MAIN_CMAKE.read_text(encoding="utf-8")

        self.assertNotIn('"hal/usb_serial_jtag_ll.h"', app)
        self.assertNotIn("usb_serial_jtag_ll_", app)
        self.assertNotIn("flockfile", app)
        self.assertNotIn("fsync(", app)
        self.assertNotIn("fwrite(", app)
        self.assertIn("usb_serial_jtag_driver_install", transport)
        self.assertIn("usb_serial_jtag_write_bytes", transport)
        self.assertIn("usb_serial_jtag_wait_tx_done", transport)
        self.assertNotIn("hal\n", cmake)

    def test_driver_writer_terminates_and_completes_each_logical_frame(self) -> None:
        transport = TRANSPORT_CPP.read_text(encoding="utf-8")
        start = transport.index("bool UsbProtocolTransport::write_frame")
        end = transport.index("bool UsbProtocolTransport::connected", start)
        writer = transport[start:end]

        append = writer.index("frame.append(response.data(), response.size())")
        newline = writer.index("frame.push_back('\\n')", append)
        write = writer.index("usb_serial_jtag_write_bytes", newline)
        done = writer.index("usb_serial_jtag_wait_tx_done", write)
        self.assertLess(append, newline)
        self.assertLess(newline, write)
        self.assertLess(write, done)
        self.assertIn("kUsbProtocolWriteTimeoutMs", writer)
        self.assertIn("return completed;", writer)

    def test_snapshot_response_uses_same_protocol_owned_writer(self) -> None:
        source = APP_MAIN.read_text(encoding="utf-8")
        marker = "const ScreenSnapshotRequestParse snapshot_request = parse_screen_snapshot_request(request);"
        start = source.index(marker)
        end = source.index("const TimingOperation timing_operation", start)
        dispatch = source[start:end]
        self.assertIn("write_response(response)", dispatch)
        self.assertIn("fail_transport_session(protocol)", dispatch)
        self.assertNotIn("synchronize_screen_snapshot_response_boundary", source)
        self.assertNotIn("wait_for_screen_snapshot_tx_fifo_writable", source)

    def test_production_default_off_diagnostic_gate_remains_present(self) -> None:
        source = APP_MAIN.read_text(encoding="utf-8")
        self.assertIn("#if M5AUTH_TEST_SCREEN_SNAPSHOT", source)
        self.assertIn("#ifndef M5AUTH_TEST_SCREEN_SNAPSHOT", source)
        self.assertIn("#define M5AUTH_TEST_SCREEN_SNAPSHOT 0", source)


if __name__ == "__main__":
    unittest.main()
