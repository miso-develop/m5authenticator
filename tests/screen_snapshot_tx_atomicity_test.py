from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_MAIN = ROOT / "firmware/main/app_main.cpp"
TRANSPORT_CPP = ROOT / "firmware/main/usb_protocol_transport.cpp"


def extract_braced_block(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated C++ block for {signature}")


class ScreenSnapshotTxAtomicityTest(unittest.TestCase):
    def test_response_and_newline_are_one_driver_owned_logical_frame(self) -> None:
        transport = TRANSPORT_CPP.read_text(encoding="utf-8")
        writer = extract_braced_block(transport, "bool UsbProtocolTransport::write_frame(")

        self.assertIn("std::string frame", writer)
        self.assertIn("frame.append(response.data(), response.size())", writer)
        self.assertIn("frame.push_back('\\n')", writer)
        self.assertIn("usb_serial_jtag_write_bytes", writer)
        self.assertIn("usb_serial_jtag_wait_tx_done", writer)
        self.assertNotIn("stdout", writer)
        self.assertNotIn("fwrite", writer)

    def test_driver_write_loops_until_whole_frame_and_then_waits_for_tx_done(self) -> None:
        transport = TRANSPORT_CPP.read_text(encoding="utf-8")
        writer = extract_braced_block(transport, "bool UsbProtocolTransport::write_frame(")

        loop = writer.index("while (offset < frame.size())")
        write = writer.index("usb_serial_jtag_write_bytes", loop)
        offset = writer.index("offset += static_cast<std::size_t>(written)", write)
        done = writer.index("usb_serial_jtag_wait_tx_done", offset)

        self.assertLess(loop, write)
        self.assertLess(write, offset)
        self.assertLess(offset, done)
        self.assertIn("kUsbProtocolWriteTimeoutMs", writer)
        self.assertIn("if (written <= 0", writer)

    def test_tx_hardening_does_not_change_diagnostic_compile_gate(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        self.assertIn("#ifndef M5AUTH_TEST_SCREEN_SNAPSHOT", app)
        self.assertIn("#if M5AUTH_TEST_SCREEN_SNAPSHOT", app)
        self.assertIn("constexpr bool kTestScreenSnapshotEnabled", app)

    def test_writer_records_driver_frame_success_without_stdio(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        writer = extract_braced_block(app, "bool write_response(")
        self.assertIn("g_protocol_transport.write_frame(response)", writer)
        self.assertIn("sample.response_bytes = response.size();", writer)
        self.assertIn("sample.newline_ok = write_ok ? 1 : 0;", writer)
        self.assertIn("sample.fflush_ok = write_ok ? 1 : 0;", writer)
        for forbidden in ("std::fwrite", "std::fflush", "::fsync", "stdout"):
            self.assertNotIn(forbidden, writer)


if __name__ == "__main__":
    unittest.main()
