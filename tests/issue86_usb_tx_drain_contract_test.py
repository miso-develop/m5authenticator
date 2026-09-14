from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_MAIN = ROOT / "firmware" / "main" / "app_main.cpp"


class Issue86UsbTxDrainContractTests(unittest.TestCase):
    def test_response_writer_drains_usb_vfs_after_stdio_flush(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        start = app.index("void write_response(")
        end = app.index("\nstd::string timing_diagnostics_response()", start)
        writer = app[start:end]

        self.assertIn("#include <unistd.h>", app)
        self.assertEqual(1, writer.count("::fsync(STDOUT_FILENO)"))

        fwrite = writer.index("std::fwrite(")
        newline = writer.index("std::fputc('\\n', stdout)")
        fflush = writer.index("std::fflush(stdout)")
        drain = writer.index("::fsync(STDOUT_FILENO)")
        ferror = writer.index("std::ferror(stdout)")

        self.assertLess(fwrite, newline)
        self.assertLess(newline, fflush)
        self.assertLess(fflush, drain)
        self.assertLess(drain, ferror)

    def test_fix_does_not_change_protocol_or_retry_semantics(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        self.assertIn("write_response(response, timing_operation);", app)
        self.assertIn("protocol.handle_line(", app)
        self.assertNotIn("retry_response", app)
        self.assertNotIn("retry_write", app)


if __name__ == "__main__":
    unittest.main()
