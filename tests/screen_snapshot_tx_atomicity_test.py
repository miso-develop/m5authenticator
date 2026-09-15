from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_MAIN = ROOT / "firmware/main/app_main.cpp"


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
    def test_response_and_newline_are_one_logical_stdio_write(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        writer = extract_braced_block(app, "void write_response(")

        self.assertIn("std::string frame", writer)
        self.assertIn("frame.append(response)", writer)
        self.assertIn("frame.push_back('\\n')", writer)
        self.assertIn("std::fwrite(frame.data(), 1, frame.size(), stdout)", writer)
        self.assertNotIn("std::fputc", writer)

    def test_stdout_file_lock_covers_frame_write_flush_and_fsync(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        writer = extract_braced_block(app, "void write_response(")

        lock = writer.index("::flockfile(stdout)")
        write = writer.index("std::fwrite(frame.data(), 1, frame.size(), stdout)")
        flush = writer.index("std::fflush(stdout)")
        sync = writer.index("::fsync(STDOUT_FILENO)")
        unlock = writer.index("::funlockfile(stdout)")

        self.assertLess(lock, write)
        self.assertLess(write, flush)
        self.assertLess(flush, sync)
        self.assertLess(sync, unlock)

    def test_tx_hardening_does_not_change_diagnostic_compile_gate(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        self.assertIn("#ifndef M5AUTH_TEST_SCREEN_SNAPSHOT", app)
        self.assertIn("#if M5AUTH_TEST_SCREEN_SNAPSHOT", app)
        self.assertIn("constexpr bool kTestScreenSnapshotEnabled", app)

    def test_writer_records_whole_frame_write_success(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        writer = extract_braced_block(app, "void write_response(")
        self.assertIn("fwrite_bytes == frame.size()", writer)
        self.assertIn("sample.response_bytes = response.size();", writer)
        self.assertIn("sample.newline_ok =", writer)


if __name__ == "__main__":
    unittest.main()
