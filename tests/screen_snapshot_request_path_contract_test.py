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


class ScreenSnapshotRequestPathContractTest(unittest.TestCase):
    def test_diagnostic_parser_copies_rx_text_only_for_parsing_and_never_prints_it(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        parser = extract_braced_block(
            app,
            "ScreenSnapshotRequestParse parse_screen_snapshot_request(std::string_view line)",
        )
        self.assertIn("const std::string diagnostic_json(line);", parser)
        self.assertIn("cJSON_ParseWithLengthOpts", parser)
        for forbidden in (
            "printf(",
            "fprintf(",
            "fwrite(",
            "fputs(",
            "puts(",
            "ESP_LOG",
            "M5.Log",
            "stdout",
            "stderr",
        ):
            self.assertNotIn(forbidden, parser)

    def test_request_view_and_response_have_separate_storage_and_rx_is_wiped_before_tx(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        request_decl = "const std::string_view request(input.data(), length);"
        marker = "const ScreenSnapshotRequestParse snapshot_request = parse_screen_snapshot_request(request);"
        request_index = app.index(request_decl)
        marker_index = app.index(marker, request_index)
        end = app.index("const TimingOperation timing_operation", marker_index)
        dispatch = app[marker_index:end]

        self.assertIn("std::string response;", dispatch)
        self.assertIn("screen_snapshot_response(snapshot_request.id, snapshot)", dispatch)
        self.assertIn("consume_input_prefix(input, &buffered_input, consumed);", dispatch)
        self.assertIn("write_response(response)", dispatch)

        response_decl = dispatch.index("std::string response;")
        consume = dispatch.index("consume_input_prefix(input, &buffered_input, consumed);")
        write = dispatch.index("write_response(response)", consume)
        self.assertLess(response_decl, consume)
        self.assertLess(consume, write)

        helper = extract_braced_block(app, "void consume_input_prefix(")
        self.assertIn("std::memmove", helper)
        self.assertIn("m5auth::vault_runtime::secure_zero(", helper)
        self.assertIn("*buffered_input = remaining;", helper)

        # request is a view over the bounded RX vector; response is independent
        # storage produced before the consumed request bytes are securely removed.
        self.assertIn("std::vector<char> input(", app)
        self.assertLess(app.index("std::vector<char> input("), request_index)
        self.assertNotIn("response.assign(input", dispatch)
        self.assertNotIn("response.append(input", dispatch)
        self.assertNotIn("write_response(request", dispatch)

    def test_driver_rx_path_has_no_application_echo_before_diagnostic_dispatch(self) -> None:
        app = APP_MAIN.read_text(encoding="utf-8")
        loop_start = app.index("while (true) {")
        marker = app.index(
            "const ScreenSnapshotRequestParse snapshot_request = parse_screen_snapshot_request(request);",
            loop_start,
        )
        rx_path = app[loop_start:marker]

        for forbidden in (
            "write_response(request",
            "std::fwrite(input",
            "std::fputs(input",
            "std::printf(input",
            "std::fprintf(stdout, input",
            "std::fprintf(stderr, input",
            "ESP_LOG",
        ):
            self.assertNotIn(forbidden, rx_path)
        self.assertIn("g_protocol_transport.read(", rx_path)
        self.assertIn("secure_zero(input.data(), input.size())", rx_path)


if __name__ == "__main__":
    unittest.main()
