from __future__ import annotations

import argparse
import json
import time
from typing import Any

import serial


REQUEST_ID = 9002
REQUEST = b'{"v":2,"id":9002,"op":"diagnostics.tx_boundary","params":{}}\n'
ALLOWED_FIELDS = (
    "count",
    "stage",
    "handler_us",
    "input_wipe_us",
    "fwrite_us",
    "newline_us",
    "fflush_us",
    "total_write_us",
    "response_bytes",
    "fwrite_bytes",
    "newline_ok",
    "fflush_ok",
    "ferror",
    "connected_before_write",
    "connected_after_fwrite",
    "connected_after_newline",
    "connected_after_flush",
    "txfifo_before_write",
    "txfifo_after_fwrite",
    "txfifo_after_newline",
    "txfifo_after_flush",
    "stack_hwm_before_write",
    "stack_hwm_after_flush",
    "reset_reason",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read the non-secret #86 TX-boundary RTC snapshot. "
            "Close Chrome/Web Serial before running this helper."
        )
    )
    parser.add_argument("--port", default="COM8", help="Serial port (default: COM8)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Read deadline in seconds")
    return parser.parse_args()


def valid_numeric(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def main() -> int:
    args = parse_args()

    port = serial.Serial()
    port.port = args.port
    port.baudrate = 115200
    port.timeout = 0.1
    port.write_timeout = 1
    port.dtr = False
    port.rts = False

    try:
        port.open()
        time.sleep(0.15)
        port.reset_input_buffer()
        port.write(REQUEST)
        port.flush()

        deadline = time.monotonic() + max(0.5, args.timeout)
        pending = b""
        while time.monotonic() < deadline:
            chunk = port.read(port.in_waiting or 1)
            if not chunk:
                continue
            pending += chunk
            if len(pending) > 8192:
                raise RuntimeError("Probe response exceeded the bounded local buffer")

            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                try:
                    obj = json.loads(line.decode("utf-8", "strict").strip())
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(obj, dict) or obj.get("id") != REQUEST_ID:
                    continue
                if obj.get("ok") is not True or not isinstance(obj.get("data"), dict):
                    raise RuntimeError("Device did not return the enabled TX-boundary snapshot")

                data = obj["data"]
                if set(data) != set(ALLOWED_FIELDS):
                    raise RuntimeError("Probe response field set did not match the non-secret allowlist")
                if not all(valid_numeric(data[name]) for name in ALLOWED_FIELDS):
                    raise RuntimeError("Probe response contained a non-numeric or invalid value")

                print("ISSUE86_TX_BOUNDARY_PROBE=PASS")
                for name in ALLOWED_FIELDS:
                    print(f"{name}={data[name]}")
                return 0

        raise RuntimeError("No matching TX-boundary diagnostic response before the local deadline")
    except (OSError, serial.SerialException, RuntimeError) as exc:
        print(f"ISSUE86_TX_BOUNDARY_PROBE=FAIL: {exc}")
        return 1
    finally:
        if port.is_open:
            port.close()


if __name__ == "__main__":
    raise SystemExit(main())
