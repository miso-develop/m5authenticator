#!/usr/bin/env python3
"""Read the #117 test-only sanitized screen snapshot over USB Serial/JTAG.

This helper sends exactly one read-only Protocol-v2 diagnostic request and prints
exactly one validated JSON response line. It never sends session, unlock, Vault,
time-sync, reset, or other state-changing operations.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


REQUEST_TEXT = '{"v":2,"id":9002,"op":"diagnostics.screen_snapshot","params":{}}'
REQUEST_BYTES = (REQUEST_TEXT + "\n").encode("ascii")

_ALLOWED_DATA_KEYS = {
    "runtime_state",
    "trusted_time_readiness",
    "presence",
    "screen_mode",
}
_ALLOWED_PRESENCE_KEYS = {"active", "confirmed", "operation"}
_ALLOWED_RUNTIME_STATES = {
    "unprovisioned",
    "reprovision_required",
    "locked",
    "unlocked",
    "error",
}
_ALLOWED_TIME_READINESS = {"not_synced", "ready", "stale"}
_ALLOWED_PRESENCE_OPERATIONS = {
    "none",
    "trusted_browser_unlock",
    "initial_provisioning",
    "recovery",
    "browser_replacement",
    "vmk_rekey",
    "factory_reset",
}
_ALLOWED_SCREEN_MODES = {
    "unlock_request",
    "vault_unavailable",
    "open_web",
    "no_accounts",
    "otp_revealed",
    "account_view",
}


def _require_exact_keys(value: dict[str, Any], expected: set[str], where: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(f"unexpected {where} keys: {sorted(actual)}")


def validate_response(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("response is not a JSON object")
    if value.get("v") != 2 or value.get("id") != 9002:
        raise ValueError("unexpected protocol version or response id")
    if value.get("ok") is not True:
        raise ValueError("diagnostic response was not successful")
    _require_exact_keys(value, {"v", "id", "ok", "data"}, "top-level")

    data = value.get("data")
    if not isinstance(data, dict):
        raise ValueError("data is not an object")
    _require_exact_keys(data, _ALLOWED_DATA_KEYS, "data")

    runtime_state = data.get("runtime_state")
    readiness = data.get("trusted_time_readiness")
    screen_mode = data.get("screen_mode")
    if runtime_state not in _ALLOWED_RUNTIME_STATES:
        raise ValueError("unexpected runtime_state")
    if readiness not in _ALLOWED_TIME_READINESS:
        raise ValueError("unexpected trusted_time_readiness")
    if screen_mode not in _ALLOWED_SCREEN_MODES:
        raise ValueError("unexpected screen_mode")

    presence = data.get("presence")
    if not isinstance(presence, dict):
        raise ValueError("presence is not an object")
    _require_exact_keys(presence, _ALLOWED_PRESENCE_KEYS, "presence")
    if not isinstance(presence.get("active"), bool):
        raise ValueError("presence.active is not boolean")
    if not isinstance(presence.get("confirmed"), bool):
        raise ValueError("presence.confirmed is not boolean")
    if presence.get("operation") not in _ALLOWED_PRESENCE_OPERATIONS:
        raise ValueError("unexpected presence.operation")

    return value


def read_snapshot(port_name: str, timeout_seconds: float) -> dict[str, Any]:
    try:
        import serial
        from serial import SerialException
    except ImportError as exc:  # pragma: no cover - environment guidance only
        raise RuntimeError(
            "pyserial is required; run from the activated ESP-IDF Python environment"
        ) from exc

    try:
        with serial.Serial(
            port=port_name,
            baudrate=115200,
            timeout=timeout_seconds,
            write_timeout=timeout_seconds,
            rtscts=False,
            dsrdtr=False,
        ) as port:
            port.write(REQUEST_BYTES)
            port.flush()
            raw = port.readline()
    except SerialException as exc:
        raise RuntimeError(
            "could not open/read the serial port; close Web Serial, idf.py monitor, "
            "and any other process that owns the COM/serial port, then retry"
        ) from exc

    if not raw:
        raise RuntimeError("no response line received before timeout")
    if b"\n" in raw[:-1] or b"\r" in raw[:-2]:
        raise RuntimeError("response contained unexpected embedded line breaks")

    try:
        line = raw.rstrip(b"\r\n").decode("utf-8", errors="strict")
        parsed = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("response was not valid one-line UTF-8 JSON") from exc

    try:
        return validate_response(parsed)
    except ValueError as exc:
        raise RuntimeError(f"response failed sanitized allowlist validation: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read #117 test-only sanitized M5StickS3 screen snapshot"
    )
    parser.add_argument("--port", required=True, help="Serial port, e.g. COM8 or /dev/ttyACM0")
    parser.add_argument("--timeout", type=float, default=3.0, help="Read/write timeout seconds")
    args = parser.parse_args()

    try:
        response = read_snapshot(args.port, args.timeout)
    except RuntimeError as exc:
        print(f"SCREEN_SNAPSHOT=FAIL: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(response, separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
