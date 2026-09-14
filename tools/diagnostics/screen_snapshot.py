#!/usr/bin/env python3
"""Read the #117 test-only sanitized screen snapshot over USB Serial/JTAG.

Each invocation sends one read-only Protocol-v2 diagnostic request with a fresh
positive request ID. Only a response echoing that ID can become test evidence.
Stale, unrelated, or malformed prior lines are never printed as a snapshot.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import secrets
import sys
import time
from typing import Any, Callable


_MAX_REQUEST_ID = 2_000_000_000
_OPERATION = "diagnostics.screen_snapshot"
_issued_request_ids: set[int] = set()

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
_ALLOWED_ERROR_CODES = {
    "snapshot_not_ready",
    "invalid_request",
    "internal_error",
}


class _DuplicateJsonKey(ValueError):
    pass


def generate_request_id() -> int:
    """Return a fresh positive ID, never reused within this helper process."""
    while True:
        request_id = secrets.randbelow(_MAX_REQUEST_ID) + 1
        if request_id not in _issued_request_ids:
            _issued_request_ids.add(request_id)
            return request_id


def build_request(request_id: int) -> bytes:
    if isinstance(request_id, bool) or not isinstance(request_id, int):
        raise ValueError("request id must be an integer")
    if request_id <= 0 or request_id > _MAX_REQUEST_ID:
        raise ValueError("request id is outside the permitted range")
    payload = {
        "v": 2,
        "id": request_id,
        "op": _OPERATION,
        "params": {},
    }
    return (json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def _require_exact_keys(value: dict[str, Any], expected: set[str], where: str) -> None:
    if set(value) != expected:
        raise ValueError(f"unexpected {where} fields")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey("duplicate JSON key")
        value[key] = item
    return value


def _parse_json_line(raw: bytes) -> Any:
    if not raw:
        raise ValueError("empty response line")
    if b"\n" in raw[:-1] or b"\r" in raw[:-2]:
        raise ValueError("embedded line break")
    try:
        line = raw.rstrip(b"\r\n").decode("utf-8", errors="strict")
        return json.loads(line, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKey) as exc:
        raise ValueError("invalid one-line JSON") from exc


def _raw_mentions_request_id(raw: bytes, request_id: int) -> bool:
    # This is failure detection only, never success parsing. If malformed bytes
    # clearly carry the current ID token, fail closed rather than skipping a
    # possibly-corrupted current response as though it were stale. False positives
    # are safe because they can only turn the diagnostic into an explicit failure.
    pattern = rb'"id"\s*:\s*' + str(request_id).encode("ascii") + rb'(?=\s*[,}])'
    return re.search(pattern, raw) is not None


def _response_id(value: Any) -> int | None:
    if not isinstance(value, dict):
        return None
    response_id = value.get("id")
    if isinstance(response_id, bool) or not isinstance(response_id, int):
        return None
    return response_id


def validate_success_response(value: Any, request_id: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("response is not a JSON object")
    if value.get("v") != 2 or _response_id(value) != request_id:
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


def _current_error(value: Any, request_id: int) -> RuntimeError:
    if not isinstance(value, dict):
        return RuntimeError("current diagnostic response is malformed")
    try:
        _require_exact_keys(value, {"v", "id", "ok", "error"}, "error response")
        if value.get("v") != 2 or _response_id(value) != request_id or value.get("ok") is not False:
            raise ValueError("invalid error envelope")
        error = value.get("error")
        if not isinstance(error, dict):
            raise ValueError("error is not an object")
        _require_exact_keys(error, {"code"}, "error")
        code = error.get("code")
        if code not in _ALLOWED_ERROR_CODES:
            raise ValueError("unexpected error code")
    except ValueError:
        return RuntimeError("current diagnostic error response failed allowlist validation")
    return RuntimeError(f"Device diagnostic failed: {code}")


def read_matching_response(
    port: Any,
    request_id: int,
    timeout_seconds: float,
    *,
    now: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    deadline = now() + timeout_seconds
    while now() < deadline:
        raw = port.readline()
        if not raw:
            continue
        try:
            parsed = _parse_json_line(raw)
        except ValueError as exc:
            if _raw_mentions_request_id(raw, request_id):
                raise RuntimeError("current diagnostic response is malformed") from exc
            # A malformed stale/unrelated line cannot become evidence. Keep
            # waiting for a valid response carrying the current fresh request ID.
            continue

        response_id = _response_id(parsed)
        if response_id != request_id:
            # Delayed responses from previous helper runs are deliberately ignored.
            continue

        if not isinstance(parsed, dict) or parsed.get("ok") is not True:
            raise _current_error(parsed, request_id)
        try:
            return validate_success_response(parsed, request_id)
        except ValueError as exc:
            raise RuntimeError(
                "current diagnostic response failed sanitized allowlist validation"
            ) from exc

    raise RuntimeError("no valid response for the current request id before timeout")


def _validate_timeout_seconds(timeout_seconds: float) -> None:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise RuntimeError("timeout must be a finite positive number")


def _collect_snapshot(serial_module: Any, port_name: str, timeout_seconds: float) -> dict[str, Any]:
    """Collect one snapshot with an explicit fail-closed serial lifecycle."""
    _validate_timeout_seconds(timeout_seconds)

    request_id = generate_request_id()
    request = build_request(request_id)
    per_read_timeout = min(max(timeout_seconds, 0.05), 0.25)

    port: Any | None = None
    result: dict[str, Any] | None = None
    primary_runtime_error: RuntimeError | None = None
    primary_io_error: BaseException | None = None
    close_error: BaseException | None = None

    try:
        # pySerial applies the configured DTR/RTS states when open() runs. Build a
        # closed object first so the test helper never intentionally opens with the
        # library defaults (active/True). rtscts/dsrdtr only control flow-control
        # modes; the explicit line states below are the observational-safety guard.
        port = serial_module.Serial()
        port.port = port_name
        port.baudrate = 115200
        port.timeout = per_read_timeout
        port.write_timeout = timeout_seconds
        port.rtscts = False
        port.dsrdtr = False
        port.dtr = False
        port.rts = False
        port.open()

        # Purging is defense-in-depth only. Fresh request-ID matching below is the
        # primary freshness guarantee and remains required even if a driver cannot
        # purge or a delayed line arrives after this point.
        reset_input = getattr(port, "reset_input_buffer", None)
        if callable(reset_input):
            reset_input()
        port.write(request)
        port.flush()
        result = read_matching_response(port, request_id, timeout_seconds)
    except RuntimeError as exc:
        primary_runtime_error = exc
    except BaseException as exc:  # serial/OS read-write-open failures all fail closed
        primary_io_error = exc
    finally:
        if port is not None and bool(getattr(port, "is_open", False)):
            try:
                port.close()
            except BaseException as exc:
                close_error = exc

    if primary_runtime_error is not None:
        if close_error is not None:
            raise RuntimeError("serial snapshot failed and port close also failed") from close_error
        raise primary_runtime_error
    if primary_io_error is not None:
        if close_error is not None:
            raise RuntimeError("serial snapshot I/O failed and port close also failed") from close_error
        raise RuntimeError(
            "serial snapshot I/O failed; close Web Serial, idf.py monitor, and any "
            "other process that owns the COM/serial port, then retry"
        ) from primary_io_error
    if close_error is not None:
        # Test evidence is not accepted if lifecycle cleanup itself is ambiguous.
        raise RuntimeError("serial port close failed; snapshot evidence discarded") from close_error
    if result is None:
        raise RuntimeError("serial snapshot ended without validated evidence")
    return result


def read_snapshot(port_name: str, timeout_seconds: float) -> dict[str, Any]:
    # Validate before importing/opening pySerial so invalid CLI values fail fast.
    _validate_timeout_seconds(timeout_seconds)
    try:
        import serial
    except ImportError as exc:  # pragma: no cover - environment guidance only
        raise RuntimeError(
            "pyserial is required; run from the activated ESP-IDF Python environment"
        ) from exc

    return _collect_snapshot(serial, port_name, timeout_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read #117 test-only sanitized M5StickS3 screen snapshot"
    )
    parser.add_argument("--port", required=True, help="Serial port, e.g. COM8 or /dev/ttyACM0")
    parser.add_argument("--timeout", type=float, default=3.0, help="Overall response timeout seconds")
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
