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
_MAX_RESPONSE_LINE_BYTES = 4096
_MAX_PRE_REQUEST_DRAIN_BYTES = 8192
_PRE_REQUEST_QUIET_SECONDS = 0.20
_PRE_REQUEST_SYNC_MAX_SECONDS = 1.50
_OPERATION = "diagnostics.screen_snapshot"
_issued_request_ids: set[int] = set()
_collection_count = 0

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


def _request_id_pattern(request_id: int) -> bytes:
    return rb'"id"\s*:\s*' + str(request_id).encode("ascii") + rb'(?=\s*[,}])'


def _raw_mentions_request_id(raw: bytes, request_id: int) -> bool:
    # This is failure detection only, never success parsing. If malformed bytes
    # clearly carry the current ID token, fail closed rather than skipping a
    # possibly-corrupted current response as though it were stale. False positives
    # are safe because they can only turn the diagnostic into an explicit failure.
    return re.search(_request_id_pattern(request_id), raw) is not None


def _position_bucket(position: int | None, length: int) -> str:
    if position is None or length <= 0:
        return "unknown"
    fraction = position / length
    if fraction < 0.25:
        return "near-start"
    if fraction > 0.75:
        return "near-end"
    return "middle"


def _count_bucket(count: int) -> str:
    if count <= 0:
        return "none"
    if count == 1:
        return "one"
    return "multiple"


def _prefix_match_bucket(length: int) -> str:
    if length <= 0:
        return "none"
    if length <= 15:
        return "1-15"
    if length <= 31:
        return "16-31"
    if length <= 63:
        return "32-63"
    if length == 64:
        return "64"
    return "gt-64"


def _top_level_object_buckets(text: str) -> tuple[str, str]:
    """Count JSON-object-looking top-level brace pairs without exposing text."""
    starts = 0
    ends = 0
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                starts += 1
            depth += 1
        elif char == "}" and depth > 0:
            depth -= 1
            if depth == 0:
                ends += 1
    return _count_bucket(starts), _count_bucket(ends)


def _json_error_bucket(exc: ValueError, payload_length: int) -> str:
    cause = exc.__cause__
    if isinstance(cause, json.JSONDecodeError):
        return _position_bucket(cause.pos, payload_length)
    if isinstance(cause, UnicodeDecodeError):
        return _position_bucket(cause.start, payload_length)
    return "unknown"


def _timing_bucket(seconds: float | None) -> str:
    if seconds is None:
        return "none"
    if seconds <= 0.05:
        return "le-50ms"
    if seconds <= 0.25:
        return "51-250ms"
    return "gt-250ms"


def _pre_purge_waiting_presence(port: Any) -> str:
    try:
        waiting = getattr(port, "in_waiting")
    except Exception:
        return "unknown"
    if isinstance(waiting, bool) or not isinstance(waiting, int) or waiting < 0:
        return "unknown"
    return "yes" if waiting > 0 else "no"


def _format_pre_request_sync(sync: dict[str, Any]) -> str:
    """Format only structural/timing metadata; never include discarded serial data."""
    return (
        f"pre_purge_waiting={sync['pre_purge_waiting']},"
        f"pre_request_data={sync['pre_request_data']},"
        f"pre_request_bytes={sync['pre_request_bytes']},"
        f"pre_request_newline={sync['pre_request_newline']},"
        f"first_byte={sync['first_byte']},"
        f"quiet_ms={sync['quiet_ms']},"
        f"invocation={sync['invocation']}"
    )


def _synchronize_before_request(
    port: Any,
    *,
    now: Callable[[], float] = time.monotonic,
    invocation: str = "unknown",
) -> dict[str, Any]:
    """Drain late startup bytes and require bounded continuous quiet before request 1."""
    started = now()
    deadline = started + _PRE_REQUEST_SYNC_MAX_SECONDS
    pre_purge_waiting = _pre_purge_waiting_presence(port)

    # On Windows pySerial this purges the host driver RX queue only. It cannot
    # guarantee that bytes still pending in the Device USB TX path will not arrive
    # later, so continue draining until a continuous quiet condition is observed.
    reset_input = getattr(port, "reset_input_buffer", None)
    if callable(reset_input):
        reset_input()

    last_data_at = now()
    total_bytes = 0
    saw_newline = False
    first_byte_elapsed: float | None = None

    while True:
        current = now()
        quiet_seconds = max(0.0, current - last_data_at)
        if quiet_seconds >= _PRE_REQUEST_QUIET_SECONDS:
            return {
                "pre_purge_waiting": pre_purge_waiting,
                "pre_request_data": "yes" if total_bytes else "no",
                "pre_request_bytes": total_bytes,
                "pre_request_newline": "yes" if saw_newline else "no",
                "first_byte": _timing_bucket(first_byte_elapsed),
                "quiet_ms": int(quiet_seconds * 1000),
                "invocation": invocation,
            }
        if current >= deadline:
            sync = {
                "pre_purge_waiting": pre_purge_waiting,
                "pre_request_data": "yes" if total_bytes else "no",
                "pre_request_bytes": total_bytes,
                "pre_request_newline": "yes" if saw_newline else "no",
                "first_byte": _timing_bucket(first_byte_elapsed),
                "quiet_ms": int(quiet_seconds * 1000),
                "invocation": invocation,
            }
            raise RuntimeError(
                "pre-request synchronization did not reach quiet condition ("
                + _format_pre_request_sync(sync)
                + ")"
            )

        fragment = port.readline()
        after_read = now()
        if fragment:
            if first_byte_elapsed is None:
                first_byte_elapsed = max(0.0, after_read - started)
            total_bytes += len(fragment)
            saw_newline = saw_newline or b"\n" in fragment
            if total_bytes > _MAX_PRE_REQUEST_DRAIN_BYTES:
                sync = {
                    "pre_purge_waiting": pre_purge_waiting,
                    "pre_request_data": "yes",
                    "pre_request_bytes": total_bytes,
                    "pre_request_newline": "yes" if saw_newline else "no",
                    "first_byte": _timing_bucket(first_byte_elapsed),
                    "quiet_ms": 0,
                    "invocation": invocation,
                }
                raise RuntimeError(
                    "pre-request synchronization exceeded byte limit ("
                    + _format_pre_request_sync(sync)
                    + ")"
                )
            # Any newly-arrived data restarts the continuous quiet requirement.
            last_data_at = after_read


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


def _validate_error_response(value: Any, request_id: int) -> str:
    if not isinstance(value, dict):
        raise ValueError("error response is not an object")
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
    return str(code)


def _current_error(value: Any, request_id: int) -> RuntimeError:
    try:
        code = _validate_error_response(value, request_id)
    except ValueError:
        return RuntimeError("current diagnostic error response failed allowlist validation")
    return RuntimeError(f"Device diagnostic failed: {code}")


def _strict_current_response_allowlisted(value: Any, request_id: int) -> bool:
    if not isinstance(value, dict) or _response_id(value) != request_id:
        return False
    try:
        if value.get("ok") is True:
            validate_success_response(value, request_id)
        elif value.get("ok") is False:
            _validate_error_response(value, request_id)
        else:
            return False
    except ValueError:
        return False
    return True


def _analyze_malformed_relation(raw: bytes, request_id: int, request: bytes) -> dict[str, Any]:
    """Return request/prefix/suffix relations without retaining or formatting raw data."""
    payload = raw.rstrip(b"\r\n")
    candidates: list[tuple[int, Any]] = []
    for index, byte in enumerate(payload):
        if byte != ord("{"):
            continue
        try:
            candidates.append((index, _parse_json_line(payload[index:])))
        except ValueError:
            continue

    current_candidates = [
        (index, value)
        for index, value in candidates
        if _response_id(value) == request_id
    ]
    if current_candidates:
        suffix_start = current_candidates[0][0]
    elif candidates:
        suffix_start = candidates[0][0]
    else:
        first_brace = payload.find(b"{")
        suffix_start = first_brace if first_brace >= 0 else None

    prefix = payload[:suffix_start] if suffix_start is not None else None
    common_prefix = 0
    if prefix is not None:
        for prefix_byte, request_byte in zip(prefix, request):
            if prefix_byte != request_byte:
                break
            common_prefix += 1

    if prefix is None:
        prefix_equals_request_prefix = "unknown"
        prefix_equals_request_first64 = "unknown"
        match_bucket = "unknown"
        prefix_len: int | str = "unknown"
    else:
        prefix_len = len(prefix)
        prefix_equals_request_prefix = (
            "yes" if len(prefix) <= len(request) and prefix == request[: len(prefix)] else "no"
        )
        if len(request) < 64:
            prefix_equals_request_first64 = "not-applicable"
        else:
            prefix_equals_request_first64 = (
                "yes" if len(prefix) == 64 and prefix == request[:64] else "no"
            )
        match_bucket = _prefix_match_bucket(common_prefix)

    suffix_json_valid = "yes" if candidates else "no"
    suffix_id_matches_current = "yes" if current_candidates else "no"
    suffix_allowlist_valid = (
        "yes"
        if any(_strict_current_response_allowlisted(value, request_id) for _, value in current_candidates)
        else "no"
    )

    return {
        "request_len": len(request),
        "prefix_len": prefix_len,
        "prefix_equals_request_prefix": prefix_equals_request_prefix,
        "prefix_equals_request_first64": prefix_equals_request_first64,
        "request_prefix_match_len": match_bucket,
        "suffix_json_valid": suffix_json_valid,
        "suffix_id_matches_current": suffix_id_matches_current,
        "suffix_allowlist_valid": suffix_allowlist_valid,
    }


def _format_malformed_relation(relation: dict[str, Any]) -> str:
    """Format structural booleans/counts only; never include request/prefix/suffix bytes."""
    return (
        f"request_len={relation['request_len']},"
        f"prefix_len={relation['prefix_len']},"
        f"prefix_equals_request_prefix={relation['prefix_equals_request_prefix']},"
        f"prefix_equals_request_first64={relation['prefix_equals_request_first64']},"
        f"request_prefix_match_len={relation['request_prefix_match_len']},"
        f"suffix_json_valid={relation['suffix_json_valid']},"
        f"suffix_id_matches_current={relation['suffix_id_matches_current']},"
        f"suffix_allowlist_valid={relation['suffix_allowlist_valid']}"
    )


def _completed_malformed_diagnostics(
    raw: bytes,
    request_id: int,
    exc: ValueError,
    pre_request_sync: dict[str, Any] | None = None,
    request: bytes | None = None,
    post_request_first_byte: str = "unknown",
) -> str:
    """Return structural-only diagnostics; never include serial bytes or decoded text."""
    payload = raw.rstrip(b"\r\n")
    trimmed = payload.strip(b" \t\r\n")
    first_object = "yes" if trimmed.startswith(b"{") else "no"
    last_object = "yes" if trimmed.endswith(b"}") else "no"
    nul = "yes" if b"\x00" in payload else "no"
    control = "yes" if any(byte < 0x20 and byte != 0x09 for byte in payload) else "no"

    id_match = re.search(_request_id_pattern(request_id), payload)
    id_position = _position_bucket(id_match.start() if id_match else None, len(payload))
    json_error = _json_error_bucket(exc, len(payload))

    relation: dict[str, Any] | None = None
    if request is not None:
        relation = _analyze_malformed_relation(raw, request_id, request)
        prefix_len: int | str = relation["prefix_len"]
    else:
        first_brace = payload.find(b"{")
        prefix_len = first_brace if first_object == "no" and first_brace >= 0 else "unknown"

    text: str | None
    try:
        text = payload.decode("utf-8", errors="strict")
        utf8 = "valid"
    except UnicodeDecodeError:
        text = None
        utf8 = "invalid"

    object_starts = "unknown"
    object_ends = "unknown"
    has_decodable_suffix = False
    if text is not None:
        object_starts, object_ends = _top_level_object_buckets(text)
        stripped_text = text.lstrip()
        try:
            _, decoded_end = json.JSONDecoder().raw_decode(stripped_text)
            has_decodable_suffix = bool(stripped_text[decoded_end:].strip())
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    relation_is_current_prefix = (
        relation is not None
        and isinstance(relation["prefix_len"], int)
        and relation["prefix_len"] > 0
        and relation["suffix_json_valid"] == "yes"
        and relation["suffix_id_matches_current"] == "yes"
    )

    if utf8 == "invalid":
        shape = "invalid-utf8"
    elif object_starts == "multiple" and object_ends == "multiple":
        shape = "concatenated-objects"
    elif relation_is_current_prefix:
        shape = "prefix-contamination"
    elif first_object == "no" and id_match is not None:
        shape = "prefix-contamination"
    elif has_decodable_suffix:
        shape = "suffix-contamination"
    elif first_object == "yes" and last_object == "no":
        shape = "truncated-looking"
    elif first_object == "yes" and last_object == "yes":
        shape = "middle-interleave-corruption"
    else:
        shape = "unknown"

    relation_suffix = ""
    if relation is not None:
        relation_suffix = "," + _format_malformed_relation(relation)

    sync_suffix = ""
    if pre_request_sync is not None:
        sync_suffix = "," + _format_pre_request_sync(pre_request_sync)

    return (
        "current diagnostic response is malformed "
        f"(frame_len={len(raw)},utf8={utf8},first_object={first_object},"
        f"last_object={last_object},nul={nul},control={control},"
        f"json_error={json_error},id_position={id_position},prefix_len={prefix_len},"
        f"object_starts={object_starts},object_ends={object_ends},shape={shape},"
        f"post_request_first_byte={post_request_first_byte}"
        f"{relation_suffix}{sync_suffix})"
    )


def _format_timeout_diagnostics(
    *,
    post_request_data: bool,
    completed_lines: int,
    first_completed_frame_len: int | None,
    malformed_unrelated_lines: int,
    valid_wrong_id_lines: int,
    post_request_first_byte: str,
) -> str:
    """Format timeout-only structural metadata without any serial payload content."""
    return (
        f"post_request_data={'yes' if post_request_data else 'no'},"
        f"completed_lines={_count_bucket(completed_lines)},"
        f"first_completed_frame_len={first_completed_frame_len if first_completed_frame_len is not None else 'none'},"
        f"malformed_unrelated_lines={_count_bucket(malformed_unrelated_lines)},"
        f"valid_wrong_id_lines={_count_bucket(valid_wrong_id_lines)},"
        f"post_request_first_byte={post_request_first_byte}"
    )


def read_matching_response(
    port: Any,
    request_id: int,
    timeout_seconds: float,
    *,
    now: Callable[[], float] = time.monotonic,
    pre_request_sync: dict[str, Any] | None = None,
    request: bytes | None = None,
    request_sent_at: float | None = None,
) -> dict[str, Any]:
    deadline = now() + timeout_seconds
    pending = bytearray()
    post_request_first_byte = "unknown" if request_sent_at is None else "none"
    post_request_data = False
    completed_lines = 0
    first_completed_frame_len: int | None = None
    malformed_unrelated_lines = 0
    valid_wrong_id_lines = 0

    while now() < deadline:
        fragment = port.readline()
        after_read = now()
        if not fragment:
            # A per-read timeout does not terminate the overall collection window.
            # Preserve any partial frame and keep waiting until the overall deadline.
            continue

        post_request_data = True
        if request_sent_at is not None and post_request_first_byte == "none":
            post_request_first_byte = _timing_bucket(max(0.0, after_read - request_sent_at))

        pending.extend(fragment)

        while True:
            newline_index = pending.find(b"\n")
            if newline_index < 0:
                if len(pending) > _MAX_RESPONSE_LINE_BYTES:
                    raise RuntimeError("diagnostic response line exceeds maximum length")
                break

            frame_length = newline_index + 1
            if frame_length > _MAX_RESPONSE_LINE_BYTES:
                raise RuntimeError("diagnostic response line exceeds maximum length")

            raw = bytes(pending[:frame_length])
            del pending[:frame_length]
            completed_lines += 1
            if first_completed_frame_len is None:
                first_completed_frame_len = frame_length

            try:
                parsed = _parse_json_line(raw)
            except ValueError as exc:
                if _raw_mentions_request_id(raw, request_id):
                    raise RuntimeError(
                        _completed_malformed_diagnostics(
                            raw,
                            request_id,
                            exc,
                            pre_request_sync,
                            request,
                            post_request_first_byte,
                        )
                    ) from exc
                malformed_unrelated_lines += 1
                # A malformed stale/unrelated completed line cannot become evidence.
                # Keep waiting for a valid response carrying the fresh request ID.
                continue

            response_id = _response_id(parsed)
            if response_id != request_id:
                # Count only a strict allowlisted response carrying its own ID as a
                # valid wrong-ID frame. Other unrelated completed JSON is grouped
                # with malformed/unusable unrelated lines. Neither can be evidence.
                if response_id is not None and _strict_current_response_allowlisted(
                    parsed, response_id
                ):
                    valid_wrong_id_lines += 1
                else:
                    malformed_unrelated_lines += 1
                continue

            if not isinstance(parsed, dict) or parsed.get("ok") is not True:
                raise _current_error(parsed, request_id)
            try:
                return validate_success_response(parsed, request_id)
            except ValueError as exc:
                raise RuntimeError(
                    "current diagnostic response failed sanitized allowlist validation"
                ) from exc

    timeout_diagnostics = _format_timeout_diagnostics(
        post_request_data=post_request_data,
        completed_lines=completed_lines,
        first_completed_frame_len=first_completed_frame_len,
        malformed_unrelated_lines=malformed_unrelated_lines,
        valid_wrong_id_lines=valid_wrong_id_lines,
        post_request_first_byte=post_request_first_byte,
    )
    if pending:
        # Partial bytes are not malformed JSON: without a terminating newline the
        # frame is incomplete. Fail closed at the overall deadline without logging
        # or echoing any raw serial payload.
        raise RuntimeError(
            "diagnostic response line was incomplete before timeout ("
            + timeout_diagnostics
            + ")"
        )

    raise RuntimeError(
        "no valid response for the current request id before timeout ("
        + timeout_diagnostics
        + ")"
    )


def _validate_timeout_seconds(timeout_seconds: float) -> None:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise RuntimeError("timeout must be a finite positive number")


def _collect_snapshot(
    serial_module: Any,
    port_name: str,
    timeout_seconds: float,
    *,
    now: Callable[[], float] = time.monotonic,
    sync_reporter: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Collect one snapshot with an explicit fail-closed serial lifecycle."""
    _validate_timeout_seconds(timeout_seconds)

    global _collection_count
    _collection_count += 1
    invocation = "first" if _collection_count == 1 else "later"

    request_id = generate_request_id()
    request = build_request(request_id)
    per_read_timeout = min(max(timeout_seconds, 0.05), 0.25)

    port: Any | None = None
    result: dict[str, Any] | None = None
    primary_runtime_error: RuntimeError | None = None
    primary_io_error: Exception | None = None
    close_error: Exception | None = None

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

        # A host-side purge cannot remove bytes which are still pending in the
        # Device USB TX path. Drain after the purge and require continuous quiet
        # before sending request 1. This phase never sends a protocol request and
        # therefore is synchronization, not a retry or malformed-frame recovery.
        pre_request_sync = _synchronize_before_request(
            port,
            now=now,
            invocation=invocation,
        )
        if sync_reporter is not None:
            sync_reporter(_format_pre_request_sync(pre_request_sync))

        port.write(request)
        port.flush()
        request_sent_at = now()
        result = read_matching_response(
            port,
            request_id,
            timeout_seconds,
            now=now,
            pre_request_sync=pre_request_sync,
            request=request,
            request_sent_at=request_sent_at,
        )
    except RuntimeError as exc:
        primary_runtime_error = exc
    except Exception as exc:  # serial/OS read-write-open failures all fail closed
        primary_io_error = exc
    finally:
        if port is not None and bool(getattr(port, "is_open", False)):
            try:
                port.close()
            except Exception as exc:
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


def read_snapshot(
    port_name: str,
    timeout_seconds: float,
    *,
    sync_reporter: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    # Validate before importing/opening pySerial so invalid CLI values fail fast.
    _validate_timeout_seconds(timeout_seconds)
    try:
        import serial
    except ImportError as exc:  # pragma: no cover - environment guidance only
        raise RuntimeError(
            "pyserial is required; run from the activated ESP-IDF Python environment"
        ) from exc

    return _collect_snapshot(
        serial,
        port_name,
        timeout_seconds,
        sync_reporter=sync_reporter,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read #117 test-only sanitized M5StickS3 screen snapshot"
    )
    parser.add_argument("--port", required=True, help="Serial port, e.g. COM8 or /dev/ttyACM0")
    parser.add_argument("--timeout", type=float, default=3.0, help="Overall response timeout seconds")
    args = parser.parse_args()

    def report_sync(summary: str) -> None:
        # This line intentionally contains metadata only. It reports whether stale
        # data existed before request 1 without ever exposing the discarded bytes.
        print(f"SCREEN_SNAPSHOT_SYNC={summary}", file=sys.stderr)

    try:
        response = read_snapshot(
            args.port,
            args.timeout,
            sync_reporter=report_sync,
        )
    except RuntimeError as exc:
        print(f"SCREEN_SNAPSHOT=FAIL: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(response, separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
