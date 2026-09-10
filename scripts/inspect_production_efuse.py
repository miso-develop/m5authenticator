#!/usr/bin/env python3
"""Read-only, redacted inspection of ESP32-S3 key eFuses for Task #26."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = REPO_ROOT / "firmware" / "release-profile.json"
KEY_COUNT = 6


class InspectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class SlotInspection:
    key_id: int
    state: str
    purpose: str
    read_protected: bool
    key_write_protected: bool
    purpose_write_protected: bool


def _require_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InspectionError(f"missing or invalid eFuse field: {name}")
    return value


def _require_bool(item: dict[str, Any], field: str, name: str) -> bool:
    value = item.get(field)
    if not isinstance(value, bool):
        raise InspectionError(f"missing or invalid {field} for {name}")
    return value


def _purpose_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "UNKNOWN"
    return value.strip().upper()


def _raw_is_zero(item: dict[str, Any]) -> bool | None:
    raw = item.get("raw_value")
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    digits = raw[2:].lower()
    if not digits or any(ch not in "0123456789abcdef" for ch in digits):
        return None
    return all(ch == "0" for ch in digits)


def classify_slot(summary: dict[str, Any], key_id: int) -> SlotInspection:
    if key_id < 0 or key_id >= KEY_COUNT:
        raise InspectionError("key ID out of range")

    purpose_name = f"KEY_PURPOSE_{key_id}"
    block_name = f"BLOCK_KEY{key_id}"
    purpose_item = _require_dict(summary.get(purpose_name), purpose_name)
    block_item = _require_dict(summary.get(block_name), block_name)

    purpose = _purpose_name(purpose_item.get("value"))
    block_readable = _require_bool(block_item, "readable", block_name)
    block_writeable = _require_bool(block_item, "writeable", block_name)
    purpose_writeable = _require_bool(purpose_item, "writeable", purpose_name)
    raw_zero = _raw_is_zero(block_item) if block_readable else None

    read_protected = not block_readable
    key_write_protected = not block_writeable
    purpose_write_protected = not purpose_writeable

    if purpose == "HMAC_UP":
        state = (
            "reusable"
            if read_protected and key_write_protected and purpose_write_protected
            else "incompatible"
        )
    elif purpose == "USER":
        if raw_zero is True and block_writeable and purpose_writeable and block_readable:
            state = "free"
        elif raw_zero is None:
            state = "ambiguous"
        else:
            state = "incompatible"
    else:
        state = "incompatible"

    return SlotInspection(
        key_id=key_id,
        state=state,
        purpose=purpose,
        read_protected=read_protected,
        key_write_protected=key_write_protected,
        purpose_write_protected=purpose_write_protected,
    )


def load_selected_key(profile_path: Path = DEFAULT_PROFILE) -> int:
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InspectionError(f"cannot read release profile: {exc}") from exc
    if not isinstance(profile, dict) or profile.get("security_backend") != "hmac-efuse":
        raise InspectionError("release profile is not configured for hmac-efuse")
    key_id = profile.get("hmac_efuse_key_id")
    if not isinstance(key_id, int) or isinstance(key_id, bool) or not 0 <= key_id < KEY_COUNT:
        raise InspectionError("release profile has invalid hmac_efuse_key_id")
    return key_id


def resolve_port(explicit: str | None) -> str:
    value = explicit if explicit is not None else os.environ.get("M5AUTH_PORT")
    if not isinstance(value, str) or not value.strip():
        raise InspectionError("serial port is required; pass --port or load M5AUTH_PORT from .env")
    return value.strip()


def _find_tool(explicit: str | None) -> str:
    if explicit:
        return explicit
    for candidate in ("espefuse", "espefuse.py"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise InspectionError("espefuse was not found; run this from an ESP-IDF 5.5.5 shell or pass --tool")


def _tool_prefix(executable: str) -> list[str]:
    return [sys.executable, executable] if Path(executable).suffix.lower() == ".py" else [executable]


def parse_summary_json(output: str) -> dict[str, Any]:
    start = output.find("{")
    end = output.rfind("}")
    if start < 0 or end < start:
        raise InspectionError("espefuse did not return JSON summary data")
    try:
        data = json.loads(output[start : end + 1])
    except json.JSONDecodeError as exc:
        raise InspectionError("espefuse returned invalid JSON summary data") from exc
    if not isinstance(data, dict):
        raise InspectionError("espefuse JSON summary is not an object")
    return data


def read_summary(port: str, tool: str | None = None) -> dict[str, Any]:
    executable = _find_tool(tool)
    fields: list[str] = []
    for key_id in range(KEY_COUNT):
        fields.extend((f"KEY_PURPOSE_{key_id}", f"BLOCK_KEY{key_id}"))
    command = [
        *_tool_prefix(executable),
        "--port",
        port,
        "summary",
        "--format",
        "json",
        *fields,
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        suffix = f": {detail[-1][:200]}" if detail else ""
        raise InspectionError(f"espefuse summary failed{suffix}")
    return parse_summary_json(completed.stdout)


def evaluate(slots: list[SlotInspection], selected_key_id: int) -> tuple[str, str]:
    selected = next((slot for slot in slots if slot.key_id == selected_key_id), None)
    if selected is None:
        raise InspectionError("selected key slot is missing from inspection")

    other_hmac = [
        slot.key_id
        for slot in slots
        if slot.key_id != selected_key_id and slot.purpose == "HMAC_UP"
    ]
    if selected.state == "free" and other_hmac:
        names = ", ".join(f"KEY{key_id}" for key_id in other_hmac)
        return (
            "blocked-review-existing-hmac",
            f"configured KEY{selected_key_id} is free, but HMAC_UP exists in {names}; verify ownership before any burn",
        )
    if selected.state == "free":
        return (
            "first-time-init-candidate",
            f"configured KEY{selected_key_id} is structurally free; continue only to Web non-destructive preflight",
        )
    if selected.state == "reusable":
        return (
            "reusable-key-present",
            f"configured KEY{selected_key_id} is fully protected HMAC_UP; normal boot should reuse it and no burn is allowed",
        )
    return (
        "blocked",
        f"configured KEY{selected_key_id} is {selected.state}; do not initialize or change slots by trial and error",
    )


def format_report(slots: list[SlotInspection], selected_key_id: int) -> str:
    verdict, explanation = evaluate(slots, selected_key_id)
    lines = [
        "M5Authenticator production eFuse inspection (read-only/redacted)",
        f"configured_hmac_key_id={selected_key_id}",
    ]
    for slot in slots:
        lines.append(
            f"KEY{slot.key_id}: state={slot.state} purpose={slot.purpose} "
            f"read_protected={'yes' if slot.read_protected else 'no'} "
            f"key_write_protected={'yes' if slot.key_write_protected else 'no'} "
            f"purpose_write_protected={'yes' if slot.purpose_write_protected else 'no'}"
        )
    lines.extend(
        (
            f"verdict={verdict}",
            f"detail={explanation}",
            "No eFuse key values were printed or saved by this helper.",
            "This helper never performs a burn operation.",
        )
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read and redact ESP32-S3 key eFuse state without programming eFuse."
    )
    parser.add_argument(
        "--port",
        help="Serial port, for example COM7 or /dev/ttyACM0; defaults to M5AUTH_PORT",
    )
    parser.add_argument("--tool", help="Optional explicit path/name for espefuse or espefuse.py")
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    args = parser.parse_args()

    try:
        port = resolve_port(args.port)
        selected_key_id = load_selected_key(args.profile)
        summary = read_summary(port, args.tool)
        slots = [classify_slot(summary, key_id) for key_id in range(KEY_COUNT)]
        verdict, _ = evaluate(slots, selected_key_id)
        print(format_report(slots, selected_key_id))
    except InspectionError as exc:
        print(f"inspection failed: {exc}")
        return 2

    return 0 if verdict in {"first-time-init-candidate", "reusable-key-present"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
