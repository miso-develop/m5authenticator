#!/usr/bin/env python3
"""Fail closed if a release firmware image contains retired credential surfaces."""

from __future__ import annotations

import argparse
from pathlib import Path


FORBIDDEN_MARKERS: tuple[bytes, ...] = (
    b"accounts.list",
    b"import.begin",
    b"import.item",
    b"import.validate",
    b"import.commit",
    b"account.rename",
    b"account.delete",
    b"accounts.reorder",
    b"selection.get",
    b"selection.set",
    b"wifi.status",
    b"wifi.set",
    b"wifi.clear",
    b"factory.reset",
    b"DevSecurityBackend",
    b"development-synthetic",
)


def verify_firmware_image(path: Path) -> None:
    try:
        image = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"cannot read firmware image: {exc}") from exc
    if not image:
        raise RuntimeError("firmware image is empty")

    present = [marker.decode("ascii") for marker in FORBIDDEN_MARKERS if marker in image]
    if present:
        raise RuntimeError(
            "release firmware contains retired credential/protocol surface: "
            + ", ".join(present)
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", type=Path)
    args = parser.parse_args()
    try:
        verify_firmware_image(args.firmware)
    except RuntimeError as exc:
        print(f"firmware image verification failed: {exc}")
        return 1
    print(f"firmware image security surface OK: {args.firmware}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
