#!/usr/bin/env python3
"""Render GitHub Pages candidate summaries without shell interpolation."""

from __future__ import annotations

import argparse
from pathlib import Path


def _inline_code(value: str) -> str:
    return "`" + value.replace("`", "\\`") + "`"


def append_candidate_authorization_summary(
    summary_path: Path,
    *,
    source_ref: str,
    source_sha: str,
    candidate_sha: str,
    current_main: str,
) -> None:
    lines = [
        "## PRE-RELEASE Pages candidate",
        "",
        f"- source ref: {_inline_code(source_ref)}",
        f"- source SHA: {_inline_code(source_sha)}",
        f"- candidate SHA: {_inline_code(candidate_sha)}",
        f"- current main: {_inline_code(current_main)}",
        "- this deployment is a mutable public candidate, not an immutable GitHub Release",
        "",
    ]
    with summary_path.open("a", encoding="utf-8") as output:
        output.write("\n".join(lines))


def append_candidate_build_identity(
    summary_path: Path,
    *,
    version: str,
    build_commit: str,
    exact_release: str,
) -> None:
    if exact_release not in {"true", "false"}:
        raise ValueError("exact_release must be true or false")
    lines = [
        "",
        "### Candidate build identity",
        f"- Web/Firmware version: {_inline_code('v' + version)}",
        f"- build commit: {_inline_code(build_commit)}",
        f"- exact release: {_inline_code(exact_release)}",
        "",
    ]
    with summary_path.open("a", encoding="utf-8") as output:
        output.write("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    auth = subparsers.add_parser("candidate-authorization")
    auth.add_argument("--summary-path", type=Path, required=True)
    auth.add_argument("--source-ref", required=True)
    auth.add_argument("--source-sha", required=True)
    auth.add_argument("--candidate-sha", required=True)
    auth.add_argument("--current-main", required=True)

    identity = subparsers.add_parser("candidate-build-identity")
    identity.add_argument("--summary-path", type=Path, required=True)
    identity.add_argument("--version", required=True)
    identity.add_argument("--build-commit", required=True)
    identity.add_argument("--exact-release", choices=("true", "false"), required=True)

    args = parser.parse_args(argv)

    if args.command == "candidate-authorization":
        append_candidate_authorization_summary(
            args.summary_path,
            source_ref=args.source_ref,
            source_sha=args.source_sha,
            candidate_sha=args.candidate_sha,
            current_main=args.current_main,
        )
    else:
        append_candidate_build_identity(
            args.summary_path,
            version=args.version,
            build_commit=args.build_commit,
            exact_release=args.exact_release,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
