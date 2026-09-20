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


def append_web_released_firmware_summary(
    summary_path: Path,
    *,
    web_version: str,
    web_sha: str,
    firmware_release_tag: str,
    release_id: str,
    firmware_source_sha: str,
    sha256sums_sha256: str,
    publisher_workflow_sha: str,
    publisher_run_id: str,
    publisher_run_attempt: str,
) -> None:
    lines = [
        "",
        "## Pages Web-only / Released Firmware",
        "",
        "- deployment mode: `Web-only / released firmware`",
        f"- Web version: {_inline_code('v' + web_version)}",
        f"- Web build commit: {_inline_code(web_sha)}",
        "- Web exact release: `false`",
        f"- firmware Release tag: {_inline_code(firmware_release_tag)}",
        f"- immutable Release id: {_inline_code(release_id)}",
        f"- firmware source commit: {_inline_code(firmware_source_sha)}",
        "- firmware exact release: `true`",
        f"- SHA256SUMS SHA-256: {_inline_code(sha256sums_sha256)}",
        f"- signed publisher workflow SHA: {_inline_code(publisher_workflow_sha)}",
        f"- signed publisher run: {_inline_code(publisher_run_id + '/' + publisher_run_attempt)}",
        "- no GitHub Release, tag, or Release asset was created or modified by this workflow",
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

    mixed = subparsers.add_parser("web-released-firmware")
    mixed.add_argument("--summary-path", type=Path, required=True)
    mixed.add_argument("--web-version", required=True)
    mixed.add_argument("--web-sha", required=True)
    mixed.add_argument("--firmware-release-tag", required=True)
    mixed.add_argument("--release-id", required=True)
    mixed.add_argument("--firmware-source-sha", required=True)
    mixed.add_argument("--sha256sums-sha256", required=True)
    mixed.add_argument("--publisher-workflow-sha", required=True)
    mixed.add_argument("--publisher-run-id", required=True)
    mixed.add_argument("--publisher-run-attempt", required=True)

    args = parser.parse_args(argv)

    if args.command == "candidate-authorization":
        append_candidate_authorization_summary(
            args.summary_path,
            source_ref=args.source_ref,
            source_sha=args.source_sha,
            candidate_sha=args.candidate_sha,
            current_main=args.current_main,
        )
    elif args.command == "candidate-build-identity":
        append_candidate_build_identity(
            args.summary_path,
            version=args.version,
            build_commit=args.build_commit,
            exact_release=args.exact_release,
        )
    else:
        append_web_released_firmware_summary(
            args.summary_path,
            web_version=args.web_version,
            web_sha=args.web_sha,
            firmware_release_tag=args.firmware_release_tag,
            release_id=args.release_id,
            firmware_source_sha=args.firmware_source_sha,
            sha256sums_sha256=args.sha256sums_sha256,
            publisher_workflow_sha=args.publisher_workflow_sha,
            publisher_run_id=args.publisher_run_id,
            publisher_run_attempt=args.publisher_run_attempt,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
