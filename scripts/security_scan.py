#!/usr/bin/env python3
"""Repository-owned secret leakage scanner for M5 Authenticator.

This scanner intentionally has no third-party dependencies. It scans Git-tracked
files and fails closed when it cannot enumerate them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

ALLOWLIST_FILE = ".security-scan-allowlist.json"
MAX_FILE_BYTES = 8 * 1024 * 1024

CODE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp",
    ".ino", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
}
CONFIG_SUFFIXES = CODE_SUFFIXES | {
    ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".xml",
}

FORBIDDEN_SUFFIXES = (
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore",
    ".pcap", ".pcapng", ".core", ".dump", ".dmp", ".nvs", ".nvs.bin",
)
DOCUMENTATION_SUFFIXES = {".md", ".rst", ".adoc"}
FORBIDDEN_NAME_PARTS = (
    "nvs-dump", "flash-dump", "ram-dump",
    "authenticator-export", "authenticator-migration",
    "otpauth-import", "totp-secret",
    "recovery-package", "vault-backup", "credential-backup",
    "authenticator-backup",
)

# Build sensitive literals from fragments so the scanner does not trigger on
# its own rule definitions.
_TOTP_SCHEME = "otp" + "auth://"
_MIGRATION_SCHEME = "otp" + "auth-" + "migration://"
_SECRET_PARAM = "sec" + "ret"

RULE_PATTERNS = {
    "totp-uri-secret": re.compile(
        re.escape(_TOTP_SCHEME)
        + r"""[^\s"'<>]{0,2048}[?&]"""
        + _SECRET_PARAM
        + r"=[A-Z2-7]+=*",
        re.IGNORECASE,
    ),
    "migration-payload": re.compile(
        re.escape(_MIGRATION_SCHEME) + r"[A-Za-z0-9%?=&._~+\-]{8,}",
        re.IGNORECASE,
    ),
    "private-key": re.compile(
        r"-{5}BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-{5}"
    ),
}

_CREDENTIAL_NAME = (
    r"(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|wifi[_-]?password|totp[_-]?secret|"
    r"vault[_-]?master[_-]?key|vmk|kek|passphrase[_-]?(?:derived[_-]?)?kek|"
    r"browser[_-]?unlock[_-]?key|buk|"
    r"browser[_-]?registration[_-]?private[_-]?key|brk[_-]?private[_-]?key|"
    r"browser[_-]?registration[_-]?key|brk|"
    r"unlock[_-]?session[_-]?key|session[_-]?key)"
)
_CREDENTIAL_KEY = (
    r"(?:"
    + _CREDENTIAL_NAME
    + r"|(?P<credential_quote>[\"'])"
    + _CREDENTIAL_NAME
    + r"(?P=credential_quote))"
)
CREDENTIAL_LITERAL_PATTERN = re.compile(
    _CREDENTIAL_KEY
    + r"""\s*[:=]\s*["'][^"'\r\n]{8,}["']""",
    re.IGNORECASE,
)

LOG_SINK_PATTERN = re.compile(
    r"(?:Serial\.(?:print|printf|println)|"
    r"console\.(?:log|debug|info|warn|error)|"
    r"(?:printf|ESP_LOG[EWIDV]|LOG_[EWIDV]|"
    r"logger\.(?:debug|info|warning|error|exception)))"
    r"\s*\([^\)\n]*(?:secret|password|token|credential|migration|otpauth|decrypted|"
    r"vault[_-]?master[_-]?key|\bvmk\b|browser[_-]?unlock[_-]?key|\bbuk\b|"
    r"browser[_-]?registration[_-]?key|\bbrk\b|session[_-]?key)",
    re.IGNORECASE,
)

KNOWN_RULES = frozenset(
    {"forbidden-path", "large-file", "credential-literal", "dangerous-log"}
    | set(RULE_PATTERNS)
)
ALLOWLISTABLE_RULES = KNOWN_RULES - {"forbidden-path", "large-file"}


class ScanError(RuntimeError):
    """Fatal scanner configuration or repository error."""


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    message: str


@dataclass(frozen=True)
class AllowEntry:
    path: str
    rule: str
    kind: str
    file_sha256: str
    reason: str


def normalize_relative_path(raw: str) -> str:
    path = PurePosixPath(raw.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ScanError(f"invalid repository-relative path: {raw!r}")
    return path.as_posix()


def _allowed_fixture_prefix(kind: str) -> str:
    if kind == "public-test-vector":
        return "tests/fixtures/public/"
    if kind == "synthetic-fixture":
        return "tests/fixtures/synthetic/"
    raise ScanError(f"invalid allowlist kind: {kind!r}")


def load_allowlist(root: Path) -> list[AllowEntry]:
    path = root / ALLOWLIST_FILE
    if not path.exists():
        raise ScanError(f"required allowlist file is missing: {ALLOWLIST_FILE}")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanError(f"cannot read {ALLOWLIST_FILE}: {exc}") from exc

    if payload.get("version") != 1 or not isinstance(payload.get("entries"), list):
        raise ScanError(f"{ALLOWLIST_FILE} must contain version=1 and an entries array")

    entries: list[AllowEntry] = []
    for index, raw in enumerate(payload["entries"]):
        if not isinstance(raw, dict):
            raise ScanError(f"allowlist entry {index} must be an object")

        expected = {"path", "rule", "kind", "file_sha256", "reason"}
        if set(raw) != expected:
            raise ScanError(
                f"allowlist entry {index} must contain exactly: "
                + ", ".join(sorted(expected))
            )

        entry_path = normalize_relative_path(str(raw["path"]))
        rule = str(raw["rule"])
        kind = str(raw["kind"])
        file_sha256 = str(raw["file_sha256"]).lower()
        reason = str(raw["reason"]).strip()

        if rule not in ALLOWLISTABLE_RULES:
            raise ScanError(f"allowlist entry {index} uses non-allowlistable rule: {rule}")
        prefix = _allowed_fixture_prefix(kind)
        if not entry_path.startswith(prefix):
            raise ScanError(
                f"allowlist entry {index} path must be under {prefix} for kind {kind}"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", file_sha256):
            raise ScanError(f"allowlist entry {index} has invalid file_sha256")
        if not reason:
            raise ScanError(f"allowlist entry {index} requires a non-empty reason")

        entries.append(
            AllowEntry(
                path=entry_path,
                rule=rule,
                kind=kind,
                file_sha256=file_sha256,
                reason=reason,
            )
        )

    if len({(e.path, e.rule, e.file_sha256) for e in entries}) != len(entries):
        raise ScanError("duplicate allowlist entries are not permitted")
    return entries


def git_tracked_files(root: Path) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ScanError("cannot enumerate Git-tracked files; run inside a Git worktree") from exc

    paths = [
        normalize_relative_path(item.decode("utf-8"))
        for item in result.stdout.split(b"\0")
        if item
    ]
    if not paths:
        raise ScanError("Git reported no tracked files")
    return paths


def file_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_path(path: str) -> list[Finding]:
    lowered = path.lower()
    findings: list[Finding] = []

    suffix = PurePosixPath(path).suffix.lower()
    suspicious_name = suffix not in DOCUMENTATION_SUFFIXES and any(
        part in lowered for part in FORBIDDEN_NAME_PARTS
    )
    if lowered.endswith(FORBIDDEN_SUFFIXES) or suspicious_name:
        findings.append(
            Finding(
                path=path,
                line=1,
                rule="forbidden-path",
                message="credential/dump/key-like file must not be tracked",
            )
        )
    return findings


def scan_content(path: str, data: bytes) -> list[Finding]:
    if len(data) > MAX_FILE_BYTES:
        return [
            Finding(
                path=path,
                line=1,
                rule="large-file",
                message=f"tracked file exceeds {MAX_FILE_BYTES} bytes and is not scanned",
            )
        ]

    text = data.decode("utf-8", errors="replace")
    suffix = PurePosixPath(path).suffix.lower()
    findings: list[Finding] = []

    for rule, pattern in RULE_PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    path=path,
                    line=line_number(text, match.start()),
                    rule=rule,
                    message={
                        "totp-uri-secret": "TOTP URI containing a secret parameter",
                        "migration-payload": "Google Authenticator migration payload",
                        "private-key": "private key material",
                    }[rule],
                )
            )

    if suffix in CONFIG_SUFFIXES or PurePosixPath(path).name.startswith(".env"):
        for match in CREDENTIAL_LITERAL_PATTERN.finditer(text):
            findings.append(
                Finding(
                    path=path,
                    line=line_number(text, match.start()),
                    rule="credential-literal",
                    message="credential-like literal assignment",
                )
            )

    if suffix in CODE_SUFFIXES:
        for match in LOG_SINK_PATTERN.finditer(text):
            findings.append(
                Finding(
                    path=path,
                    line=line_number(text, match.start()),
                    rule="dangerous-log",
                    message="logging call appears to include credential-bearing data",
                )
            )

    return findings


def apply_allowlist(
    findings: Iterable[Finding],
    file_hashes: dict[str, str],
    entries: Iterable[AllowEntry],
) -> tuple[list[Finding], list[AllowEntry]]:
    entry_map = {(e.path, e.rule, e.file_sha256): e for e in entries}
    used: set[tuple[str, str, str]] = set()
    remaining: list[Finding] = []

    for finding in findings:
        digest = file_hashes.get(finding.path)
        key = (finding.path, finding.rule, digest or "")
        if key in entry_map:
            used.add(key)
        else:
            remaining.append(finding)

    stale = [entry for key, entry in entry_map.items() if key not in used]
    return remaining, stale


def scan_repository(root: Path) -> tuple[list[Finding], list[AllowEntry]]:
    entries = load_allowlist(root)
    findings: list[Finding] = []
    hashes: dict[str, str] = {}

    for relative in git_tracked_files(root):
        full_path = root / relative
        findings.extend(scan_path(relative))

        try:
            data = full_path.read_bytes()
        except OSError as exc:
            raise ScanError(f"cannot read tracked file {relative}: {exc}") from exc

        hashes[relative] = file_sha256(data)
        findings.extend(scan_content(relative, data))

    return apply_allowlist(findings, hashes, entries)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan tracked repository files for secret leakage")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the script parent repository)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = args.root.resolve()

    try:
        findings, stale = scan_repository(root)
    except ScanError as exc:
        print(f"[security:scan] ERROR: {exc}", file=sys.stderr)
        return 2

    for entry in stale:
        print(
            f"[security:scan] ERROR: stale allowlist entry "
            f"{entry.path} [{entry.rule}]",
            file=sys.stderr,
        )

    for finding in findings:
        print(
            f"[security:scan] {finding.path}:{finding.line}: "
            f"[{finding.rule}] {finding.message}",
            file=sys.stderr,
        )

    if findings or stale:
        print(
            f"[security:scan] FAILED: {len(findings)} finding(s), "
            f"{len(stale)} stale allowlist entry/entries",
            file=sys.stderr,
        )
        return 1

    print("[security:scan] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
