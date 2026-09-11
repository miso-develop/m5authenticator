from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "security_scan.py"
SPEC = importlib.util.spec_from_file_location("security_scan", MODULE_PATH)
assert SPEC and SPEC.loader
security_scan = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = security_scan
SPEC.loader.exec_module(security_scan)


def synthetic_totp_uri() -> str:
    return (
        "otp"
        + "auth://Example:user@example.invalid?"
        + "sec"
        + "ret=JBSWY3DPEHPK3PXP&issuer=Example"
    )


def synthetic_migration_uri() -> str:
    return "otp" + "auth-" + "migration://offline?data=AAAA-SYNTHETIC-ONLY"


def private_key_marker() -> str:
    return "-" * 5 + "BEGIN " + "PRIVATE KEY" + "-" * 5


def quoted_property(name: str, value: str, quote: str = '"') -> str:
    return "{" + quote + name + quote + ": " + quote + value + quote + "}"


class SecurityScanTests(unittest.TestCase):
    def test_detects_totp_uri_with_secret(self) -> None:
        findings = security_scan.scan_content(
            "sample.txt", synthetic_totp_uri().encode("utf-8")
        )
        self.assertEqual(["totp-uri-secret"], [f.rule for f in findings])

    def test_bare_totp_scheme_is_not_a_finding(self) -> None:
        findings = security_scan.scan_content(
            "README.md", ("otp" + "auth:// URI is documented here").encode("utf-8")
        )
        self.assertEqual([], findings)

    def test_detects_google_migration_payload(self) -> None:
        findings = security_scan.scan_content(
            "sample.txt", synthetic_migration_uri().encode("utf-8")
        )
        self.assertEqual(["migration-payload"], [f.rule for f in findings])

    def test_bare_migration_scheme_is_not_a_finding(self) -> None:
        findings = security_scan.scan_content(
            "SECURITY.md", ("otp" + "auth-" + "migration://").encode("utf-8")
        )
        self.assertEqual([], findings)

    def test_detects_private_key_marker(self) -> None:
        findings = security_scan.scan_content(
            "sample.txt", private_key_marker().encode("utf-8")
        )
        self.assertEqual(["private-key"], [f.rule for f in findings])

    def test_detects_credential_literal_in_config(self) -> None:
        content = ("wifi_" + "pass" + 'word = "synthetic-password-only"').encode("utf-8")
        findings = security_scan.scan_content("config.toml", content)
        self.assertEqual(["credential-literal"], [f.rule for f in findings])

    def test_detects_vault_master_key_literal_in_config(self) -> None:
        content = (
            "vault_" + "master_" + 'key = "synthetic-vmk-material"'
        ).encode("utf-8")
        findings = security_scan.scan_content("config.toml", content)
        self.assertEqual(["credential-literal"], [f.rule for f in findings])

    def test_detects_browser_unlock_key_literal_in_config(self) -> None:
        content = (
            "browser_" + "unlock_" + 'key = "synthetic-buk-material"'
        ).encode("utf-8")
        findings = security_scan.scan_content("config.toml", content)
        self.assertEqual(["credential-literal"], [f.rule for f in findings])

    def test_detects_browser_registration_key_literal_in_config(self) -> None:
        content = (
            "browser_" + "registration_" + 'key = "synthetic-brk-material"'
        ).encode("utf-8")
        findings = security_scan.scan_content("config.toml", content)
        self.assertEqual(["credential-literal"], [f.rule for f in findings])

    def test_detects_unlock_session_key_literal_in_config(self) -> None:
        content = (
            "unlock_" + "session_" + 'key = "synthetic-session-material"'
        ).encode("utf-8")
        findings = security_scan.scan_content("config.toml", content)
        self.assertEqual(["credential-literal"], [f.rule for f in findings])

    def test_detects_double_quoted_credential_property_in_json(self) -> None:
        content = quoted_property("totp_secret", "synthetic-totp-material").encode("utf-8")
        findings = security_scan.scan_content("fixture.json", content)
        self.assertEqual(["credential-literal"], [f.rule for f in findings])

    def test_detects_single_quoted_credential_property(self) -> None:
        content = quoted_property("vmk", "synthetic-vmk-material", quote="'").encode("utf-8")
        findings = security_scan.scan_content("fixture.conf", content)
        self.assertEqual(["credential-literal"], [f.rule for f in findings])

    def test_detects_v1_key_names_in_quoted_json_properties(self) -> None:
        names = [
            "vmk",
            "kek",
            "buk",
            "brk_private_key",
            "browser_registration_private_key",
            "session_key",
        ]
        for name in names:
            with self.subTest(name=name):
                content = quoted_property(name, "synthetic-key-material-only").encode("utf-8")
                findings = security_scan.scan_content("fixture.jsonc", content)
                self.assertEqual(["credential-literal"], [f.rule for f in findings])

    def test_credential_finding_never_contains_matched_value(self) -> None:
        synthetic_value = "synthetic-redaction-marker"
        content = quoted_property("password", synthetic_value).encode("utf-8")
        findings = security_scan.scan_content("fixture.json", content)
        self.assertEqual(1, len(findings))
        self.assertNotIn(synthetic_value, findings[0].message)

    def test_documentation_quoted_assignment_example_is_not_a_finding(self) -> None:
        content = (
            "Documentation example only: "
            + quoted_property("vmk", "synthetic-documentation-value")
        ).encode("utf-8")
        findings = security_scan.scan_content("docs/example.md", content)
        self.assertEqual([], findings)

    def test_quoted_sensitive_name_without_literal_assignment_is_not_a_finding(self) -> None:
        content = ('{"' + "vmk" + '": null}').encode("utf-8")
        findings = security_scan.scan_content("fixture.json", content)
        self.assertEqual([], findings)

    def test_detects_dangerous_log_in_code(self) -> None:
        content = ("Serial." + "println(secret)").encode("utf-8")
        findings = security_scan.scan_content("main.cpp", content)
        self.assertEqual(["dangerous-log"], [f.rule for f in findings])

    def test_detects_dangerous_vmk_log_in_code(self) -> None:
        content = ("console." + "log(v" + "mk)").encode("utf-8")
        findings = security_scan.scan_content("main.ts", content)
        self.assertEqual(["dangerous-log"], [f.rule for f in findings])

    def test_detects_dangerous_brk_log_in_code(self) -> None:
        content = ("console." + "log(b" + "rk)").encode("utf-8")
        findings = security_scan.scan_content("main.ts", content)
        self.assertEqual(["dangerous-log"], [f.rule for f in findings])

    def test_detects_forbidden_dump_path(self) -> None:
        findings = security_scan.scan_path("captures/device-flash-dump.bin")
        self.assertEqual(["forbidden-path"], [f.rule for f in findings])

    def test_detects_recovery_package_path(self) -> None:
        findings = security_scan.scan_path("local/device-recovery-package.json")
        self.assertEqual(["forbidden-path"], [f.rule for f in findings])

    def test_detects_vault_backup_path(self) -> None:
        findings = security_scan.scan_path("exports/vault-backup.json")
        self.assertEqual(["forbidden-path"], [f.rule for f in findings])

    def test_documentation_name_is_not_treated_as_dump(self) -> None:
        findings = security_scan.scan_path("docs/authenticator-migration.md")
        self.assertEqual([], findings)

    def test_recovery_documentation_name_is_not_treated_as_backup(self) -> None:
        findings = security_scan.scan_path("docs/recovery-package.md")
        self.assertEqual([], findings)

    def test_allowlist_requires_safe_fixture_location(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / security_scan.ALLOWLIST_FILE).write_text(
                json.dumps(
                    {
                        "version": 1,
                        "entries": [
                            {
                                "path": "src/example.txt",
                                "rule": "totp-uri-secret",
                                "kind": "synthetic-fixture",
                                "file_sha256": "0" * 64,
                                "reason": "synthetic test",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(security_scan.ScanError):
                security_scan.load_allowlist(root)

    def test_exact_synthetic_fixture_hash_can_be_allowlisted(self) -> None:
        data = synthetic_totp_uri().encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        finding = security_scan.scan_content(
            "tests/fixtures/synthetic/example.txt", data
        )[0]
        entry = security_scan.AllowEntry(
            path="tests/fixtures/synthetic/example.txt",
            rule="totp-uri-secret",
            kind="synthetic-fixture",
            file_sha256=digest,
            reason="synthetic scanner fixture",
        )

        remaining, stale = security_scan.apply_allowlist(
            [finding],
            {"tests/fixtures/synthetic/example.txt": digest},
            [entry],
        )
        self.assertEqual([], remaining)
        self.assertEqual([], stale)

    def test_changed_fixture_does_not_match_allowlist(self) -> None:
        data = synthetic_totp_uri().encode("utf-8")
        finding = security_scan.scan_content(
            "tests/fixtures/synthetic/example.txt", data
        )[0]
        entry = security_scan.AllowEntry(
            path="tests/fixtures/synthetic/example.txt",
            rule="totp-uri-secret",
            kind="synthetic-fixture",
            file_sha256="0" * 64,
            reason="synthetic scanner fixture",
        )

        remaining, stale = security_scan.apply_allowlist(
            [finding],
            {
                "tests/fixtures/synthetic/example.txt": hashlib.sha256(data).hexdigest()
            },
            [entry],
        )
        self.assertEqual([finding], remaining)
        self.assertEqual([entry], stale)


if __name__ == "__main__":
    unittest.main()
