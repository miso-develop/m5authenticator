from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import validate_release

CANONICAL_PROTOCOL = ROOT / "firmware/components/m5auth_provisioning/canonical_protocol_v2.cpp"
BROWSER_VAULT = ROOT / "web/src/security/browser-vault.ts"
PROVISIONER_HTML = ROOT / "web/index.html"
QR_IMAGE_DECODER = ROOT / "web/src/import/qr.ts"
SECRET_VAULT_DOC = ROOT / "docs/SECRET_VAULT.md"
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"
PAGES_WORKFLOW = ROOT / ".github/workflows/pages.yml"
SECURITY_WORKFLOW = ROOT / ".github/workflows/security.yml"

LEGACY_PROTOCOL_OPERATIONS = (
    "accounts.list",
    "import.begin",
    "import.item",
    "import.validate",
    "import.commit",
    "account.rename",
    "account.delete",
    "accounts.reorder",
    "selection.get",
    "selection.set",
    "wifi.status",
    "wifi.set",
    "wifi.clear",
    "factory.reset",
)

NETWORK_APIS = (
    "fetch(",
    "XMLHttpRequest",
    "WebSocket(",
    "EventSource(",
    "sendBeacon(",
)

LOGGING_APIS = (
    "console.log(",
    "console.info(",
    "console.warn(",
    "console.error(",
    "console.debug(",
)


class SecurityCloseoutContractTest(unittest.TestCase):
    def test_release_contract_and_build_surface_validate(self) -> None:
        result = validate_release.validate_release(require_production=True)
        profile = result["profile"]
        self.assertEqual(profile["protocol_version"], 2)
        self.assertEqual(profile["storage_schema_version"], 2)
        self.assertEqual(profile["vault_format_version"], 1)
        self.assertEqual(profile["security_profile"], validate_release.V1_SECURITY_PROFILE)
        self.assertIs(profile["public_synthetic_flash_key_allowed"], False)
        self.assertIs(profile["project_specific_efuse_required"], False)
        self.assertEqual(profile["vmk_persistence"], "ram-only")
        self.assertEqual(profile["post_update_state"], "locked")
        self.assertIs(profile["production_release_allowed"], True)

    def test_core_dump_is_fail_closed_for_credential_bearing_ram(self) -> None:
        sdkconfig = validate_release.DEFAULT_SDKCONFIG.read_text(encoding="utf-8")
        self.assertRegex(sdkconfig, r"(?m)^CONFIG_ESP_COREDUMP_ENABLE_TO_NONE=y$")
        self.assertNotIn("CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y", sdkconfig)
        self.assertNotIn("CONFIG_ESP_COREDUMP_ENABLE_TO_UART=y", sdkconfig)

    def test_release_components_exclude_legacy_schema1_surfaces(self) -> None:
        validate_release.validate_release_build_surface()
        app = validate_release.DEFAULT_BOOTSTRAP.read_text(encoding="utf-8")
        self.assertNotIn("m5auth/storage/storage.hpp", app)
        self.assertNotIn("m5auth/device/sticks3/device.hpp", app)
        self.assertNotIn("m5auth::storage::Store", app)
        self.assertNotIn("m5auth::provisioning::Session", app)
        self.assertNotIn("DevSecurityBackend", app)

    def test_canonical_device_protocol_has_no_stored_secret_read_or_legacy_mutation_ops(self) -> None:
        source = CANONICAL_PROTOCOL.read_text(encoding="utf-8")
        for operation in LEGACY_PROTOCOL_OPERATIONS:
            self.assertNotIn(f'operation == "{operation}"', source)
        for forbidden in (
            'operation == "secret.read"',
            'operation == "vault.read"',
            'operation == "vault.export"',
            'operation == "wifi.password"',
            'operation == "vmk.export"',
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('operation == "vault.update"', source)
        self.assertIn('operation == "vault.rekey"', source)
        self.assertIn('operation == "device.lock"', source)

    def test_provisioner_csp_forbids_network_connections(self) -> None:
        html = PROVISIONER_HTML.read_text(encoding="utf-8")
        self.assertIn("connect-src 'none'", html)
        self.assertIn("form-action 'none'", html)
        self.assertIn("object-src 'none'", html)

    def test_qr_file_decode_stays_local_without_object_urls(self) -> None:
        html = PROVISIONER_HTML.read_text(encoding="utf-8")
        decoder = QR_IMAGE_DECODER.read_text(encoding="utf-8")
        self.assertIn("createImageBitmap(file)", decoder)
        self.assertIn("getImageData(0, 0, canvas.width, canvas.height)", decoder)
        self.assertIn("RGBLuminanceSource", decoder)
        self.assertIn("HybridBinarizer", decoder)
        self.assertIn("GlobalHistogramBinarizer", decoder)
        self.assertIn("QRCodeReader", decoder)
        self.assertIn("imageData?.data.fill(0)", decoder)
        self.assertIn("bitmap?.close()", decoder)
        self.assertNotIn("BrowserQRCodeReader", decoder)
        self.assertNotIn("decodeFromCanvas", decoder)
        self.assertNotIn("URL.createObjectURL", decoder)
        self.assertNotIn("URL.revokeObjectURL", decoder)
        self.assertIn("img-src 'self' data:", html)
        self.assertNotIn("img-src 'self' data: blob:", html)
        self.assertIn("connect-src 'none'", html)
        self.assertIn("form-action 'none'", html)
        self.assertIn("object-src 'none'", html)

    def test_credential_processing_sources_have_no_network_or_console_egress(self) -> None:
        excluded = {
            ROOT / "web/src/firmware-update.ts",
            ROOT / "web/src/flasher.ts",
        }
        checked = 0
        for path in (ROOT / "web/src").rglob("*.ts"):
            if path in excluded or path.name.endswith(".test.ts") or path.name.endswith(".d.ts"):
                continue
            text = path.read_text(encoding="utf-8")
            for api in NETWORK_APIS:
                self.assertNotIn(api, text, f"network API {api} in {path.relative_to(ROOT)}")
            for api in LOGGING_APIS:
                self.assertNotIn(api, text, f"console API {api} in {path.relative_to(ROOT)}")
            checked += 1
        self.assertGreater(checked, 10)

    def test_recovery_package_export_excludes_browser_private_keys(self) -> None:
        source = BROWSER_VAULT.read_text(encoding="utf-8")
        start = source.index("export function exportRecoveryPackage")
        end = source.index("export function parseRecoveryPackage", start)
        export_body = source[start:end]
        self.assertIn("safe.recoveryWrappedVmk", export_body)
        self.assertIn("safe.trustedBrowser.registrationId", export_body)
        self.assertNotIn("safe.trustedBrowser.buk", export_body)
        self.assertNotIn("safe.trustedBrowser.brkPrivateKey", export_body)
        self.assertNotIn("safe.trustedBrowser.wrappedVmk", export_body)
        self.assertIn("extractable === false", source)
        self.assertIn('namedCurve: "P-256"', source)

    def test_architecture_doc_describes_activated_version_boundary(self) -> None:
        source = SECRET_VAULT_DOC.read_text(encoding="utf-8")
        self.assertIn("Canonical V1 is now active end to end", source)
        self.assertIn("`PROTOCOL_VERSION = 2`", source)
        self.assertIn("`STORAGE_SCHEMA_VERSION = 2`", source)
        self.assertIn("`VAULT_FORMAT_VERSION = 1`", source)
        self.assertNotIn("Current development main may still implement Protocol 1", source)
        self.assertIn("Legacy Protocol 1 / Storage Schema 1 source may remain only as non-release historical/test material", source)

    def test_release_distribution_paths_share_fail_closed_production_validation(self) -> None:
        release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        pages = PAGES_WORKFLOW.read_text(encoding="utf-8")
        self.assertGreaterEqual(release.count("--require-production"), 2)
        self.assertGreaterEqual(pages.count("--require-production"), 2)
        self.assertIn("package_firmware.py", release)
        self.assertIn("package_firmware.py", pages)
        for source in (release.lower(), pages.lower()):
            self.assertNotIn("efuse", source)
            self.assertNotIn("hmac", source)
            self.assertNotIn("development-synthetic", source)

    def test_security_workflow_keeps_repository_scanner_as_independent_layer(self) -> None:
        workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("test_security_scan.py", workflow)
        self.assertIn("scripts/security_scan.py", workflow)
        self.assertNotIn("continue-on-error: true", workflow)


if __name__ == "__main__":
    unittest.main()
