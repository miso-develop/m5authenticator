from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "firmware/components/m5auth_provisioning/canonical_protocol_v2.cpp"
PROTOCOL_HEADER = ROOT / "firmware/components/m5auth_provisioning/include/m5auth/provisioning/canonical_protocol_v2.hpp"
RUNTIME = ROOT / "firmware/components/m5auth_vault_runtime/runtime.cpp"
NVS = ROOT / "firmware/components/m5auth_vault_runtime/nvs_persistence.cpp"
VAULT_HEADER = ROOT / "firmware/components/m5auth_vault/include/m5auth/vault.hpp"


class AutomaticLockProtocolContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.protocol = PROTOCOL.read_text(encoding="utf-8")
        cls.protocol_header = PROTOCOL_HEADER.read_text(encoding="utf-8")
        cls.runtime = RUNTIME.read_text(encoding="utf-8")
        cls.nvs = NVS.read_text(encoding="utf-8")
        cls.vault_header = VAULT_HEADER.read_text(encoding="utf-8")

    def test_protocol2_envelope_parser_accepts_only_formats_one_and_two(self) -> None:
        start = self.protocol.index("bool read_envelope(")
        end = self.protocol.index("bool response_ok(", start)
        parser = self.protocol[start:end]
        self.assertIn("vault::kVaultFormatVersion1", parser)
        self.assertIn("vault::kVaultFormatVersion2", parser)
        self.assertIn("vault_format != vault::kVaultFormatVersion1", parser)
        self.assertIn("vault_format != vault::kVaultFormatVersion2", parser)
        self.assertIn("storage_schema != vault::kTargetStorageSchemaVersion", parser)

    def test_hello_reports_persisted_format_and_supported_formats(self) -> None:
        start = self.protocol.index("std::string hello_success(")
        end = self.protocol.index("std::string time_status_success", start)
        hello = self.protocol[start:end]
        self.assertIn("runtime_metadata.vault_format_version", hello)
        self.assertIn('"vault_format"', hello)
        self.assertIn('"vault_format_version"', hello)
        self.assertIn('"supported_vault_formats"', hello)
        self.assertIn("cJSON_CreateNumber(vault::kVaultFormatVersion1)", hello)
        self.assertIn("cJSON_CreateNumber(vault::kVaultFormatVersion2)", hello)

    def test_vault_update_applies_policy_only_after_runtime_commit(self) -> None:
        start = self.protocol.index('operation == "vault.update"')
        end = self.protocol.index('operation == "vault.rekey"', start)
        update = self.protocol[start:end]
        commit_call = "runtime_.update_encrypted_vault"
        due_check = (
            "if (status == vault_runtime::Status::kOk && "
            "automatic_lock_due_after_commit)"
        )
        self.assertIn(commit_call, update)
        self.assertIn("automatic_lock_due_after_commit", update)
        self.assertIn(due_check, update)
        self.assertIn("lock_security_boundary();", update)
        self.assertLess(update.index(commit_call), update.index(due_check))
        self.assertLess(update.index(due_check), update.index("lock_security_boundary();"))

    def test_vault_rekey_rechecks_original_deadline_after_commit(self) -> None:
        start = self.protocol.index('operation == "vault.rekey"')
        end = self.protocol.index('operation == "time.status"', start)
        rekey = self.protocol[start:end]
        install_call = "vmk_sink_.install_rekeyed_vault"
        due_check = "runtime_.automatic_lock_due(now_ms)"
        self.assertIn(install_call, rekey)
        self.assertIn("automatic_lock_due_after_rekey", rekey)
        self.assertIn(due_check, rekey)
        self.assertIn("lock_security_boundary()", rekey)
        self.assertLess(rekey.index(install_call), rekey.index(due_check))
        self.assertLess(rekey.index(due_check), rekey.index("lock_security_boundary()"))

    def test_expiry_and_explicit_lock_use_same_security_boundary(self) -> None:
        self.assertIn("vault_runtime::Status lock_security_boundary();", self.protocol_header)
        housekeeping_start = self.protocol.index(
            "void CanonicalProtocolV2Handler::housekeeping("
        )
        housekeeping_end = self.protocol.index(
            "RecoveryResetDecision CanonicalProtocolV2Handler::recovery_reset_decision",
            housekeeping_start,
        )
        housekeeping = self.protocol[housekeeping_start:housekeeping_end]
        self.assertIn("runtime_.automatic_lock_due(now_ms)", housekeeping)
        self.assertIn("lock_security_boundary();", housekeeping)

        device_lock_start = self.protocol.index('operation == "device.lock"')
        factory_reset_start = self.protocol.index(
            'operation == "factory_reset"', device_lock_start
        )
        device_lock = self.protocol[device_lock_start:factory_reset_start]
        self.assertIn("lock_security_boundary();", device_lock)
        self.assertNotIn("runtime_.lock();", device_lock)

    def test_runtime_rejects_format2_to_format1_downgrade(self) -> None:
        start = self.runtime.index("Status Runtime::update_encrypted_vault(")
        end = self.runtime.index("Status Runtime::metadata(", start)
        update = self.runtime[start:end]
        self.assertIn("envelope_.vault_format_version == vault::kVaultFormatVersion2", update)
        self.assertIn("envelope.vault_format_version == vault::kVaultFormatVersion1", update)
        self.assertIn("return Status::kInvalidArgument;", update)

    def test_unknown_persisted_format_is_non_destructive_fail_closed(self) -> None:
        self.assertIn("Status::kUnsupportedVaultFormat", self.nvs)
        self.assertIn("vault::is_supported_vault_format", self.nvs)
        initialize_start = self.runtime.index("Status Runtime::initialize()")
        initialize_end = self.runtime.index("Status Runtime::reload_after_persistence()")
        initialize = self.runtime[initialize_start:initialize_end]
        self.assertIn("Status::kUnsupportedVaultFormat", initialize)
        self.assertIn("recovery_reset_allowed_ = false;", initialize)

    def test_version_tuple_remains_protocol2_storage2_with_dual_vault_formats(self) -> None:
        self.assertIn("kTargetStorageSchemaVersion = 2", self.vault_header)
        self.assertIn("kVaultFormatVersion1 = 1", self.vault_header)
        self.assertIn("kVaultFormatVersion2 = 2", self.vault_header)
        self.assertNotIn("kTargetStorageSchemaVersion = 3", self.vault_header)


if __name__ == "__main__":
    unittest.main()
