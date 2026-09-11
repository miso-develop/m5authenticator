from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "firmware/components/m5auth_vault_runtime/runtime.cpp"
HEADER = ROOT / "firmware/components/m5auth_vault_runtime/include/m5auth/vault_runtime/runtime.hpp"
NVS = ROOT / "firmware/components/m5auth_vault_runtime/nvs_persistence.cpp"
VAULT_FORMAT = ROOT / "firmware/components/m5auth_vault/vault_format.cpp"
CORE_METADATA = ROOT / "firmware/components/m5auth_core/include/m5auth/core/metadata.hpp"


class VaultRuntimeContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime = RUNTIME.read_text(encoding="utf-8")
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.nvs = NVS.read_text(encoding="utf-8")
        cls.vault_format = VAULT_FORMAT.read_text(encoding="utf-8")
        cls.core_metadata = CORE_METADATA.read_text(encoding="utf-8")
        cls.component = cls.runtime + "\n" + cls.header + "\n" + cls.nvs

    def test_vmk_is_explicitly_wiped_and_destructor_wipes(self) -> None:
        self.assertIn("secure_zero(vmk_.data(), vmk_.size())", self.runtime)
        self.assertIn("Runtime::~Runtime()", self.runtime)
        destructor_start = self.runtime.index("Runtime::~Runtime()")
        self.assertIn("wipe_vmk();", self.runtime[destructor_start:destructor_start + 120])

    def test_locked_paths_gate_plaintext_access(self) -> None:
        self.assertGreaterEqual(
            self.runtime.count("state_ != State::kUnlocked || !vmk_present_ || !has_vault_"),
            3,
        )
        self.assertIn("return Status::kLocked;", self.runtime)

    def test_transient_plaintext_has_explicit_wipe_seams(self) -> None:
        self.assertIn("wipe_plaintext(&plaintext);", self.runtime)
        self.assertIn("wipe_bytes(&encoded_plaintext);", self.runtime)
        self.assertIn("credential.credential_id.fill(0);", self.runtime)
        self.assertIn("wipe_bytes(&credential.secret);", self.runtime)
        self.assertIn("wipe_string(&plaintext->wifi->password);", self.runtime)

    def test_vault_codec_zeroizes_internal_plaintext_temporaries(self) -> None:
        self.assertIn("ByteVectorWipeGuard candidate_wipe(candidate);", self.vault_format)
        self.assertIn("PlaintextWipeGuard candidate_wipe(candidate);", self.vault_format)
        self.assertIn("candidate.credentials.reserve(count);", self.vault_format)
        self.assertIn("wipe_plaintext_candidate(&value);", self.vault_format)
        read_text_start = self.vault_format.index("bool read_sized_text(std::string& value)")
        read_text_end = self.vault_format.index("bool at_end() const", read_text_start)
        read_text = self.vault_format[read_text_start:read_text_end]
        self.assertNotIn("std::vector<std::uint8_t> bytes", read_text)
        self.assertIn("wipe_string(&value);", read_text)

    def test_nvs_update_uses_inactive_slot_then_active_pointer(self) -> None:
        phase1 = self.nvs.index("Phase 1")
        staged_blob = self.nvs.index("nvs_set_blob(handle, inactive_key", phase1)
        phase2 = self.nvs.index("Phase 2", staged_blob)
        active_pointer = self.nvs.index("nvs_set_u8(handle, kActiveSlotKey", phase2)
        self.assertLess(staged_blob, phase2)
        self.assertLess(phase2, active_pointer)
        self.assertIn("nvs_commit(handle)", self.nvs[staged_blob:phase2])
        self.assertIn("nvs_commit(handle)", self.nvs[active_pointer:active_pointer + 240])

    def test_only_opaque_last_used_is_persisted_outside_ciphertext(self) -> None:
        self.assertIn('constexpr char kLastUsedKey[] = "last_used";', self.nvs)
        self.assertIn("credential_id->data()", self.nvs)
        self.assertIn("credential_id->size()", self.nvs)
        for forbidden in (
            "issuer",
            "display_name",
            "wifi_ssid",
            "wifi_password",
            "passphrase",
            "plaintext_vmk",
        ):
            self.assertNotIn(forbidden, self.nvs.lower())

    def test_schema2_is_staged_without_canonical_activation(self) -> None:
        self.assertIn("kStorageSchemaVersion = 2", self.header)
        self.assertIn("kTargetStorageSchemaVersion", self.nvs)
        self.assertIn("kProtocolVersion = 1", self.core_metadata)
        self.assertIn("kStorageSchemaVersion = 1", self.core_metadata)
        self.assertNotIn("kProtocolVersion", self.component)

    def test_known_schema1_requires_reprovision_and_newer_fails_closed(self) -> None:
        self.assertIn("if (schema == 1) return Status::kReprovisionRequired;", self.nvs)
        self.assertIn("if (schema > kStorageSchemaVersion) return Status::kUnsupportedSchema;", self.nvs)
        self.assertNotIn("format_schema2();", self.runtime[self.runtime.index("Status Runtime::initialize()"):self.runtime.index("Status Runtime::reload_after_persistence()")])

    def test_component_has_no_project_efuse_or_secret_logging_path(self) -> None:
        lowered = self.component.lower()
        self.assertNotIn("efuse", lowered)
        for logging_api in ("esp_log", "printf(", "fprintf(", "std::cout", "std::cerr"):
            self.assertNotIn(logging_api, lowered)


if __name__ == "__main__":
    unittest.main()
