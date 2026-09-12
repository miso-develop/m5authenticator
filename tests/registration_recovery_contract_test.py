from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRATION_CPP = (
    ROOT
    / "firmware"
    / "components"
    / "m5auth_registration"
    / "registration.cpp"
)
REGISTRATION_HPP = (
    ROOT
    / "firmware"
    / "components"
    / "m5auth_registration"
    / "include"
    / "m5auth"
    / "registration"
    / "registration.hpp"
)
CANONICAL_PROTOCOL_CPP = (
    ROOT
    / "firmware"
    / "components"
    / "m5auth_provisioning"
    / "canonical_protocol_v2.cpp"
)


class RegistrationRecoveryContractTests(unittest.TestCase):
    def test_structural_device_id_corruption_is_recovery_only_not_auto_erase(self) -> None:
        text = REGISTRATION_CPP.read_text(encoding="utf-8")
        initialize = re.search(
            r"Status Store::initialize\(\) \{([\s\S]+?)\n\}\n\nStatus Store::load_or_create_device_id",
            text,
        )
        self.assertIsNotNone(initialize)
        body = initialize.group(1)
        self.assertIn("if (status == Status::kCorrupt)", body)
        self.assertIn("generate_device_id_candidate();", body)
        self.assertIn("recovery_reset_available_ = true;", body)
        self.assertIn("device_id_recovery_required_ = true;", body)
        self.assertNotIn("nvs_erase_all", body)
        self.assertNotIn("nvs_erase_key", body)

    def test_device_id_length_is_queried_before_fixed_buffer_read(self) -> None:
        text = REGISTRATION_CPP.read_text(encoding="utf-8")
        loader = re.search(
            r"Status Store::load_or_create_device_id\(\) \{([\s\S]+?)\n\}\n\nStatus Store::load_registration",
            text,
        )
        self.assertIsNotNone(loader)
        body = loader.group(1)
        query = body.index("nvs_get_blob(handle, kDeviceIdKey, nullptr, &size)")
        size_check = body.index("if (size != snapshot_.device_id.size())", query)
        fixed_read = body.index(
            "nvs_get_blob(handle, kDeviceIdKey, snapshot_.device_id.data(), &size)",
            size_check,
        )
        self.assertLess(query, size_check)
        self.assertLess(size_check, fixed_read)
        self.assertIn("return Status::kCorrupt;", body[size_check:fixed_read])
        self.assertIn("all_zero(snapshot_.device_id)", body)
        self.assertIn("return map_error(result);", body)

    def test_registration_length_is_queried_before_fixed_buffer_read(self) -> None:
        text = REGISTRATION_CPP.read_text(encoding="utf-8")
        loader = re.search(
            r"Status Store::load_registration\(\) \{([\s\S]+?)\n\}\n\nStatus Store::persist_registration",
            text,
        )
        self.assertIsNotNone(loader)
        body = loader.group(1)
        query = body.index("nvs_get_blob(handle, kRegistrationKey, nullptr, &size)")
        size_check = body.index("if (size != kEncodedRegistrationBytes)", query)
        fixed_read = body.index(
            "nvs_get_blob(handle, kRegistrationKey, encoded.data(), &size)",
            size_check,
        )
        self.assertLess(query, size_check)
        self.assertLess(size_check, fixed_read)
        self.assertIn("return Status::kCorrupt;", body[size_check:fixed_read])
        self.assertIn("return map_error(result);", body)

    def test_confirmed_device_id_recovery_is_the_only_namespace_erase_site(self) -> None:
        text = REGISTRATION_CPP.read_text(encoding="utf-8")
        self.assertEqual(text.count("nvs_erase_all(handle)"), 1)
        recovery = re.search(
            r"Status Store::clear_corrupt_registration_for_recovery\(\) \{([\s\S]+?)\n\}\n\nStatus Store::reinitialize_after_partition_reset",
            text,
        )
        self.assertIsNotNone(recovery)
        body = recovery.group(1)
        self.assertIn("const DeviceId recovery_device_id = snapshot_.device_id;", body)
        self.assertIn("if (device_id_recovery_required_)", body)
        self.assertIn("nvs_erase_all(handle)", body)
        self.assertIn("kDeviceIdKey", body)
        self.assertIn("recovery_device_id.data()", body)
        self.assertIn("snapshot_.device_id = recovery_device_id;", body)

    def test_valid_device_id_corrupt_registration_preserves_identity(self) -> None:
        text = REGISTRATION_CPP.read_text(encoding="utf-8")
        initialize = re.search(
            r"Status Store::initialize\(\) \{([\s\S]+?)\n\}\n\nStatus Store::load_or_create_device_id",
            text,
        )
        self.assertIsNotNone(initialize)
        body = initialize.group(1)
        self.assertIn("const DeviceId stable_device_id = snapshot_.device_id;", body)
        self.assertIn("snapshot_.device_id = stable_device_id;", body)
        recovery = re.search(
            r"Status Store::clear_corrupt_registration_for_recovery\(\) \{([\s\S]+?)\n\}\n\nStatus Store::reinitialize_after_partition_reset",
            text,
        )
        self.assertIsNotNone(recovery)
        self.assertIn("nvs_erase_key(handle, kRegistrationKey)", recovery.group(1))

    def test_generic_io_does_not_enable_destructive_recovery(self) -> None:
        text = REGISTRATION_CPP.read_text(encoding="utf-8")
        initialize = re.search(
            r"Status Store::initialize\(\) \{([\s\S]+?)\n\}\n\nStatus Store::load_or_create_device_id",
            text,
        )
        self.assertIsNotNone(initialize)
        body = initialize.group(1)
        self.assertRegex(body, r"if \(status != Status::kOk\) return status;")
        self.assertRegex(
            body,
            r"if \(status != Status::kOk && status != Status::kNotFound\) \{[\s\S]+?return status;",
        )

    def test_brk_persistence_uses_full_shared_p256_validator(self) -> None:
        text = REGISTRATION_CPP.read_text(encoding="utf-8")
        self.assertIn("return session::valid_p256_public_key(key);", text)
        self.assertNotIn("return !all_zero(key) && key[0] == 0x04;", text)
        self.assertIn("!valid_public_key(snapshot_.brk_public_key)", text)
        self.assertIn("!valid_public_key(brk_public_key)", text)

    def test_recovery_reset_persists_registration_identity_before_vault_erase(self) -> None:
        text = CANONICAL_PROTOCOL_CPP.read_text(encoding="utf-8")
        start = text.index('operation == "factory_reset.recovery_complete"')
        end = text.index('operation == "vault.install"', start)
        body = text[start:end]
        clear_corrupt = body.index("registration_.clear_corrupt_registration_for_recovery()")
        clear_normal = body.index("registration_.clear_registration()")
        vault_erase = body.index("runtime_.factory_reset()")
        self.assertLess(clear_corrupt, vault_erase)
        self.assertLess(clear_normal, vault_erase)
        self.assertIn("if (clear_status == registration::Status::kOk)", body)

    def test_vault_install_routes_by_device_owned_pending_operation(self) -> None:
        text = CANONICAL_PROTOCOL_CPP.read_text(encoding="utf-8")
        start = text.index('operation == "vault.install"')
        end = text.index('operation == "vault.update"', start)
        body = text[start:end]
        self.assertIn("switch (vmk_sink_.pending_operation())", body)
        self.assertIn("Operation::kInitialProvisioning", body)
        self.assertIn("install_initial_vault", body)
        self.assertIn("Operation::kRecovery", body)
        self.assertIn("install_recovered_vault", body)
        self.assertIn("default:", body)
        self.assertIn("vmk_sink_.cancel_pending();", body)

    def test_header_exposes_no_unconfirmed_device_id_reset_api(self) -> None:
        text = REGISTRATION_HPP.read_text(encoding="utf-8")
        self.assertIn("clear_corrupt_registration_for_recovery", text)
        self.assertIn("device_id_recovery_required_", text)
        self.assertNotIn("reset_device_id", text)
        self.assertNotIn("erase_device_id", text)


if __name__ == "__main__":
    unittest.main()
