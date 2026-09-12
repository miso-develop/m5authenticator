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
        # Recovery flags are set only in the explicit kCorrupt branches. The
        # generic non-OK path returns without enabling recovery.
        self.assertRegex(
            body,
            r"if \(status != Status::kOk\) return status;",
        )
        self.assertRegex(
            body,
            r"if \(status != Status::kOk && status != Status::kNotFound\) \{[\s\S]+?return status;",
        )

    def test_header_exposes_no_unconfirmed_device_id_reset_api(self) -> None:
        text = REGISTRATION_HPP.read_text(encoding="utf-8")
        self.assertIn("clear_corrupt_registration_for_recovery", text)
        self.assertIn("device_id_recovery_required_", text)
        self.assertNotIn("reset_device_id", text)
        self.assertNotIn("erase_device_id", text)


if __name__ == "__main__":
    unittest.main()
