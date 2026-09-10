from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeviceIdentityGuardTest(unittest.TestCase):
    def test_runtime_board_check_is_sticks3_specific(self) -> None:
        source = (ROOT / "firmware" / "components" / "m5auth_device_sticks3" / "hardware_identity.cpp").read_text(encoding="utf-8")
        self.assertIn("M5.getBoard() == m5::board_t::board_M5StickS3", source)
        self.assertIn("halt_unexpected_hardware", source)

    def test_guard_runs_before_storage_or_efuse_backend_construction(self) -> None:
        source = (ROOT / "firmware" / "main" / "app_main.cpp").read_text(encoding="utf-8")
        guard = source.index("is_expected_hardware()")
        halt = source.index("halt_unexpected_hardware()")
        production_backend = source.index("HmacEfuseSecurityBackend")
        store = source.index("storage::Store store")

        self.assertLess(guard, production_backend)
        self.assertLess(halt, production_backend)
        self.assertLess(guard, store)
        self.assertLess(halt, store)


if __name__ == "__main__":
    unittest.main()
