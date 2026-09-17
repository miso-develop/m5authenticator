from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FactoryResetProtocolBehaviorBuildTest(unittest.TestCase):
    def test_canonical_factory_reset_protocol_behavior(self) -> None:
        output = Path("/tmp/m5auth-canonical-reset-behavior-test")
        command = [
            "g++",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-Itests/host_stubs",
            "-Ifirmware/components/m5auth_core/include",
            "-Ifirmware/components/m5auth_provisioning/include",
            "-Ifirmware/components/m5auth_registration/include",
            "-Ifirmware/components/m5auth_session/include",
            "-Ifirmware/components/m5auth_time/include",
            "-Ifirmware/components/m5auth_vault/include",
            "-Ifirmware/components/m5auth_vault_runtime/include",
            "tests/host_stubs/cJSON.cpp",
            "firmware/components/m5auth_provisioning/canonical_protocol_v2.cpp",
            "firmware/components/m5auth_session/session_protocol_v2.cpp",
            "firmware/components/m5auth_session/p256_public_key.cpp",
            "firmware/components/m5auth_session/user_presence.cpp",
            "firmware/components/m5auth_vault/vault_format.cpp",
            "firmware/components/m5auth_vault/vault_crypto.cpp",
            "firmware/components/m5auth_vault_runtime/runtime.cpp",
            "tests/canonical_protocol_v2_factory_reset_behavior_test.cpp",
            "-lcrypto",
            "-o",
            str(output),
        ]
        subprocess.run(command, cwd=ROOT, check=True)
        subprocess.run([str(output)], cwd=ROOT, check=True)


if __name__ == "__main__":
    unittest.main()
