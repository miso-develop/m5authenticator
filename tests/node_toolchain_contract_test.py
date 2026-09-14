from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class NodeToolchainContractTest(unittest.TestCase):
    def test_windows_bootstrap_targets_pinned_npm_directly(self) -> None:
        text = (ROOT / "scripts" / "bootstrap_node_toolchain.cmd").read_text(encoding="utf-8")
        self.assertIn('node -p "process.execPath"', text)
        self.assertIn('set "PINNED_NPM_CMD=%PINNED_NODE_DIR%npm.cmd"', text)
        self.assertIn('call "%PINNED_NPM_CMD%" install --global npm@%NPM_VERSION%', text)
        self.assertNotIn('cmd.exe /d /s /c "npm install --global', text)

    def test_windows_autorun_applies_current_directory_immediately(self) -> None:
        text = (ROOT / "scripts" / "fnm_autorun.cmd").read_text(encoding="utf-8")
        self.assertIn("fnm env --use-on-cd --version-file-strategy recursive", text)
        self.assertIn("fnm use --silent-if-unchanged --version-file-strategy recursive", text)


if __name__ == "__main__":
    unittest.main()
