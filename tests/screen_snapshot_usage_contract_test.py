from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/testing/screen-snapshot-diagnostics.md"
HELPER = ROOT / "tools/diagnostics/screen_snapshot.py"


class ScreenSnapshotUsageContractTest(unittest.TestCase):
    def test_human_procedure_uses_isolated_diagnostics_build_directory(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("idf.py -B build-screen-snapshot set-target esp32s3", doc)
        self.assertIn(
            "idf.py -B build-screen-snapshot -DM5AUTH_TEST_SCREEN_SNAPSHOT=ON build",
            doc,
        )
        self.assertIn("M5AUTH_TEST_SCREEN_SNAPSHOT:BOOL=ON", doc)
        self.assertIn("idf.py -B build-screen-snapshot -p COM8 flash", doc)
        self.assertIn("Do not reuse `firmware\\build`", doc)

    def test_human_procedure_documents_exact_read_only_request_and_port_ownership(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        helper = HELPER.read_text(encoding="utf-8")
        request = '{"v":2,"id":9002,"op":"diagnostics.screen_snapshot","params":{}}'
        self.assertIn(request, doc)
        self.assertIn(request, helper)
        self.assertIn("python tools\\diagnostics\\screen_snapshot.py --port COM8", doc)
        self.assertIn("Web Serial", doc)
        self.assertIn("idf.py monitor", doc)
        self.assertIn("one process can normally own", doc)

    def test_diagnostics_on_is_auxiliary_and_cannot_satisfy_issue75(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("auxiliary/preflight", doc)
        self.assertIn("Never record a diagnostics-ON firmware run as the #75 release PASS", doc)
        self.assertIn("exact default-OFF production firmware", doc)
        self.assertIn("GitHub Pages/main", doc)

    def test_human_procedure_forbids_destructive_setup_shortcuts(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        for required in (
            "Factory Reset",
            "re-Provisioning",
            "site-data",
            "IndexedDB",
            "erase-flash",
            "eFuse",
        ):
            self.assertIn(required, doc)
        self.assertIn("eFuse operations remain prohibited", doc)


if __name__ == "__main__":
    unittest.main()
