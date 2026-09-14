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

    def test_helper_fresh_id_and_stale_response_contract_is_documented(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        helper = HELPER.read_text(encoding="utf-8")
        self.assertIn("fresh positive request ID", doc)
        self.assertIn("it is **not fixed**", doc)
        self.assertIn("response.id", doc)
        self.assertIn("wrong-ID lines are ignored", doc)
        self.assertIn("malformed stale lines are ignored", doc)
        self.assertIn("secrets.randbelow", helper)
        self.assertIn("response_id != request_id", helper)
        self.assertNotIn('id":9002', helper)

    def test_snapshot_not_ready_is_explicit_fail_closed_evidence(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("snapshot_not_ready", doc)
        self.assertIn("FAIL / re-check condition", doc)
        self.assertIn("Before the first render has completed", doc)
        self.assertIn("failed to start", doc)
        self.assertIn("not evidence", doc)

    def test_serial_ownership_can_invalidate_active_unlock_observation(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("disconnecting Chrome/Web Serial", doc)
        self.assertIn("cancel the active Protocol v2 transport session", doc)
        self.assertIn("physical-presence attempt", doc)
        self.assertIn("may **not** be suitable", doc)
        self.assertIn("active `UNLOCK REQUEST`", doc)
        self.assertIn("steady-state screen mode", doc)
        self.assertIn("account-view / OTP-revealed coarse modes", doc)
        self.assertIn("one process can normally own", doc)
        self.assertIn("idf.py monitor", doc)

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
