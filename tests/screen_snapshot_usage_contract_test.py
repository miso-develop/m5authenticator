from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/testing/screen-snapshot-diagnostics.md"
HELPER = ROOT / "tools/diagnostics/screen_snapshot.py"
WORKFLOW = ROOT / ".github/workflows/issue117-screen-snapshot.yml"


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

    def test_serial_control_lines_are_preconfigured_inactive_and_caveat_is_explicit(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        helper = HELPER.read_text(encoding="utf-8")
        self.assertIn("DTR = inactive / False", doc)
        self.assertIn("RTS = inactive / False", doc)
        self.assertIn("only then calls `open()`", doc)
        self.assertIn("may momentarily activate or glitch RTS/DTR", doc)
        self.assertIn("Human Gate", doc)
        self.assertIn("port.dtr = False", helper)
        self.assertIn("port.rts = False", helper)
        self.assertLess(helper.index("port.dtr = False"), helper.index("port.open()"))
        self.assertLess(helper.index("port.rts = False"), helper.index("port.open()"))
        self.assertNotIn("port.dtr = True", helper)
        self.assertNotIn("port.rts = True", helper)

    def test_nonfinite_timeout_is_rejected_before_serial_open(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        helper = HELPER.read_text(encoding="utf-8")
        self.assertIn("must be finite and greater than zero", doc)
        self.assertIn("math.isfinite(timeout_seconds)", helper)
        validate_index = helper.index("_validate_timeout_seconds(timeout_seconds)", helper.index("def read_snapshot"))
        import_index = helper.index("import serial", helper.index("def read_snapshot"))
        self.assertLess(validate_index, import_index)

    def test_human_gate_rejects_observation_induced_reset_or_state_change(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("at least **5 consecutive times without power cycling**", doc)
        self.assertIn("`Starting...` does not appear", doc)
        self.assertIn("Device does not reboot", doc)
        self.assertIn("download/bootloader mode", doc)
        self.assertIn("screen/runtime state does not change unexpectedly", doc)
        self.assertIn("snapshot matches the physical LCD coarse state", doc)
        self.assertIn("no unsolicited serial output", doc)
        self.assertIn("Any visible reset/glitch/state transition is **FAIL**", doc)

    def test_workflow_tracks_vault_runtime_snapshot_dependency(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('"firmware/components/m5auth_vault_runtime/**"', workflow)
        for required in (
            '"firmware/components/m5auth_device_sticks3/**"',
            '"firmware/components/m5auth_time/**"',
            '"firmware/components/m5auth_session/**"',
        ):
            self.assertIn(required, workflow)

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
