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
        self.assertNotIn('id\":9002', helper)

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

    def test_pre_request_sync_is_bounded_defense_in_depth_not_root_fix(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        helper = HELPER.read_text(encoding="utf-8")
        self.assertIn("continuous quiet", doc)
        self.assertIn("before sending the first and only diagnostic request", doc)
        self.assertIn("sends no diagnostic request", doc)
        self.assertIn("not a retry", doc)
        self.assertIn("defense-in-depth", doc)
        self.assertIn("not sufficient", doc)
        self.assertIn("SCREEN_SNAPSHOT_SYNC=", doc)
        for field in (
            "pre_purge_waiting",
            "pre_request_data",
            "pre_request_bytes",
            "pre_request_newline",
            "first_byte",
            "quiet_ms",
            "invocation",
        ):
            self.assertIn(field, doc)
            self.assertIn(field, helper)
        self.assertIn("_PRE_REQUEST_QUIET_SECONDS", helper)
        self.assertIn("_PRE_REQUEST_SYNC_MAX_SECONDS", helper)
        self.assertIn("_MAX_PRE_REQUEST_DRAIN_BYTES", helper)

    def test_completed_malformed_current_frame_relation_is_sanitized_and_fail_closed(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        helper = HELPER.read_text(encoding="utf-8")
        for field in (
            "frame_len",
            "utf8",
            "first_object",
            "last_object",
            "nul",
            "control",
            "json_error",
            "id_position",
            "request_len",
            "prefix_len",
            "prefix_equals_request_prefix",
            "prefix_equals_request_first64",
            "request_prefix_match_len",
            "suffix_json_valid",
            "suffix_id_matches_current",
            "suffix_allowlist_valid",
            "post_request_first_byte",
            "object_starts",
            "object_ends",
            "shape",
        ):
            self.assertIn(field, doc)
            self.assertIn(field, helper)
        self.assertIn("diagnosis only", doc)
        self.assertIn("It does **not** skip that current frame", doc)
        self.assertIn("retry automatically", doc)
        self.assertIn("must not overwrite the failed run", doc)
        self.assertIn("never print the raw serial payload", doc)
        self.assertIn("does not become PASS", doc)
        self.assertNotIn("errors=\"replace\"", helper)

    def test_64_byte_transport_boundary_is_documented_without_overclaim(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("64-byte", doc)
        self.assertIn("full USB packet", doc)
        self.assertIn("short packet or ZLP", doc)
        self.assertIn("cannot by itself prove", doc)
        self.assertIn("request begins with `{`", doc)
        self.assertIn("first_object=no", doc)

    def test_device_tx_framing_and_transport_residual_risk_are_documented(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("common `write_response()` path", doc)
        self.assertIn("one logical stdio write", doc)
        self.assertIn("`stdout` FILE lock", doc)
        self.assertIn("default-OFF production firmware", doc)
        self.assertIn("does **not** enable the screen-snapshot operation", doc)
        self.assertIn("Direct/early/ROM writers", doc)
        self.assertIn("abandon bytes", doc)
        self.assertIn("cannot reconstruct bytes already lost", doc)

    def test_human_gate_requires_clean_first_open_case_before_repetition(self) -> None:
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("first helper invocation after flash/reboot", doc)
        self.assertIn("helper has never opened the COM port", doc)
        self.assertIn("must be tested separately", doc)
        self.assertIn("record the sanitized `SCREEN_SNAPSHOT_SYNC` line", doc)
        self.assertIn("prefix_equals_request_first64", doc)
        self.assertIn("suffix_allowlist_valid", doc)
        self.assertIn("at least **5 consecutive times without power cycling**", doc)
        self.assertIn("`Starting...` does not appear", doc)
        self.assertIn("Device does not reboot", doc)
        self.assertIn("download/bootloader mode", doc)
        self.assertIn("screen/runtime state does not change unexpectedly", doc)
        self.assertIn("snapshot matches the physical LCD coarse state", doc)
        self.assertIn("malformed current-ID completed frame", doc)
        self.assertIn("return to Integration", doc)

    def test_workflow_tracks_relation_suite_and_vault_runtime_dependency(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("tests/screen_snapshot_request_relation_test.py", workflow)
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
