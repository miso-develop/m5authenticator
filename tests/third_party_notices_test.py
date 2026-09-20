from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_third_party_notices as notices


class ThirdPartyNoticesTest(unittest.TestCase):
    def test_repository_notice_exactly_covers_current_production_closures(self) -> None:
        web_count, firmware_count = notices.verify()
        self.assertEqual(web_count, 33)
        self.assertEqual(firmware_count, 3)

    def test_web_production_closure_excludes_dev_only_packages(self) -> None:
        closure = notices.web_production_dependencies()
        self.assertIn(("@material/web", "2.2.0"), closure)
        self.assertIn(("@material/web", "2.5.0"), closure)
        self.assertIn(("protobufjs", "7.6.6"), closure)
        for dev_only in (("vite", "8.2.2"), ("vitest", "5.0.0"), ("typescript", "7.0.2")):
            self.assertNotIn(dev_only, closure)

    def test_duplicate_inventory_marker_fails_closed(self) -> None:
        source = notices.DEFAULT_NOTICE.read_text(encoding="utf-8")
        first_marker = notices.MARKER_RE.search(source)
        self.assertIsNotNone(first_marker)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "THIRD_PARTY_NOTICES.md"
            path.write_text(source + "\n" + first_marker.group(0) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(notices.NoticeVerificationError, "duplicate notice marker"):
                notices.verify(notice_path=path)

    def test_stale_or_replaced_web_version_fails_closed(self) -> None:
        source = notices.DEFAULT_NOTICE.read_text(encoding="utf-8")
        current = '<!-- M5AUTH-NOTICE {"scope":"web","name":"hash-wasm","version":"4.12.0"} -->'
        stale = '<!-- M5AUTH-NOTICE {"scope":"web","name":"hash-wasm","version":"9.9.9"} -->'
        self.assertIn(current, source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "THIRD_PARTY_NOTICES.md"
            path.write_text(source.replace(current, stale, 1), encoding="utf-8")
            with self.assertRaisesRegex(notices.NoticeVerificationError, "Web notice inventory drift"):
                notices.verify(notice_path=path)

    def test_agent_skill_notice_cannot_substitute_for_product_notice(self) -> None:
        agent_notice = ROOT / ".agents" / "skills" / "THIRD-PARTY-NOTICES.md"
        self.assertTrue(agent_notice.is_file())
        with self.assertRaisesRegex(notices.NoticeVerificationError, "no structured inventory markers"):
            notices.verify(notice_path=agent_notice)

    def test_firmware_lock_parser_rejects_stale_notice_version(self) -> None:
        source = notices.DEFAULT_NOTICE.read_text(encoding="utf-8")
        current = '<!-- M5AUTH-NOTICE {"scope":"firmware-lock","name":"idf","version":"5.5.5"} -->'
        stale = '<!-- M5AUTH-NOTICE {"scope":"firmware-lock","name":"idf","version":"5.5.4"} -->'
        self.assertIn(current, source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "THIRD_PARTY_NOTICES.md"
            path.write_text(source.replace(current, stale, 1), encoding="utf-8")
            with self.assertRaisesRegex(notices.NoticeVerificationError, "firmware notice inventory drift"):
                notices.verify(notice_path=path)


if __name__ == "__main__":
    unittest.main()
