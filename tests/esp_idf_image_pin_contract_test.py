from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import esp_idf_build_image


BUILD_WORKFLOWS = (
    ROOT / ".github" / "workflows" / "foundation.yml",
    ROOT / ".github" / "workflows" / "pages.yml",
    ROOT / ".github" / "workflows" / "release.yml",
    ROOT / ".github" / "workflows" / "issue117-screen-snapshot.yml",
)
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"


class EspIdfImagePinContractTest(unittest.TestCase):
    def test_v555_identity_is_exact_and_immutable(self) -> None:
        self.assertEqual(esp_idf_build_image.ESP_IDF_VERSION, "5.5.5")
        self.assertEqual(esp_idf_build_image.ESP_IDF_IMAGE_REPOSITORY, "espressif/idf")
        self.assertEqual(esp_idf_build_image.ESP_IDF_IMAGE_TAG, "v5.5.5")
        self.assertEqual(
            esp_idf_build_image.ESP_IDF_IMAGE_INDEX_DIGEST,
            "sha256:a9231d0697ab8f7517cc072e93b7c83e04907bfbfba80b6440d7dbbf90665cf2",
        )
        self.assertEqual(
            esp_idf_build_image.ESP_IDF_IMAGE_LINUX_AMD64_MANIFEST_DIGEST,
            "sha256:6e2800a69f1c6521a5651da524f811e237d13e34cad369687916d0ad0bc4ef89",
        )
        self.assertEqual(
            esp_idf_build_image.ESP_IDF_IMAGE_REFERENCE,
            "espressif/idf:v5.5.5@sha256:a9231d0697ab8f7517cc072e93b7c83e04907bfbfba80b6440d7dbbf90665cf2",
        )

    def test_security_relevant_build_workflows_use_repository_owned_reference(self) -> None:
        for path in BUILD_WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            with self.subTest(workflow=path.name):
                self.assertIn(
                    'ESP_IDF_IMAGE="$(python scripts/esp_idf_build_image.py --reference)"',
                    text,
                )
                self.assertIn('"$ESP_IDF_IMAGE"', text)
                self.assertIn("tests/esp_idf_image_pin_contract_test.py", text)

    def test_official_workflows_do_not_embed_mutable_espressif_idf_tags(self) -> None:
        mutable_reference = re.compile(r"espressif/idf:[^\s\"']+")
        for path in (ROOT / ".github" / "workflows").glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(workflow=path.name):
                self.assertEqual(mutable_reference.findall(text), [])

    def test_security_workflow_enforces_image_pin_contract(self) -> None:
        text = SECURITY_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("tests/esp_idf_image_pin_contract_test.py", text)


if __name__ == "__main__":
    unittest.main()
