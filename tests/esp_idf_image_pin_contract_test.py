from __future__ import annotations

import re
import sys
import tempfile
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
PACKAGE_SCRIPT = ROOT / "scripts" / "package_firmware.py"
WORKFLOW_EXTENSIONS = (".yml", ".yaml")
MUTABLE_ESP_IDF_REFERENCE = re.compile(r"espressif/idf:[^\s\"']+")


def workflow_files(workflows_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in workflows_dir.iterdir()
        if path.is_file() and path.suffix in WORKFLOW_EXTENSIONS
    )


def mutable_esp_idf_references(workflows_dir: Path) -> dict[str, list[str]]:
    violations: dict[str, list[str]] = {}
    for path in workflow_files(workflows_dir):
        matches = MUTABLE_ESP_IDF_REFERENCE.findall(path.read_text(encoding="utf-8"))
        if matches:
            violations[path.name] = matches
    return violations


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
        self.assertEqual(
            mutable_esp_idf_references(ROOT / ".github" / "workflows"),
            {},
        )

    def test_mutable_reference_guard_rejects_yml_and_yaml_workflows(self) -> None:
        for extension in WORKFLOW_EXTENSIONS:
            with self.subTest(extension=extension), tempfile.TemporaryDirectory() as directory:
                workflows_dir = Path(directory)
                filename = f"regression-probe{extension}"
                (workflows_dir / filename).write_text(
                    "jobs:\n  firmware:\n    container: espressif/idf:v5.5.5\n",
                    encoding="utf-8",
                )
                self.assertEqual(
                    mutable_esp_idf_references(workflows_dir),
                    {filename: ["espressif/idf:v5.5.5"]},
                )

    def test_release_package_records_exact_build_image_provenance(self) -> None:
        text = PACKAGE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("import esp_idf_build_image", text)
        self.assertIn('"esp_idf": esp_idf_build_image.provenance()', text)
        provenance = esp_idf_build_image.provenance()
        self.assertEqual(provenance["version"], "5.5.5")
        self.assertEqual(provenance["repository"], "espressif/idf")
        self.assertEqual(provenance["tag"], "v5.5.5")
        self.assertEqual(provenance["index_digest"], esp_idf_build_image.ESP_IDF_IMAGE_INDEX_DIGEST)
        self.assertEqual(
            provenance["linux_amd64_manifest_digest"],
            esp_idf_build_image.ESP_IDF_IMAGE_LINUX_AMD64_MANIFEST_DIGEST,
        )
        self.assertEqual(provenance["reference"], esp_idf_build_image.ESP_IDF_IMAGE_REFERENCE)

    def test_security_workflow_enforces_image_pin_contract(self) -> None:
        text = SECURITY_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("tests/esp_idf_image_pin_contract_test.py", text)


if __name__ == "__main__":
    unittest.main()
