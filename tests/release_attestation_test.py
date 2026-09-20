from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import esp_idf_build_image
import release_attestation


SOURCE_SHA = "996378b07d8587c0d11e43362590e5d1062ad8c2"
WORKFLOW_SHA = "b" * 40


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def synthetic_package(base: Path) -> Path:
    package = base / "release"
    package.mkdir()
    firmware = package / "firmware.bin"
    firmware.write_bytes(b"synthetic-firmware")
    metadata = package / "release-metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "build_commit": SOURCE_SHA,
                "exact_release": True,
                "build_environment": {
                    "esp_idf": esp_idf_build_image.provenance(),
                },
            }
        ),
        encoding="utf-8",
    )
    notice = package / "THIRD_PARTY_NOTICES.md"
    notice.write_text("# synthetic third-party notices\n", encoding="utf-8")
    checksums = package / "SHA256SUMS"
    checksums.write_text(
        f"{sha256(firmware)}  {firmware.name}\n"
        f"{sha256(metadata)}  {metadata.name}\n"
        f"{sha256(notice)}  {notice.name}\n",
        encoding="utf-8",
    )
    return package


class ReleaseAttestationTest(unittest.TestCase):
    def test_predicate_binds_source_workflow_asset_and_immutable_build_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = synthetic_package(Path(directory))
            predicate = release_attestation.build_predicate(
                package,
                SOURCE_SHA,
                "miso-develop/m5authenticator",
                "miso-develop/m5authenticator/.github/workflows/release.yml@refs/tags/v0.2.0",
                WORKFLOW_SHA,
                "12345",
                "2",
            )

            self.assertNotEqual(SOURCE_SHA, WORKFLOW_SHA)
            self.assertEqual(predicate["source_commit"], SOURCE_SHA)
            self.assertEqual(predicate["workflow"]["workflow_sha"], WORKFLOW_SHA)
            self.assertEqual(predicate["workflow"]["run_id"], 12345)
            self.assertEqual(predicate["workflow"]["run_attempt"], 2)
            self.assertEqual(
                predicate["build_environment"]["esp_idf"],
                esp_idf_build_image.provenance(),
            )
            self.assertEqual(
                predicate["sha256sums_sha256"],
                sha256(package / "SHA256SUMS"),
            )
            subjects = {item["name"]: item["sha256"] for item in predicate["artifacts"]}
            self.assertEqual(subjects["firmware.bin"], sha256(package / "firmware.bin"))
            self.assertEqual(
                subjects["release-metadata.json"],
                sha256(package / "release-metadata.json"),
            )
            self.assertEqual(
                subjects["THIRD_PARTY_NOTICES.md"],
                sha256(package / "THIRD_PARTY_NOTICES.md"),
            )

    def test_asset_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = synthetic_package(Path(directory))
            (package / "firmware.bin").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                release_attestation.build_predicate(
                    package,
                    SOURCE_SHA,
                    "miso-develop/m5authenticator",
                    "workflow-ref",
                    WORKFLOW_SHA,
                    "1",
                    "1",
                )

    def test_build_image_provenance_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = synthetic_package(Path(directory))
            metadata_path = package / "release-metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["build_environment"]["esp_idf"]["index_digest"] = "sha256:" + "0" * 64
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            (package / "SHA256SUMS").write_text(
                f"{sha256(package / 'firmware.bin')}  firmware.bin\n"
                f"{sha256(metadata_path)}  release-metadata.json\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "immutable build identity"):
                release_attestation.build_predicate(
                    package,
                    SOURCE_SHA,
                    "miso-develop/m5authenticator",
                    "workflow-ref",
                    WORKFLOW_SHA,
                    "1",
                    "1",
                )

    def test_source_commit_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = synthetic_package(Path(directory))
            with self.assertRaisesRegex(ValueError, "build_commit"):
                release_attestation.build_predicate(
                    package,
                    "c" * 40,
                    "miso-develop/m5authenticator",
                    "workflow-ref",
                    WORKFLOW_SHA,
                    "1",
                    "1",
                )


if __name__ == "__main__":
    unittest.main()
