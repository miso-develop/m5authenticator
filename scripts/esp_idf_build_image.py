#!/usr/bin/env python3
"""Immutable ESP-IDF build-image identity used by official CI paths."""

from __future__ import annotations

import argparse
import json

ESP_IDF_VERSION = "5.5.5"
ESP_IDF_IMAGE_REPOSITORY = "espressif/idf"
ESP_IDF_IMAGE_TAG = "v5.5.5"
# Docker Hub multi-platform index digest for espressif/idf:v5.5.5.
ESP_IDF_IMAGE_INDEX_DIGEST = (
    "sha256:a9231d0697ab8f7517cc072e93b7c83e04907bfbfba80b6440d7dbbf90665cf2"
)
# Docker Hub child manifest currently selected by GitHub's linux/amd64 hosted runners.
ESP_IDF_IMAGE_LINUX_AMD64_MANIFEST_DIGEST = (
    "sha256:6e2800a69f1c6521a5651da524f811e237d13e34cad369687916d0ad0bc4ef89"
)
ESP_IDF_IMAGE_REFERENCE = (
    f"{ESP_IDF_IMAGE_REPOSITORY}:{ESP_IDF_IMAGE_TAG}@{ESP_IDF_IMAGE_INDEX_DIGEST}"
)


def provenance() -> dict[str, str]:
    return {
        "version": ESP_IDF_VERSION,
        "repository": ESP_IDF_IMAGE_REPOSITORY,
        "tag": ESP_IDF_IMAGE_TAG,
        "index_digest": ESP_IDF_IMAGE_INDEX_DIGEST,
        "linux_amd64_manifest_digest": ESP_IDF_IMAGE_LINUX_AMD64_MANIFEST_DIGEST,
        "reference": ESP_IDF_IMAGE_REFERENCE,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.reference == args.json:
        parser.error("choose exactly one of --reference or --json")
    if args.reference:
        print(ESP_IDF_IMAGE_REFERENCE)
    else:
        print(json.dumps(provenance(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
