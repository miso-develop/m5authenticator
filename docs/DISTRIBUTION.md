# V1 Distribution and Update Paths

M5Authenticator V1 distributes one CI-built, user-independent M5StickS3 firmware image through GitHub Releases, the same-site GitHub Pages Web Flasher, and M5Burner. Distribution must never package authenticator accounts, TOTP secrets, Wi-Fi credentials, device dumps, or a universal production encryption key.

## Release gate

`firmware/release-profile.json` is the machine-readable distribution contract. `scripts/validate_release.py` cross-checks it against firmware version/protocol/storage constants and `firmware/partitions.csv`.

The current profile is intentionally `development-synthetic` with `production_release_allowed: false`. This means:

- ordinary CI may build and validate a non-published development package;
- GitHub Pages shows the Firmware Flash surface but does not expose a flash manifest/binary;
- a `v*.*.*` Release workflow fails closed before publishing anything;
- Task #26 must install the production device-specific security backend and deliberately change the release eligibility contract before public firmware distribution is enabled.

Changing only a tag does not bypass this gate.

## Canonical firmware package

CI builds with exact-pinned ESP-IDF 5.5.5 and runs:

```text
idf.py build
idf.py merge-bin -o build/m5authenticator-merged.bin -f raw
```

The raw merged image is flashed at offset `0x0`. `scripts/package_firmware.py` rejects an empty image or one whose byte range reaches the protected `auth_nvs` partition. The script produces:

```text
m5authenticator-v<version>-m5sticks3.bin
factory-manifest.json
update-manifest.json
release-metadata.json
m5authenticator-v<version>-m5sticks3-m5burner.zip
SHA256SUMS
```

`release-metadata.json` contains only non-secret build/device/version/security-profile metadata. `SHA256SUMS` covers the downloadable package files.

The M5Burner ZIP contains the same merged image as `firmware/m5authenticator_0x0.bin` plus compatibility metadata. There is no separately rebuilt M5Burner firmware.

## State-preserving flash layout

The V1 8 MiB release layout places both 0x3d0000-byte OTA application slots before `auth_nvs`, and reserves the final 0x30000 bytes for `auth_nvs`:

```text
0x000000  bootloader / partition table / system data
0x030000  ota_0
0x400000  ota_1
0x7d0000  auth_nvs
0x800000  end of flash
```

The merged image is generated without `--pad-to-size`, so its normal write range ends before `auth_nvs`. This allows the **same CI-built binary** to serve both installation modes:

- **First install:** erase flash, then flash the merged image at `0x0`.
- **Normal update:** do not erase flash; flash the same merged image at `0x0`. `auth_nvs` remains outside the write range and therefore preserves accounts, secrets, Wi-Fi credentials, and user settings.

Factory Reset is not an update mechanism. Factory Reset explicitly erases `auth_nvs`; a normal update must not.

Task #14 moved `auth_nvs` from its early development position to the V1 release position before any production release. Existing development data from the old layout is not migration-compatible and must be reprovisioned once after this transition.

## GitHub Pages Web Flasher

The Pages site contains two entries:

- Provisioner: account/device management over local Web Serial
- Firmware Flash: ESP Web Tools 10.4.0 bundled from the exact-pinned NPM dependency

No runtime CDN is used. The Provisioner keeps `connect-src 'none'`; the separate Flasher page allows only `connect-src 'self'` so ESP Web Tools can fetch same-origin manifests and firmware binaries.

When production release eligibility is enabled, CI places the package binary and manifests under the site's `/firmware/` path. Two clearly separated install choices are shown:

### First install — destructive

Uses `factory-manifest.json`. This path is intended for an erased/new device and performs the new-install erase behavior.

### Update — preserve authenticator data

Uses `update-manifest.json`, which requests ESP Web Tools to show its new-install erase prompt. For a normal update, the user must choose **not to erase**. The merged firmware itself does not include `auth_nvs` and does not intentionally overwrite it.

Until Task #26 enables production release eligibility, the Flasher page remains visible but fail-closed: no firmware manifest is offered.

## GitHub Releases

`.github/workflows/release.yml` runs only for SemVer-like `v*.*.*` tags. It:

1. requires a production-eligible release profile;
2. verifies the tag equals `v<firmware_version>`;
3. builds and merges firmware in the pinned ESP-IDF 5.5.5 container;
4. packages that exact CI-built image;
5. uploads package files directly to the GitHub Release using the repository token.

GitHub Actions Artifact is not used as an intermediate or long-term firmware store.

## GitHub Pages staging artifact policy

GitHub Pages deployment requires a Pages staging artifact. It is the only intentional Actions Artifact in the distribution path.

- `retention-days: 1` is explicit;
- deployment consumes the artifact;
- the deploy job then deletes that exact artifact ID immediately using the repository-scoped GitHub token;
- ordinary Security/Foundation/Release jobs do not upload Actions Artifacts.

## M5Burner

M5Stack's current M5Burner workflow uses `USER CUSTOM` -> `Publish` and asks for Name, Version, Description, Device Type, GitHub link, Firmware, and Cover metadata. The release package provides the firmware/build metadata needed for that manual publication step.

For M5Authenticator, **do not use M5Burner's Firmware Export function on a provisioned device**, even though generic M5Burner documentation recommends Export as a convenient source for publishing. A full-device export can capture credential-bearing flash contents. That conflicts with `SECURITY.md`.

Instead:

1. use only the secret-free firmware produced by the production Release workflow;
2. choose M5StickS3 as the device type;
3. use the project GitHub repository as the source link;
4. upload the CI-built merged firmware/package from the GitHub Release;
5. verify version/checksum against `release-metadata.json` and `SHA256SUMS`;
6. never source a public M5Burner upload from a user/provisioned device dump.

M5Burner community publication remains a deliberate manual operation after Task #26 makes the build production eligible. The repository prepares the reproducible source package; it does not store M5Stack account credentials in GitHub Actions.

## Build-output retention

Normal pull-request CI builds firmware only for verification and then discards it. It does not upload Actions Artifacts. If later physical testing needs an exact non-Release CI binary, the separate temporary-build storage plan (for example Cloudflare R2 with short lifecycle) is introduced at that point rather than turning normal CI artifacts into long-term storage.
