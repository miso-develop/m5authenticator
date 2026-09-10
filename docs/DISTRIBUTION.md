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
idf.py merge-bin -o m5authenticator-merged.bin -f raw
```

`idf.py merge-bin` runs esptool from ESP-IDF's build directory, so the merged output is created as `firmware/build/m5authenticator-merged.bin`.

The raw merged image is flashed at offset `0x0`. `scripts/package_firmware.py` rejects an empty image or one whose byte range reaches the protected `auth_nvs` partition. The script produces:

```text
m5authenticator-v<version>-m5sticks3.bin
factory-manifest.json
update-manifest.json
release-metadata.json
SHA256SUMS
```

`release-metadata.json` contains only non-secret build/device/version/security-profile metadata. `SHA256SUMS` covers the downloadable package files.

There is no separately rebuilt or invented M5Burner firmware package. M5Burner `USER CUSTOM` publication uses the same merged `.bin` that GitHub Releases and the Web Flasher use.

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

Factory Reset is not an update mechanism. Factory Reset explicitly erases `auth_nvs`; a normal update must not expose or invoke a full-flash erase operation.

Task #14 moved `auth_nvs` from its early development position to the V1 release position before any production release. Existing development data from the old layout is not migration-compatible and must be reprovisioned once after this transition.

## GitHub Pages Web Flasher

The Pages site contains two entries:

- Provisioner: account/device management over local Web Serial
- Firmware Flash: ESP Web Tools 10.4.0 bundled from the exact-pinned NPM dependency

No runtime CDN is used. The Provisioner keeps `connect-src 'none'`; the separate Flasher page allows only `connect-src 'self'` so firmware manifests and binaries can be fetched from the same Pages site.

When production release eligibility is enabled, CI places the package binary and manifests under the site's `/firmware/` path. Two clearly separated operations are shown:

### First install — destructive

Uses the standard ESP Web Tools install button with `factory-manifest.json`. This operation is explicitly for a new device or an intentional clean installation and performs a full-flash erase before installation.

### Update — preserve authenticator data

The normal update button does **not** use ESP Web Tools' generic install dialog because the generic no-Improv new-install path can offer or perform a full-flash erase. Instead, M5Authenticator calls ESP Web Tools 10.4.0's low-level flash API with `eraseFirst=false` unconditionally.

The update implementation also requires:

- a same-origin `update-manifest.json`;
- exactly one ESP32-S3 firmware part;
- that part at offset `0x0`;
- the same merged firmware image used by the other distribution paths.

`web/src/firmware-update.test.ts` pins the critical invariant that the update wrapper always calls the low-level flasher with `eraseFirst=false`. There is no erase choice in the normal Update UI. Intentional user-state deletion remains the explicit Factory Reset operation in the Provisioner.

`update-manifest.json` keeps the generic ESP Web Tools erase prompt enabled only as a defense-in-depth warning if someone opens that manifest outside the M5Authenticator Update UI. It is not the normal update execution path.

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

M5Stack's current M5Burner workflow uses `USER CUSTOM` -> `Publish` and asks for Name, Version, Description, Device Type, GitHub link, Firmware, and Cover metadata. The GitHub Release provides the exact `.bin`, version metadata, and checksum needed for that manual publication step.

For M5Authenticator, **do not use M5Burner's Firmware Export function on a provisioned device**, even though generic M5Burner documentation recommends Export as a convenient source for publishing. A full-device export can capture credential-bearing flash contents. That conflicts with `SECURITY.md`.

Instead:

1. use only `m5authenticator-v<version>-m5sticks3.bin` from the production GitHub Release;
2. choose M5StickS3 as the device type;
3. use the project GitHub repository as the source link;
4. select that CI-built `.bin` as the M5Burner `FirmWare` upload;
5. verify version/checksum against `release-metadata.json` and `SHA256SUMS`;
6. never source a public M5Burner upload from a user/provisioned device dump.

M5Burner community publication remains a deliberate manual operation after Task #26 makes the build production eligible. M5Burner is a distribution/install surface, not the designated state-preserving normal-update path; normal updates use the Web Flasher Update operation described above. The repository does not store M5Stack account credentials in GitHub Actions.

## Build-output retention

Normal pull-request CI builds firmware only for verification and then discards it. It does not upload Actions Artifacts. If later physical testing needs an exact non-Release CI binary, the separate temporary-build storage plan (for example Cloudflare R2 with short lifecycle) is introduced at that point rather than turning normal CI artifacts into long-term storage.
