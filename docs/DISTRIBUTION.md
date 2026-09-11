# V1 Distribution and Update Paths

M5Authenticator V1 distributes one CI-built, user-independent M5StickS3 firmware image through GitHub Releases, the same-site GitHub Pages Web Flasher, and M5Burner. Distribution must never package authenticator accounts, credential identity metadata, TOTP/Wi-Fi secrets, VMK/KEK/BUK/BRK/session keys, user Recovery Packages, device dumps, or a universal production encryption key.

## Release gate

`firmware/release-profile.json` is the machine-readable distribution contract. `scripts/validate_release.py` cross-checks it against firmware version/protocol/storage constants and `firmware/partitions.csv`.

The current main profile is intentionally development-only with `production_release_allowed: false`. Decision #40 superseded the former Production HMAC/eFuse backend. Until the replacement V1 Vault implementation and security closeout complete:

- ordinary CI may build/validate a non-published development package;
- GitHub Pages may show the Firmware Flash surface but must not expose a production firmware manifest/binary;
- a `v*.*.*` Release workflow fails closed before publication;
- a public/synthetic development storage key must never be accepted as production credential protection;
- M5Authenticator-specific eFuse programming is not a release prerequisite or supported V1 security path.

The current prerequisite chain is:

```text
#58 -> #51 -> +-> #52 -+
              +-> #53 -+-> #54 -> #55 -> #56 -> #15
#44 (code merged; physical re-test pending) -----> #56
```

#58 is repository-scanner hardening required before #51 introduces structured cryptographic fixtures. #44's code is already in main, but its remaining non-destructive StickS3 physical validation is an independent release-contract blocker. Task #56 may begin only after both #44 and #55 are complete. Task #15 performs the final security closeout and is the only stage that may enable production release eligibility after the exact implementation is validated. Changing only a tag does not bypass the gate.

## Canonical firmware package

CI builds with exact-pinned ESP-IDF 5.5.5 and runs:

```text
idf.py build
idf.py merge-bin -o m5authenticator-merged.bin -f raw
```

`idf.py merge-bin` runs esptool from ESP-IDF's build directory, so output is `firmware/build/m5authenticator-merged.bin`.

The raw merged image is flashed at offset `0x0`. `scripts/package_firmware.py` rejects an empty image or one whose byte range reaches protected `auth_nvs`.

The package contains:

```text
m5authenticator-v<version>-m5sticks3.bin
factory-manifest.json
update-manifest.json
release-metadata.json
SHA256SUMS
```

`release-metadata.json` contains only non-secret build/device/version/security-profile metadata. Target V1 metadata includes independent Firmware / Protocol / Storage Schema / Vault Format versions. `SHA256SUMS` covers downloadable package files.

There is no separately rebuilt M5Burner package. M5Burner `USER CUSTOM` publication uses the same merged `.bin` used by GitHub Releases and Web Flasher.

## State-preserving flash layout

V1 8 MiB layout:

```text
0x000000  bootloader / partition table / system data
0x030000  ota_0
0x400000  ota_1
0x7d0000  auth_nvs
0x800000  end of flash
```

Both 0x3d0000-byte OTA application slots end before the final 0x30000-byte `auth_nvs` partition.

The merged image is generated without `--pad-to-size`, so its normal write range ends before `auth_nvs`. The same CI-built binary therefore supports:

- **First install:** erase Flash, then flash merged image at `0x0`.
- **Normal update:** do not erase Flash; flash the same merged image at `0x0`, preserving `auth_nvs`.

Preserving `auth_nvs` preserves only the authenticated Encrypted Vault and approved non-secret state. VMK remains RAM-only and is lost on update/reboot, so a provisioned Device returns `LOCKED` after update.

Factory Reset is not an update mechanism. It explicitly erases M5Authenticator Vault/user/registration state; normal update must not expose or invoke a full-Flash erase path.

The pre-release move of `auth_nvs` from `0x12000` to `0x7d0000` is a development-only one-time transition. Existing development data from the old layout may require reprovisioning.

## Security profile transition

Current development builds may still use Protocol 1 / Storage Schema 1 with deliberately public synthetic encrypted-NVS material. They are release-ineligible.

Target V1 production metadata is:

- `PROTOCOL_VERSION = 2`
- `STORAGE_SCHEMA_VERSION = 2`
- `VAULT_FORMAT_VERSION = 1`
- security profile representing application-level Encrypted Vault + Device RAM-only VMK

Task #55 activates the target runtime tuple only when complete end-to-end semantics are implemented. Task #56 replaces development release-profile assumptions after #44/#55 are complete. Task #15 performs final security verification and is the gate for enabling production eligibility.

No release validation path depends on HMAC eFuse initialization.

## GitHub Pages Web Flasher

The Pages site contains:

- Provisioner: browser-local credential/device management over Web Serial
- Firmware Flash: ESP Web Tools 10.4.0 bundled from the exact-pinned dependency

No runtime CDN is used. The Provisioner retains `connect-src 'none'`; the separate Flasher page allows only `connect-src 'self'` so same-origin firmware assets can be fetched.

When production eligibility is enabled, CI places package binary/manifests under `/firmware/`.

### First install — destructive

Uses standard ESP Web Tools install with `factory-manifest.json`. This is explicitly for a new Device or intentional clean installation and performs full-Flash erase before installation.

### Update — preserve authenticator state

Normal Update does not use the generic erase-capable install dialog. M5Authenticator invokes ESP Web Tools 10.4.0 low-level flash API with `eraseFirst=false` unconditionally.

The update path requires:

- same-origin `update-manifest.json`
- exactly one ESP32-S3 firmware part
- offset `0x0`
- the same merged firmware image as other distribution paths

`web/src/firmware-update.test.ts` pins the invariant that Update always calls the flasher with `eraseFirst=false`. There is no erase choice in normal Update UI.

`update-manifest.json` may retain the generic erase prompt as defense-in-depth if opened outside the M5Authenticator UI; it is not the normal execution path.

Until Task #15 enables production eligibility, the Flasher remains fail closed with no production manifest offered.

## GitHub Releases

`.github/workflows/release.yml` runs for SemVer-like `v*.*.*` tags. It:

1. requires a production-eligible release profile;
2. verifies tag equals `v<firmware_version>`;
3. builds/merges firmware in pinned ESP-IDF 5.5.5;
4. packages that exact CI-built image;
5. uploads package files directly to the GitHub Release.

GitHub Actions Artifact is not used as an intermediate or long-term firmware store.

## GitHub Pages staging artifact policy

Pages deployment requires one staging artifact. It is the only intentional Actions Artifact in the current distribution path.

- `retention-days: 1`
- deployment consumes it
- deploy job then deletes that exact artifact ID using repository-scoped token
- ordinary Security/Foundation/Release jobs do not upload Actions Artifacts

No credential-bearing data or user Recovery Package may enter an Actions Artifact.

## M5Burner

M5Burner `USER CUSTOM` publication uses the exact `.bin` from a production GitHub Release.

Do **not** use M5Burner Firmware Export on a provisioned Device. A full-device export can capture the Encrypted Vault and user state; even ciphertext-only credential backups/dumps are prohibited public artifacts under `SECURITY.md`.

Publication procedure:

1. use only `m5authenticator-v<version>-m5sticks3.bin` from the production GitHub Release;
2. choose M5StickS3 device type;
3. use the project repository as source link;
4. upload that CI-built `.bin`;
5. verify version/checksum against `release-metadata.json` / `SHA256SUMS`;
6. never source public firmware from a provisioned Device dump.

M5Burner remains a deliberate manual distribution surface, not the designated state-preserving normal-update path. Repository Actions contain no M5Stack account credentials.

## Build-output retention

Normal PR CI builds firmware for verification and discards it. It does not upload Actions Artifacts.

If physical testing later requires exact non-Release CI binaries, a separate temporary-build storage decision may be introduced. Such storage must remain secret-free and must not become a path for user Vault/Recovery/dump retention.
