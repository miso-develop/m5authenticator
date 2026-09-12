# V1 Distribution and Update Paths

M5Authenticator V1 distributes one CI-built, user-independent M5StickS3 firmware image through GitHub Releases, the same-site GitHub Pages Web Flasher, and M5Burner. Distribution must never package authenticator accounts, credential identity metadata, TOTP/Wi-Fi secrets, VMK/KEK/BUK/BRK/session keys, user Recovery Packages, device dumps, or a universal production encryption key.

For the durable V1 requirements and cross-component flow overview, see `docs/V1_REQUIREMENTS.md` and `docs/ARCHITECTURE.md`.

## Release gate

`firmware/release-profile.json` is the machine-readable distribution contract. `scripts/validate_release.py` cross-checks it against firmware version/protocol/storage/Vault constants, the canonical firmware bootstrap, the release component surface/core-dump policy, and `firmware/partitions.csv`.

Current V1 runs the canonical Protocol 2 / Storage Schema 2 / Vault Format 1 application. Task #56 replaced the former development-synthetic release profile with the V1 security contract, Task #15 completed the cross-surface security closeout before enabling the final publication eligibility switch, and Task #16 promoted the settled current truth into durable repository documentation.

Release-profile format 2 requires:

- `PROTOCOL_VERSION = 2`
- `STORAGE_SCHEMA_VERSION = 2`
- `VAULT_FORMAT_VERSION = 1`
- security profile `encrypted-vault-ram-only-vmk`, version 1
- credential-bearing Flash persistence only as an authenticated Encrypted Vault
- VMK persistence `ram-only`
- no public/synthetic Flash credential key
- no M5Authenticator-specific eFuse requirement
- post-update runtime state `LOCKED`
- `production_release_allowed: true` only after the V1 security closeout is green

The final repository profile is production-eligible. Eligibility does not bypass any underlying security contract: Protocol/Storage/Vault/security-profile/bootstrap/component-surface/core-dump/layout checks remain mandatory, and Release/Pages workflows invoke `--require-production` fail closed.

Task #15 closeout additionally pins that:

- ESP-IDF core dumps are explicitly disabled for the release firmware so credential-bearing RAM is not persisted through crash capture;
- retired Protocol 1 / Storage Schema 1 credential-management sources are absent from the release component surface;
- the actual merged firmware image is scanned for retired credential-management markers before packaging/publication;
- a synthetic full Vault ciphertext inspection verifies that TOTP secret material, issuer/account/display-name, SSID/password, and VMK do not appear verbatim in the credential-bearing persisted ciphertext;
- project repository security scanning remains an independent blocking layer.

The V1 release/security/documentation closeout chain is complete:

```text
#56 release contract -> #15 security closeout -> #16 durable documentation
```

Future changes must preserve or explicitly supersede these contracts through a new Decision/Spec rather than silently editing around the release gate.

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

`release-metadata.json` contains only non-secret build/device/release-contract metadata, including independent Firmware / Protocol / Storage Schema / Vault Format versions, security profile/version, VMK persistence mode, post-update state, and production-eligibility state. `SHA256SUMS` covers downloadable package files.

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

Preserving `auth_nvs` preserves the authenticated Encrypted Vault and registration/non-secret runtime state. VMK is not persisted there or anywhere else in Device Flash. Firmware update/reboot therefore preserves the encrypted Vault but destroys the RAM-only VMK, and a provisioned Device returns `LOCKED` after update.

Factory Reset is not an update mechanism. It explicitly erases M5Authenticator Vault/user/registration state; normal update must not expose or invoke a full-Flash erase path.

The pre-release move of `auth_nvs` from `0x12000` to `0x7d0000` is a development-only one-time transition. Existing development data from the old layout may require reprovisioning.

## V1 security profile

The release gate does not rely on encrypted NVS protected by a public development key, a universal production key, or a project-specific HMAC/eFuse root. User credential material is persisted only in the application-level authenticated Encrypted Vault. Its random 256-bit VMK exists on Device only while the runtime is UNLOCKED and is held in RAM only.

`scripts/validate_release.py` fails closed if the canonical production bootstrap regresses to the legacy `DevSecurityBackend` / plaintext storage/provisioning path, if retired Schema 1 release components are restored, if core-dump persistence is re-enabled, if release-profile security fields no longer describe the V1 Vault contract, or if Firmware/Protocol/Storage/Vault metadata diverges.

Legacy implementation code may remain in repository history or non-release test/support surfaces, but production eligibility must never be satisfied by a release image that exposes public/synthetic credential-protection or retired plaintext-management material.

No release validation path depends on HMAC eFuse initialization.

## GitHub Pages Web Flasher

The Pages site contains:

- Provisioner: browser-local credential/device management over Web Serial
- Firmware Flash: ESP Web Tools 10.4.0 bundled from the exact-pinned dependency

No runtime CDN is used. The Provisioner retains `connect-src 'none'`; the separate Flasher page allows only `connect-src 'self'` so same-origin firmware assets can be fetched.

With production eligibility enabled, CI may place the exact validated package binary/manifests under `/firmware/` only after the same V1 release/profile and merged-image security checks pass.

### First install — destructive

Uses standard ESP Web Tools install with `factory-manifest.json`. This is explicitly for a new Device or intentional clean installation and performs the installation semantics documented by the Flasher UI.

### Update — preserve authenticator state

Normal Update does not use the generic erase-capable install dialog. M5Authenticator invokes ESP Web Tools 10.4.0 low-level flash API with `eraseFirst=false` unconditionally.

The update path requires:

- same-origin `update-manifest.json`
- exactly one ESP32-S3 firmware part
- offset `0x0`
- the same merged firmware image as other distribution paths

`web/src/firmware-update.test.ts` pins the invariant that Update always calls the flasher with `eraseFirst=false`. There is no erase choice in normal Update UI.

`update-manifest.json` may retain the generic erase prompt as defense-in-depth if opened outside the M5Authenticator UI; it is not the normal execution path.

## GitHub Releases

`.github/workflows/release.yml` runs for SemVer-like `v*.*.*` tags. It:

1. requires the exact V1 security contract and production eligibility;
2. verifies tag equals `v<firmware_version>`;
3. builds/merges firmware in pinned ESP-IDF 5.5.5;
4. verifies the actual merged firmware security surface;
5. packages that exact CI-built image;
6. uploads package files directly to the GitHub Release.

The workflow contains no M5Authenticator-specific eFuse burn/read/provisioning step and no universal production encryption key input.

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
