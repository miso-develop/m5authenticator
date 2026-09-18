# V1 Distribution and Update Paths

M5Authenticator V1 distributes CI-built, user-independent M5StickS3 firmware through GitHub Releases, the same-site GitHub Pages Web Flasher, and M5Burner. Distribution must never package authenticator accounts, credential identity metadata, TOTP/Wi-Fi secrets, VMK/KEK/BUK/BRK/session keys, user Recovery Packages, device dumps, or a universal production encryption key.

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

CI builds with ESP-IDF 5.5.5 using an immutable Docker image identity. The human-readable tag remains `espressif/idf:v5.5.5`, while execution is pinned to the multi-platform index digest recorded in `scripts/esp_idf_build_image.py`:

```text
espressif/idf:v5.5.5@sha256:a9231d0697ab8f7517cc072e93b7c83e04907bfbfba80b6440d7dbbf90665cf2
```

For GitHub-hosted `linux/amd64` runners, that index currently selects manifest digest `sha256:6e2800a69f1c6521a5651da524f811e237d13e34cad369687916d0ad0bc4ef89`. The tag is retained only as reviewable version provenance; the digest is the execution identity. Changing either digest is therefore an explicit supply-chain change, not an implicit ESP-IDF tag refresh.

Official Foundation, Pages, and Release builds do not mount the authoritative checkout into the ESP-IDF container. `scripts/ci_esp_idf_isolated_build.py` copies only `firmware/` into a disposable runner-temporary workspace, mounts that isolated copy read/write, and verifies that the isolated `dependencies.lock` still equals the authoritative lockfile after the build. Host-side verification, packaging, Web building, and publication continue from the untouched checkout or a fresh checkout in a later job.

The isolated build runs:

```text
idf.py build
idf.py merge-bin -o m5authenticator-merged.bin -f raw
```

`idf.py merge-bin` runs esptool from ESP-IDF's build directory, so the merged First Install/M5Burner image is the isolated build's `firmware/build/m5authenticator-merged.bin`.

Normal Update does **not** reuse the merged offset-0 image. `scripts/package_firmware.py` additionally packages the exact ESP-IDF build outputs:

```text
firmware/build/bootloader/bootloader.bin
firmware/build/partition_table/partition-table.bin
firmware/build/m5authenticator.bin
```

The package contains:

```text
m5authenticator-v<version>-m5sticks3.bin
m5authenticator-v<version>-m5sticks3-update-bootloader.bin
m5authenticator-v<version>-m5sticks3-update-partition-table.bin
m5authenticator-v<version>-m5sticks3-update-ota0.bin
factory-manifest.json
update-manifest.json
release-metadata.json
SHA256SUMS
```

The merged `.bin` is the destructive First Install / M5Burner artifact. The three `update-*` binaries are only for the state-preserving Web Normal Update path.

Before packaging succeeds, `scripts/package_firmware.py` validates the real binary sizes against the flash write windows and rejects any Normal Update part whose write range overlaps a partition other than the intended `ota_0` application slot. This mechanically protects ordinary `nvs`, `otadata`, `phy_init`, `ota_1`, and `auth_nvs`; in particular the #107 persistent-state contract requires preservation of both ordinary `nvs` and `auth_nvs`.

`release-metadata.json` contains only non-secret build/device/release-contract metadata, including independent Firmware / Protocol / Storage Schema / Vault Format versions, security profile/version, VMK persistence mode, post-update state, production-eligibility state, the validated Normal Update write plan, and `build_environment.esp_idf` provenance. The ESP-IDF provenance records the repository, human-readable `v5.5.5` tag, immutable index digest, selected `linux/amd64` manifest digest, and exact tag-plus-digest reference. `SHA256SUMS` covers all downloadable package files.

There is no separately rebuilt M5Burner package. M5Burner `USER CUSTOM` publication uses the merged `.bin` from the same CI build.

## State-preserving flash layout

V1 8 MiB layout:

```text
0x000000  bootloader
0x008000  partition table
0x009000  nvs       (stable Device identity + active Trusted Browser registration)
0x00f000  otadata
0x011000  phy_init
0x030000  ota_0
0x400000  ota_1
0x7d0000  auth_nvs  (canonical encrypted Vault + generation/last-used state)
0x800000  end of flash
```

The Normal Update write plan is deliberately partition-aware:

```text
bootloader       @ 0x000000, must end before 0x008000
partition table  @ 0x008000, must end before 0x009000
ota_0 app         @ 0x030000, must end before 0x400000
```

Consequently Normal Update does not write ordinary `nvs`, `otadata`, `phy_init`, `ota_1`, or `auth_nvs`.

The two persistent M5Authenticator ownership partitions are intentionally separate:

- ordinary `nvs`: stable Device identity and active Trusted Browser registration;
- `auth_nvs`: authenticated Encrypted Vault plus canonical generation/last-used state.

Both must survive Normal Update. Preserving only `auth_nvs` is insufficient and creates a fail-closed Vault-without-registration state; this is the release-blocking defect captured by #107.

VMK is not persisted in either partition or anywhere else in Device Flash. Firmware update/reboot therefore preserves persistent state but destroys the RAM-only VMK, so a provisioned Device returns `LOCKED` after update.

The two installation semantics are therefore:

- **First install:** destructive install using the merged offset-0 image; existing state may be erased.
- **Normal update:** no full erase; write only the validated bootloader, partition-table, and `ota_0` application parts listed above.

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

With production eligibility enabled, CI may place the exact validated package binaries/manifests under `/firmware/` only after the same V1 release/profile and firmware security checks pass. The ESP-IDF container receives only a disposable copy of `firmware/`; it cannot rewrite `web/`, repository validation scripts, or the authoritative checkout that is subsequently used to build same-origin production content.

### First install — destructive

Uses standard ESP Web Tools install with `factory-manifest.json`. `factory-manifest.json` contains one merged firmware part at offset `0x0`. This path is explicitly for a new Device or intentional clean installation and keeps destructive semantics separate from Normal Update.

### Update — preserve authenticator state

Normal Update does not use the generic erase-capable install dialog. M5Authenticator invokes ESP Web Tools 10.4.0 low-level flash API with `eraseFirst=false` unconditionally.

The update path requires a same-origin `update-manifest.json` containing exactly three ESP32-S3 parts:

- bootloader at `0x000000`;
- partition table at `0x008000`;
- `ota_0` application at `0x030000`.

The Web app fetches each same-origin asset before opening the Serial chooser and validates the actual byte size against the allowed write window. Legacy single merged offset-0 manifests, missing/duplicate/unexpected parts, cross-origin assets, empty files, or oversized files fail closed before flashing.

`web/src/firmware-update.test.ts` pins the accepted offsets/ranges and the invariant that Update always calls the flasher with `eraseFirst=false`. There is no erase choice in normal Update UI.

`update-manifest.json` may retain the generic erase prompt as defense-in-depth if opened outside the M5Authenticator UI; it is not the normal execution path.

## GitHub Releases

Production publication is owned by the hardened default-branch workflow `.github/workflows/release-authorized.yml`. It does **not** run on tag push. Its only production trigger is:

```yaml
on:
  repository_dispatch:
    types:
      - publish_semver_release
```

This keeps publication authority on the workflow revision stored on the repository default branch. A SemVer tag is release identity/input; it does not select the publisher workflow revision.

The historical tag-push workflow identity at `.github/workflows/release.yml` is retired from current source. Historical commits can still contain that workflow definition, so repository-level disabling of that legacy workflow identity is a mandatory #165 Human Gate. Until the legacy workflow is verified disabled, the SemVer tag Ruleset is configured, and immutable Releases are enabled/supported as required by #165, no new production release is authorized operationally and #127 remains open.

### Production release sequence

M5Authenticator uses the **pre-existing tag** sequence:

1. the intended release actor creates the protected `vX.Y.Z` tag at the exact current protected `main` HEAD under the #165 SemVer tag Ruleset;
2. after the tag exists, the intended release actor requests evaluation through `repository_dispatch` and supplies that tag as `client_payload.tag`;
3. the default-branch-owned hardened publisher validates the request and the existing tag before any build starts;
4. the workflow never creates, moves, force-updates, or deletes a production tag.

Example dispatch after the protected tag exists:

```text
gh api repos/miso-develop/m5authenticator/dispatches \
  --method POST \
  -f event_type=publish_semver_release \
  -f 'client_payload[tag]=vX.Y.Z'
```

The dispatch actor needs repository Contents write permission to submit the request. That permission authorizes only a request to evaluate the release; the workflow still fails closed unless the protected-main, tag, required-check, and release validation gates all pass.

### Hardened authorization and publication boundary

The current single-main release policy is fail-closed:

1. the `authorize` job runs from the default-branch `repository_dispatch` context, checks out that exact source SHA, requires the production release profile, and validates the requested tag uses exact `vX.Y.Z` syntax and matches `firmware/release-profile.json`;
2. it fetches authoritative remote `main` and requires the workflow/source candidate SHA to equal the exact current `origin/main` HEAD;
3. it fetches the requested **pre-existing** tag and requires the tag's peeled commit SHA to equal that same exact protected-main SHA; an absent, off-main, or stale-main tag fails before build;
4. authorization reads the active rules applied to `main`, derives every required status/check context, and requires each one to be successful for the exact source SHA with the required integration identity where the Ruleset binds one;
5. only after authorization succeeds does the `build` job run; it has `contents: read`, verifies the immutable image contract, and executes ESP-IDF only against a disposable firmware-only copy;
6. the build job creates a short-lived raw-build handoff containing only the merged/component binaries, `dependencies.lock`, source commit, exact ESP-IDF provenance, and per-file size/SHA-256 metadata;
7. the `verify` job also has only `contents: read`, independently checks out the authorized source, verifies every raw handoff digest/provenance field and dependency lock, scans the final merged image, packages the release with authoritative repository scripts, validates `release-metadata.json`, and validates every `SHA256SUMS` entry;
8. the `attest` job receives the independently verified package through the exact verified artifact ID. It rechecks the checksum-manifest identity and package checksums, then uses GitHub Artifact Attestations with OIDC to create both standard build provenance and a signed M5Authenticator custom provenance predicate. Only this job has `id-token: write`, `attestations: write`, and `artifact-metadata: write`;
9. the custom signed predicate binds the exact source commit, workflow ref/SHA/run identity, exact package asset digests, and the immutable ESP-IDF repository/tag/index digest/linux-amd64 manifest/reference recorded by the build-image contract;
10. only the `publish` job receives `contents: write`; it has no attestation/OIDC permission and never runs the ESP-IDF container. It downloads the same verified artifact ID, rechecks the exact `SHA256SUMS` identity and all package digests, then publishes those exact bytes without rebuilding;
11. a separate cleanup job has `actions: write` but no publication authority and deletes the transient Release handoff artifacts after the workflow completes.

The `gh release create --verify-tag` option remains only as an additional remote tag-existence check at publication time. It is **not** treated as cryptographic tag-signature verification, protected-main provenance, or release authorization.

The workflow contains no M5Authenticator-specific eFuse burn/read/provisioning step and no universal production encryption key input.

### Verify official release attestations

GitHub stores signed attestations independently from the downloadable Release assets. For an official downloaded asset, first verify the standard GitHub build provenance:

```text
gh attestation verify ./m5authenticator-v<version>-<commit>-m5sticks3.bin \
  --repo miso-develop/m5authenticator
```

The standard verification establishes that GitHub's attestation service signed provenance for that exact asset digest from this repository/workflow identity.

M5Authenticator also publishes a custom signed predicate that exposes the project-specific release trust details, including the immutable ESP-IDF build identity. Verify and inspect it with:

```text
gh attestation verify ./m5authenticator-v<version>-<commit>-m5sticks3.bin \
  --repo miso-develop/m5authenticator \
  --predicate-type https://miso-develop.github.io/m5authenticator/attestations/release-provenance/v1 \
  --format json \
  --jq '.[].verificationResult.statement.predicate'
```

For the custom predicate, confirm that `source_commit` is the expected Release commit, the `workflow` identity is `.github/workflows/release-authorized.yml` from the official repository/run, the artifact digest matches the downloaded file, and `build_environment.esp_idf` matches the immutable identity documented above and in `release-metadata.json`.

A local `SHA256SUMS` match is still required for package integrity, but it is not a substitute for signed platform provenance.

## Transient GitHub Actions Artifact policy

Actions Artifacts exist only where a job boundary requires an explicit transient handoff:

- Pages deployment staging artifact: `retention-days: 1`, consumed by the deploy job, then deleted by exact artifact ID;
- Release raw-build handoff: `retention-days: 1`, source-commit/image/file-hash provenance bound and independently verified before packaging;
- Release verified-package handoff: `retention-days: 1`, consumed only by the `contents: write` publish job after checksum identity verification;
- the Release cleanup job deletes both handoff artifacts by exact artifact ID as soon as practical;
- ordinary Security and Foundation jobs do not upload Actions Artifacts.

These transient artifacts contain only user-independent firmware outputs and non-secret provenance. No credential-bearing data, Device dump, Recovery Package, Vault material, or user state may enter an Actions Artifact.

## M5Burner

M5Burner `USER CUSTOM` publication uses the exact merged `.bin` from a production GitHub Release. The `update-*` component binaries are not the M5Burner publication artifact.

Do **not** use M5Burner Firmware Export on a provisioned Device. A full-device export can capture the Encrypted Vault and user state; even ciphertext-only credential backups/dumps are prohibited public artifacts under `SECURITY.md`.

Publication procedure:

1. use only `m5authenticator-v<version>-m5sticks3.bin` from the production GitHub Release;
2. choose M5StickS3 device type;
3. use the project repository as source link;
4. upload that CI-built merged `.bin`;
5. verify version/checksum against `release-metadata.json` / `SHA256SUMS`;
6. never source public firmware from a provisioned Device dump.

M5Burner remains a deliberate manual distribution surface, not the designated state-preserving normal-update path. Repository Actions contain no M5Stack account credentials.

## Build-output retention

Normal PR CI builds firmware for verification and discards it. It does not upload Actions Artifacts. Release builds use only the two bounded, one-day transient handoffs described above and delete them after publication/cleanup.

If physical testing later requires exact non-Release CI binaries, a separate temporary-build storage decision may be introduced. Such storage must remain secret-free and must not become a path for user Vault/Recovery/dump retention.
