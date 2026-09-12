# Development

This repository uses exact-pinned toolchains for the V1 foundation.

## Firmware

Canonical stack:

- ESP-IDF `v5.5.5`
- M5Unified `0.2.21` through the ESP Component Registry
- target: `esp32s3` / M5StickS3 with 8 MiB flash
- canonical build entrypoint: `idf.py` / CMake

Install ESP-IDF `v5.5.5` using Espressif's normal installation process, activate that environment, then run:

```text
cd firmware
idf.py set-target esp32s3
idf.py build
```

The build uses `sdkconfig.defaults` to select the bidirectional USB Serial/JTAG console and the custom dual-OTA partition layout in `partitions.csv`.

Do not switch the canonical build to Arduino Framework or PlatformIO.

### Current V1 security runtime

Task #55 activated the V1 runtime on the canonical executable path. Current firmware uses:

- `PROTOCOL_VERSION = 2`
- `STORAGE_SCHEMA_VERSION = 2`
- `VAULT_FORMAT_VERSION = 1`
- application-level authenticated Encrypted Vault in `auth_nvs`
- one AES-256-GCM ciphertext per Vault generation
- random 256-bit Vault Master Key (VMK)
- VMK persisted nowhere on the Device and held only in RAM while `UNLOCKED`
- Argon2id-derived Passphrase KEK for recovery wrapping
- browser-local non-extractable Browser Unlock Key (BUK) for quick-unlock wrapping
- separate browser-local non-extractable ECDSA P-256 Browser Registration Key (BRK) for the single active Trusted Browser registration
- fresh P-256 ECDH + HKDF-SHA-256 + AES-256-GCM Web-to-Device unlock session with Device user presence
- no M5Authenticator-specific eFuse burn or HMAC-root provisioning requirement

The canonical `app_main` bootstrap uses the Vault runtime and Protocol v2 management path. The superseded `DevSecurityBackend` / Protocol 1 plaintext-management path is not the production executable bootstrap and must not be restored as a release path.

Decision #40 superseded the former HMAC/eFuse production-security plan. Task #26 and PR #39 are historical/superseded and must not be revived as the V1 production path.

### V1 release transition

`firmware/release-profile.json` format 2 describes the V1 production contract independently from the final publication switch. It requires:

- Protocol 2 / Storage Schema 2 / Vault Format 1
- security profile `encrypted-vault-ram-only-vmk`, version 1
- credential-bearing Flash persistence only as authenticated Encrypted Vault data
- VMK persistence `ram-only`
- no public/synthetic Flash credential key
- no M5Authenticator-specific eFuse requirement
- post-update state `LOCKED`

`scripts/validate_release.py` verifies those fields against firmware metadata, the canonical bootstrap, and the fixed Flash layout. It rejects a regression to the legacy synthetic credential bootstrap even when `production_release_allowed` is changed.

The release implementation chain is now:

```text
#43 / #44 / #58 / #51 / #52 / #53 / #54 / #55  completed
#56  V1 release contract
  ↓
#15  final security closeout + production eligibility flip
  ↓
#16  durable documentation closeout
```

Task #56 deliberately leaves `production_release_allowed: false`. Task #15 is the only stage that may set it to `true` after the exact final implementation passes security closeout. This means ordinary CI can validate the real V1 security contract without prematurely publishing production firmware.

Until Task #15 completes, do not:

- enable `production_release_allowed`
- introduce a public/synthetic or universal credential-decryption key into the production path
- add an M5Authenticator-specific eFuse burn/provisioning dependency
- change settled KDF/AEAD/session parameters without a new Decision
- weaken Protocol/Storage/Vault/security-profile validation to make a release pass

The native state-codec check can be run from the repository root with:

```text
g++ -std=c++20 -Wall -Wextra -Werror \
  -Ifirmware/components/m5auth_storage/include \
  -Ifirmware/components/m5auth_storage \
  firmware/components/m5auth_storage/state.cpp \
  tests/storage_state_test.cpp \
  -o /tmp/m5auth-storage-state-test
/tmp/m5auth-storage-state-test
```

Release-contract checks can be run with:

```text
python scripts/validate_release.py
python -m unittest tests/release_package_test.py
```

`python scripts/validate_release.py --require-production` is expected to fail until Task #15 enables final production eligibility.

See `docs/STORAGE.md`, `docs/SECRET_VAULT.md`, `docs/PROVISIONING_PROTOCOL.md`, and `docs/DISTRIBUTION.md` for the persistence, key, protocol, and release boundaries.

## Web App

Pinned runtime/tooling:

- Node.js `24.21.0`
- npm `11.19.0`
- TypeScript `7.0.2`
- Vite `8.2.2`
- Vitest `5.0.0`

Canonical commands:

```text
cd web
npm ci
npm test
npm run build
npm run dev
```

The Web App is Vanilla TypeScript. Runtime CDN, remote JavaScript/CSS/fonts, analytics, remote error reporting, and dynamic remote module loading are not permitted.

## CI storage policy

GitHub Actions artifacts are not a default persistence mechanism for this repository. CI should build and verify without uploading an artifact unless a downstream workflow or explicit human validation requires that exact CI-produced output.

When an Actions artifact is unavoidable:

- use the minimum practical retention period; default to `retention-days: 1` unless a documented reason requires longer
- delete the artifact as soon as it has been consumed when the workflow/tooling supports immediate deletion
- do not retain duplicate or intermediate build outputs
- never upload credential-bearing data, secret material, encrypted Recovery Packages, decrypted stores, logs, dumps, or other prohibited security material

Long-lived release binaries belong in GitHub Release assets rather than Actions artifact storage. A separate storage decision must be made before introducing transient external CI build storage.

## Security checks

From the repository root:

```text
python3 -m unittest discover -s tests -p "test_security_scan.py"
python3 scripts/security_scan.py
```

Use only public test vectors or explicitly synthetic credentials in tests. Never use personal authenticator exports, real QR images, passwords, user-generated Recovery Packages, Vault/session keys, or credential-bearing dumps.
