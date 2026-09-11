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

### Current development security state

The current pre-V1 implementation still uses the development-era `DevSecurityBackend`, `PROTOCOL_VERSION = 1`, and `STORAGE_SCHEMA_VERSION = 1`. It exercises encrypted `auth_nvs` with deliberately public synthetic XTS key material and **must not burn, read for provisioning, or modify project-specific eFuse security state**. Its firmware reports `security_profile: development` and `production_release_allowed: false`.

This development backend is intentionally not a production credential-protection boundary: a public/synthetic storage key cannot protect a captured Flash image from an attacker who has the same public source material.

Decision #40 superseded the former HMAC/eFuse production-security plan. Task #26 and PR #39 are historical/superseded and must not be revived as the V1 production path.

### Target V1 security transition

The target V1 architecture is defined by `docs/SECRET_VAULT.md`:

- application-level authenticated Encrypted Vault in `auth_nvs`
- random 256-bit Vault Master Key (VMK)
- VMK persisted nowhere on the Device and held only in RAM while `UNLOCKED`
- Passphrase-derived KEK for recovery wrapping
- browser-local Browser Unlock Key (BUK) for Trusted Browser quick unlock
- fresh protected Web-to-Device unlock session with Device user presence
- no M5Authenticator-specific eFuse burn

The transition is intentionally breaking and must not silently reinterpret development protocol/storage v1. The target boundaries are:

- `PROTOCOL_VERSION = 2`
- `STORAGE_SCHEMA_VERSION = 2`
- `VAULT_FORMAT_VERSION = 1`

The former catch-all Task #41 was closed as not planned because it mixed unresolved security decisions with an oversized implementation surface. Map #17 now owns Decisions #45-#49. After those decisions are settled, Spec #7 must be updated and the security implementation decomposed into narrow Tasks before production code changes begin.

Until that replacement implementation is complete and release validation explicitly permits production distribution, do not:

- enable `production_release_allowed`
- treat the synthetic development storage key as production protection
- add an eFuse burn/provisioning path
- invent KDF/AEAD/session parameters inside an implementation Task
- advertise protocol/storage/Vault versions that are not actually implemented

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

See `docs/STORAGE.md`, `docs/SECRET_VAULT.md`, and `docs/PROVISIONING_PROTOCOL.md` for the persistence, key, and protocol boundaries.

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
