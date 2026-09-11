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

The target V1 architecture is defined by `docs/SECRET_VAULT.md` and settled Decisions #40/#45-#49:

- application-level authenticated Encrypted Vault in `auth_nvs`
- one AES-256-GCM ciphertext per Vault generation
- random 256-bit Vault Master Key (VMK)
- VMK persisted nowhere on the Device and held only in RAM while `UNLOCKED`
- Argon2id-derived Passphrase KEK for recovery wrapping
- browser-local non-extractable Browser Unlock Key (BUK) for quick-unlock wrapping
- separate browser-local non-extractable ECDSA P-256 Browser Registration Key (BRK) for the single active Trusted Browser registration
- fresh P-256 ECDH + HKDF-SHA-256 + AES-256-GCM Web-to-Device unlock session with Device user presence
- no M5Authenticator-specific eFuse burn

The transition is intentionally breaking and must not silently reinterpret development protocol/storage v1. The target boundaries are:

- `PROTOCOL_VERSION = 2`
- `STORAGE_SCHEMA_VERSION = 2`
- `VAULT_FORMAT_VERSION = 1`

The former catch-all Task #41 was closed as not planned because it mixed security decisions with an oversized implementation surface. Decisions #45-#49 are settled and promoted into Spec #7 and the durable architecture documents.

The current dependency/implementation graph is:

```text
#43 (completed)
#58 -> #51 -> +-> #52 -+
              +-> #53 -+-> #54 -> #55 -> #56 -> #15 -> #16
#44 (code merged; physical re-test pending) -----> #56
```

- #43 reconciled repository truth and security enforcement in PR #50 and is complete.
- #58 hardens repository scanning for quoted sensitive JSON/JSONC property assignments and is an explicit prerequisite for #51.
- #44 preserves the non-eFuse StickS3 runtime fixes discovered in superseded PR #39. Its code was merged in PR #57; the remaining non-destructive physical validation is outside the repository-spec consistency audit and still blocks #56.
- #51 implements the Vault crypto format and interoperability vectors without activating v2 runtime semantics.
- #52 and #53 implement Web canonical-state/Trusted-Browser ownership and Device RAM-only-VMK runtime respectively; they may proceed in parallel after #51.
- #54 implements the fresh Protocol v2 unlock/session primitives.
- #55 is the only Task that activates the complete Protocol 2 / Storage Schema 2 / Vault Format 1 tuple in the canonical application.
- #56 replaces the development release gate with the V1 Vault production contract after both #44 and #55 are complete.
- #15 performs final security closeout; #16 completes durable documentation closeout.

Until that replacement implementation and validation chain is complete and release validation explicitly permits production distribution, do not:

- enable `production_release_allowed`
- treat the synthetic development storage key as production protection
- add an eFuse burn/provisioning path
- change the settled KDF/AEAD/session parameters inside an implementation Task without a new Decision
- advertise protocol/storage/Vault versions that are not actually implemented
- begin #51 while #58 remains open

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
