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

The build uses `sdkconfig.defaults` to select the bidirectional USB Serial/JTAG console, the custom dual-OTA partition layout in `partitions.csv`, and the production HMAC/eFuse storage backend. Until Task #26 physical validation completes, `firmware/release-profile.json` deliberately keeps production distribution blocked.

Do not switch the canonical build to Arduino Framework or PlatformIO.

### Local environment (`.env`)

Repository-local machine settings use a root `.env` file. `.env` is ignored by Git; only the value-free `.env.example` template is versioned.

On Windows `cmd.exe`:

```text
copy .env.example .env
```

Then edit `.env` locally and populate the supported keys:

```text
M5AUTH_IDF_VERSION=
M5AUTH_CHIP=
M5AUTH_PORT=
```

Do not put concrete machine-specific values in `.env.example` or documentation. `scripts\load-env.cmd` validates the local values against the repository's canonical toolchain/device requirements and exports them into the current `cmd.exe` session. Keep using `call` so the variables persist in that shell:

```text
call scripts\load-env.cmd
```

`.env` is for **non-secret local tooling configuration only**. Even though it is ignored by Git, never put TOTP secrets, `otpauth` payloads, Wi-Fi passwords, tokens, private keys, or other authentication material in it.

With Espressif EIM installed, the local Windows build is:

```text
call scripts\load-env.cmd
cd firmware
eim run "idf.py set-target %M5AUTH_CHIP%" %M5AUTH_IDF_VERSION%
eim run "idf.py build" %M5AUTH_IDF_VERSION%
```

This avoids accidentally using an older globally configured ESP-IDF environment.

### Storage security profiles

`DevSecurityBackend` remains available for explicit development-only builds. It exercises encrypted `auth_nvs` with deliberately public synthetic XTS key material, never reads or burns eFuse, reports `security_profile: development`, and can never become a production release artifact.

The canonical V1 configuration now selects `HmacEfuseSecurityBackend`. A device whose deliberately configured HMAC slot is still free enters the dedicated Production Security Setup mode and performs only non-destructive inspection/preflight until the Web confirmation and physical StickS3 confirmation are both completed. Normal boot with an existing reusable HMAC key derives NVS keys read-only and does not burn eFuse.

Do not treat a storage error as permission to initialize production security. Only the explicit first-time `production_init_required` state with a selected free slot may enter the irreversible initialization path. Unknown schema, corrupt storage, incompatible eFuse state, or I/O failure remain fail-closed.

The complete physical validation and irreversible-operation procedure is documented in `docs/PRODUCTION_SECURITY.md`. Do not improvise eFuse commands outside that runbook.

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

See `docs/STORAGE.md` for the storage/security boundary.

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
- never upload credential-bearing data, secret material, decrypted stores, logs, dumps, or other prohibited security material

Long-lived release binaries belong in GitHub Release assets rather than Actions artifact storage. A separate storage decision must be made before introducing transient external CI build storage.

## Security checks

From the repository root:

```text
python3 -m unittest discover -s tests -p "test_security_scan.py"
python3 scripts/security_scan.py
```

Use only public test vectors or explicitly synthetic credentials in tests. Never use personal authenticator exports, real QR images, passwords, or credential-bearing dumps.
