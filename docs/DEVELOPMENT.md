# Development

This repository uses exact-pinned toolchains for the V1 foundation.

## Firmware

Canonical stack:

- ESP-IDF `v5.5.5`
- M5Unified `0.2.21` through the ESP Component Registry
- target: `esp32s3` / M5StickS3
- canonical build entrypoint: `idf.py` / CMake

Install ESP-IDF `v5.5.5` using Espressif's normal installation process, activate that environment, then run:

```text
cd firmware
idf.py set-target esp32s3
idf.py build
```

The build uses `sdkconfig.defaults` to select the bidirectional USB Serial/JTAG console used by the V1 Web Serial transport.

Do not switch the canonical build to Arduino Framework or PlatformIO.

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
