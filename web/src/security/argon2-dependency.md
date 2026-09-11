# Argon2id implementation pin

Task #51 uses `hash-wasm` **4.12.0** as the browser-bundled Argon2id v19 implementation.

- exact package version: `4.12.0`
- license: MIT
- runtime dependencies: none
- runtime network fetch: prohibited; Vite bundles the package into the static Web App
- V1 KDF parameters remain repository-owned: m=32768 KiB, t=3, p=1, 32-byte salt, 32-byte output

The dependency version is encoded in `web/package.json` / `web/package-lock.json`; this document is informational and must not replace the lockfile as the install authority.
