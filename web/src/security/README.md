# Web security modules

This directory contains the staged V1 application-level Vault implementation for the Web Provisioner.

- `vault-format.ts` defines the versioned encrypted Vault plaintext/AAD framing shared with firmware interoperability vectors.
- `vault-crypto.ts` implements AES-256-GCM Vault encryption plus Argon2id/AES-GCM Passphrase VMK wrapping.
- `browser-vault.ts` implements the browser canonical encrypted state: allowlisted IndexedDB persistence, non-extractable BUK/BRK ownership, BUK quick-unlock VMK wrapping, Recovery Package import/export, Passphrase re-wrap, replacement-pending state, and generation-conflict fail-closed checks.
- `session-crypto.ts` stages browser-only Protocol v2 session cryptographic primitives: bounded Device attempt material validation, fresh non-extractable Web P-256 ECDH keys, ECDH/HKDF-SHA-256 session-key derivation from explicit context bytes, AES-256-GCM VMK sealing, and BRK transcript signing. It intentionally does not define the final shared transcript encoding, NDJSON vocabulary, or activate Protocol 2; those remain integration responsibilities.
- `security-panel.ts` exposes the staged Security & Recovery UI without activating Protocol 2 or changing the current Device management version tuple.

No module in this directory may persist plaintext TOTP/Wi-Fi credentials, Passphrases, Passphrase-derived KEKs, plaintext VMKs, decrypted Vault records, session keys, BUK exports, or BRK private-key exports. Recovery Packages are encrypted but security-sensitive offline Passphrase-guessing targets and must not be committed or uploaded as public artifacts.
