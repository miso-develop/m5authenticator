# Task #51 implementation scope

This branch stages only the V1 Vault Format 1 cryptographic/serialization foundation. It does not activate Protocol 2 or Storage Schema 2 runtime semantics.

Planned branch contents:

- deterministic Vault plaintext serialization and AAD framing
- Web AES-256-GCM Vault encryption/decryption
- Argon2id v19 Passphrase KDF contract and VMK AES-256-GCM wrapping
- firmware-compatible format/AAD/AES-GCM primitives
- synthetic interoperability vectors and fail-closed tests

Protocol activation remains owned by later Tasks #54/#55.
