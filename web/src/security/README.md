# Web security primitives

This directory stages the V1 Vault Format 1 cryptographic and serialization primitives for Task #51.

The modules here are intentionally not wired into the current Protocol 1 / Storage Schema 1 runtime. Protocol 2 / Storage Schema 2 activation belongs to later integration Tasks.

Security-sensitive values must remain browser-local and ephemeral unless the durable V1 architecture explicitly permits encrypted persistence. See `../../docs/SECRET_VAULT.md` and `../../SECURITY.md`.
