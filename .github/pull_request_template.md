Parent spec: #<spec-number>
Closes #<task-number>

## Summary

- <what changed>

## Verification

- <checks and results>

## Security review

- [ ] No real secrets, credentials, QR migration data, user Recovery Packages, private dumps, or secret-bearing logs/artifacts are included.
- [ ] `SECURITY.md` and, when Vault/unlock/recovery behavior changes, `docs/SECRET_VAULT.md` were reviewed.
- [ ] VMK, Passphrase-derived KEK, BUK, unlock/session keys, plaintext TOTP/Wi-Fi data, and decrypted Vault material are neither persisted nor logged outside their approved boundary.
- [ ] Browser persistence/export and crash/core/RAM/NVS/Flash dump paths were reviewed when applicable.
- [ ] Any security-sensitive path changed here was reviewed for logging, persistence, export, network, lock/unlock, recovery, and update/reset regressions.
