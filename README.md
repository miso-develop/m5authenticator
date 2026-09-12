# M5 Authenticator

**English** | [日本語](README.ja.md)

A compact TOTP authenticator project for M5Stack devices, starting with **M5StickS3**.

> [!IMPORTANT]
> This is a public repository. **Never commit, paste, upload, log, or attach real authentication secrets or credentials.** This includes TOTP secrets, `otpauth://` URIs, Google Authenticator migration payloads/QR images, access tokens, API keys, private keys, passwords, Wi-Fi credentials, Vault/browser/session keys, user Recovery Packages, device dumps containing secrets, and equivalent sensitive material.

## Project status

The V1 implementation and security closeout are complete. The canonical production architecture is **Protocol 2 / Storage Schema 2 / Vault Format 1** with the `encrypted-vault-ram-only-vmk` security profile, and production release eligibility is enabled behind the fail-closed release/profile checks.

The GitHub Pages path now builds and deploys validated production firmware for the Web Flasher. Formal GitHub Releases remain version-tag driven and use the same secret-free CI-built merged firmware image.

The initial target is M5StickS3 with:

- TOTP (SHA-1, 6 digits, 30-second period)
- up to 32 accounts
- device-side account selection and 10-second OTP reveal
- USB/Web Serial provisioning and management
- import from standard TOTP QR screenshots and Google Authenticator migration QR screenshots
- client-side-only provisioning through a GitHub Pages web UI
- one application-level AES-GCM Encrypted Vault generation stored on Device Flash
- a random Vault Master Key (VMK) kept only in Device RAM while unlocked
- one active Trusted Browser for quick unlock without Passphrase re-entry, with explicit physical confirmation on the Device
- encrypted Recovery Package import/export for browser recovery; browser quick-unlock private keys are not included
- no M5Authenticator-specific eFuse burn or irreversible project-specific security provisioning
- NTP and USB trusted-time synchronization only after Device unlock

After reboot or power loss, the Device starts locked because the VMK is not stored in Flash. A registered Trusted Browser can restore the normal session without asking for the Passphrase again, but the Device still requires a fresh user-presence confirmation for that unlock attempt.

The original service enrollment/source Authenticator remains the authoritative source for replacing or re-enrolling credentials. The Web Provisioner's encrypted Vault is canonical only within M5Authenticator for browser/device synchronization.

For the durable V1 overview, start with [`docs/V1_REQUIREMENTS.md`](docs/V1_REQUIREMENTS.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Security-sensitive key, persistence, unlock, recovery, and Trusted Browser semantics are consolidated in [`docs/SECRET_VAULT.md`](docs/SECRET_VAULT.md). Project-wide constraints remain in `PROJECT.md`, and mandatory handling/threat-model policy remains in `SECURITY.md`.

## V1 documentation

- `docs/V1_REQUIREMENTS.md` — cross-feature V1 requirements index, state/behavior tables, version boundary, and Decision lineage.
- `docs/ARCHITECTURE.md` — firmware/Web/Vault/protocol responsibility boundaries and end-to-end V1 flows.
- `docs/SECRET_VAULT.md` — Encrypted Vault, RAM-only VMK, Passphrase/Recovery Package, Trusted Browser, Lock/Unlock, and user-presence architecture.
- `docs/DEVICE_UI.md` — StickS3 account selection, unlock user presence, trusted-time display, and 10-second OTP reveal behavior.
- `docs/WEB_PROVISIONER.md` — local-only Web Serial management, encrypted browser state, Trusted Browser ownership/recovery, and account/device management.
- `docs/TIME.md` — trusted-time synchronization and TOTP readiness rules.
- `docs/STORAGE.md` — encrypted Vault persistence, metadata privacy, and versioning boundaries.
- `docs/PROVISIONING_PROTOCOL.md` — canonical Protocol 2 NDJSON provisioning/unlock protocol.
- `docs/DISTRIBUTION.md` — Web Flasher, GitHub Releases, M5Burner, and state-preserving update contract.
- `docs/DEVELOPMENT.md` — pinned toolchains and reproducible build/test commands.
- `docs/REPOSITORY_SECURITY.md` — repository-level secret-protection controls.

## Development foundation

The canonical firmware build is ESP-IDF / CMake for M5StickS3. The Web App is Vanilla TypeScript + Vite + Vitest. See `docs/DEVELOPMENT.md` for exact pinned versions and commands.

## Development process

This repository follows Loop Engineering using GitHub `[Map]` → `[Decision]` → `[Spec]` → `[Task]` work items. See `AGENTS.md` and `agent/WORK-TRACKING.md`.

## Security

Security of authentication material is the highest-priority invariant of this project. Real secrets and user-generated encrypted credential backups must never enter Git history, Issues/PRs, CI logs, test fixtures, screenshots, artifacts, or external web requests.

The V1 design protects powered-off/rebooted Device storage by ensuring that the VMK needed to decrypt the credential Vault is not persisted on the Device. It does not claim a hardware root of trust or strong resistance to a compromised trusted browser/OS, malicious firmware/fake Device, RAM probing while unlocked, hardware-backed rollback attacks, or sophisticated physical attacks.

If a real secret is exposed, treat it as compromised and rotate/re-enroll it at the authoritative source service. Deleting a Git commit/comment is not sufficient remediation. An old exported Recovery Package is not cryptographically revoked merely by changing the current Passphrase; see `SECURITY.md` and `docs/SECRET_VAULT.md`.

### Repository security check

Before pushing security-sensitive changes, run:

```text
python3 -m unittest discover -s tests -p "test_security_scan.py"
python3 scripts/security_scan.py
```

The repository operation `security:scan` is enforced in GitHub Actions for pull requests and `main`. See `docs/REPOSITORY_SECURITY.md` for the two-layer secret protection baseline and allowlist policy.
