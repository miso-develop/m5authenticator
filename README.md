# M5 Authenticator

**English** | [日本語](README.ja.md)

A compact TOTP authenticator project for M5Stack devices, starting with **M5StickS3**.

> [!IMPORTANT]
> This is a public repository. **Never commit, paste, upload, log, or attach real authentication secrets or credentials.** This includes TOTP secrets, `otpauth://` URIs, Google Authenticator migration payloads/QR images, access tokens, API keys, private keys, passwords, Wi-Fi credentials, Vault keys, device dumps containing secrets, and equivalent sensitive material.

## Project status

V1 implementation is in progress.

The initial target is M5StickS3 with:

- TOTP (SHA-1, 6 digits, 30-second period)
- up to 32 accounts
- device-side account selection and 10-second OTP reveal
- USB/Web Serial provisioning and management
- import from standard TOTP QR screenshots and Google Authenticator migration QR screenshots
- client-side-only provisioning through a GitHub Pages web UI
- an application-level authenticated Encrypted Vault stored on the device
- a random Vault Master Key (VMK) kept only in device RAM while unlocked
- Trusted Browser quick unlock without passphrase re-entry, with explicit physical confirmation on the device
- no M5Authenticator-specific eFuse burn or irreversible project-specific security provisioning
- NTP time synchronization after unlock, with USB time sync available independently

After reboot or power loss, the device starts locked because the VMK is not stored in Flash. A registered Trusted Browser can restore the normal session without asking for the passphrase again, but the device still requires explicit user-presence confirmation.

See `PROJECT.md` for project-wide constraints, `SECURITY.md` for mandatory security policy, and `docs/SECRET_VAULT.md` for the current Vault/key/unlock architecture.

## Foundation development

The canonical firmware build is ESP-IDF / CMake for M5StickS3. The Web App is Vanilla TypeScript + Vite + Vitest.

See:

- `docs/DEVELOPMENT.md` for pinned toolchains and reproducible build/test commands.
- `docs/SECRET_VAULT.md` for the Encrypted Vault, RAM-only VMK, Trusted Browser, lock/unlock, and recovery architecture.
- `docs/DEVICE_UI.md` for StickS3 account selection, unlock user presence, trusted-time display, and 10-second OTP reveal behavior.
- `docs/WEB_PROVISIONER.md` for local-only Web Serial provisioning, encrypted browser state, Trusted Browser quick unlock, and account/device management.
- `docs/TIME.md` for trusted-time synchronization and TOTP readiness rules.
- `docs/STORAGE.md` for encrypted Vault persistence and versioning boundaries.
- `docs/PROVISIONING_PROTOCOL.md` for the versioned NDJSON provisioning/unlock protocol.
- `docs/DISTRIBUTION.md` for the Web Flasher, GitHub Releases, M5Burner, and state-preserving update contract.
- `docs/REPOSITORY_SECURITY.md` for repository-level security controls.

## Development process

This repository follows Loop Engineering using GitHub `[Map]` → `[Decision]` → `[Spec]` → `[Task]` work items. See `AGENTS.md` and `agent/WORK-TRACKING.md`.

## Security

Security of authentication material is the highest-priority invariant of this project. Real secrets must never enter Git history, Issues/PRs, CI logs, test fixtures, screenshots, artifacts, or external web requests.

The V1 design protects powered-off/rebooted device storage by ensuring that the VMK needed to decrypt the credential Vault is not persisted on the device. It does not claim a hardware root of trust or strong resistance to a compromised trusted browser/OS, malicious firmware, RAM probing while unlocked, or sophisticated physical attacks.

If a real secret is exposed, treat it as compromised and rotate/revoke it at the source service. Do not rely on deleting a Git commit or comment as remediation.

### Repository security check

Before pushing security-sensitive changes, run:

```text
python3 -m unittest discover -s tests -p "test_security_scan.py"
python3 scripts/security_scan.py
```

The repository operation `security:scan` is enforced in GitHub Actions for pull requests and `main`. See `docs/REPOSITORY_SECURITY.md` for the two-layer secret protection baseline and allowlist policy.
