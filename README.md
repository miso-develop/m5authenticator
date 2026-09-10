# M5 Authenticator

A compact TOTP authenticator project for M5Stack devices, starting with **M5StickS3**.

> [!IMPORTANT]
> This is a public repository. **Never commit, paste, upload, log, or attach real authentication secrets or credentials.** This includes TOTP secrets, `otpauth://` URIs, Google Authenticator migration payloads/QR images, access tokens, API keys, private keys, passwords, Wi-Fi credentials, device dumps containing secrets, and equivalent sensitive material.

## Project status

V1 implementation is in progress.

The initial target is M5StickS3 with:

- TOTP (SHA-1, 6 digits, 30-second period)
- up to 32 accounts
- device-side account selection and 10-second OTP reveal
- USB/Web Serial provisioning
- import from standard TOTP QR screenshots and Google Authenticator migration QR screenshots
- client-side-only provisioning through a GitHub Pages web UI
- device-specific encrypted secret storage
- NTP time synchronization with USB time sync as a fallback

See `PROJECT.md` for project-wide constraints and `SECURITY.md` for mandatory security policy.

## Foundation development

The canonical firmware build is ESP-IDF / CMake for M5StickS3. The Web App is Vanilla TypeScript + Vite + Vitest.

See:

- `docs/DEVELOPMENT.md` for pinned toolchains and reproducible build/test commands.
- `docs/DEVICE_UI.md` for StickS3 account selection, trusted-time display, and 10-second OTP reveal behavior.
- `docs/WEB_PROVISIONER.md` for local-only Web Serial provisioning and account/device management.
- `docs/TIME.md` for trusted-time synchronization and TOTP readiness rules.
- `docs/STORAGE.md` for encrypted account/Wi-Fi storage boundaries.
- `docs/PROVISIONING_PROTOCOL.md` for the versioned NDJSON provisioning protocol.
- `docs/DISTRIBUTION.md` for the Web Flasher, GitHub Releases, M5Burner, and state-preserving update contract.
- `docs/REPOSITORY_SECURITY.md` for repository-level security controls.

## Development process

This repository follows Loop Engineering using GitHub `[Map]` → `[Decision]` → `[Spec]` → `[Task]` work items. See `AGENTS.md` and `agent/WORK-TRACKING.md`.

## Security

Security of authentication material is the highest-priority invariant of this project. Real secrets must never enter Git history, Issues/PRs, CI logs, test fixtures, screenshots, artifacts, or external web requests.

If a real secret is exposed, treat it as compromised and rotate/revoke it at the source service. Do not rely on deleting a Git commit or comment as remediation.

### Repository security check

Before pushing security-sensitive changes, run:

```text
python3 -m unittest discover -s tests -p "test_security_scan.py"
python3 scripts/security_scan.py
```

The repository operation `security:scan` is enforced in GitHub Actions for pull requests and `main`. See `docs/REPOSITORY_SECURITY.md` for the two-layer secret protection baseline and allowlist policy.
