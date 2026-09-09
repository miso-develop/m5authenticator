# M5 Authenticator

A compact TOTP authenticator project for M5Stack devices, starting with **M5StickS3**.

> [!IMPORTANT]
> This is a public repository. **Never commit, paste, upload, log, or attach real authentication secrets or credentials.** This includes TOTP secrets, `otpauth://` URIs, Google Authenticator migration payloads/QR images, access tokens, API keys, private keys, passwords, Wi-Fi credentials, device dumps containing secrets, and equivalent sensitive material.

## Project status

Early design / implementation phase.

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

## Development process

This repository follows Loop Engineering using GitHub `[Map]` → `[Decision]` → `[Spec]` → `[Task]` work items. See `AGENTS.md` and `agent/WORK-TRACKING.md`.

## Security

Security of authentication material is the highest-priority invariant of this project. Real secrets must never enter Git history, Issues, Pull Requests, CI logs, test fixtures, screenshots, artifacts, or external web requests.

If a real secret is exposed, treat it as compromised and rotate/revoke it at the source service. Do not rely on deleting a Git commit or comment as remediation.
