# Security Policy

Security of authentication material is the highest-priority invariant of this repository.

This repository is public. Any value committed, pasted into an Issue/PR, uploaded as an attachment, emitted to a public log, or included in an artifact must be assumed publicly disclosed.

## Mandatory rule: never expose real authentication material

The following MUST NOT appear in this repository, Git history, Issues, Pull Requests, review comments, Actions logs, artifacts, screenshots, test fixtures, examples, documentation, release files, or telemetry:

- real TOTP secrets
- real `otpauth://` URIs
- real `otpauth-migration://` payloads
- Google Authenticator migration QR codes or screenshots
- passwords, Wi-Fi passwords, recovery codes
- PATs, OAuth tokens, API keys, access/refresh tokens, session credentials
- SSH/TLS/signing/private keys or seed material
- decrypted user account stores
- NVS, flash, RAM, crash, serial, packet, or filesystem dumps that may contain credentials
- any other value that allows authentication, secret recovery, impersonation, or decryption of user secrets

If unsure whether a value is sensitive, treat it as sensitive and do not publish it.

## Secret handling requirements

### Firmware

- Public firmware images must not contain user secrets, shared production credentials, or universal encryption keys.
- Secrets must be provisioned after flashing.
- Release builds must store TOTP material only in the approved encrypted storage backend.
- Secret-bearing buffers must not be printed or included in assertions/errors.
- Debug builds do not get an exception to secret-redaction rules.

### Web Provisioner

- QR decoding and migration parsing must happen locally in the browser.
- TOTP secrets, migration payloads, Wi-Fi credentials, and decrypted account records must never be sent to GitHub Pages or another server.
- Do not place sensitive values in URLs, query strings, fragments, analytics events, browser storage, error reporting, or console logs.
- Imported QR images are ephemeral input. Do not upload or persist them by default.
- Network dependencies added to provisioning/security-sensitive paths require explicit security review.

### USB / serial protocol

- The protocol must not provide a release-mode operation that exports stored TOTP secrets.
- Commands and responses must avoid echoing secret values.
- Errors must identify the failing field/account without including its secret-bearing payload.
- Factory Reset must be explicit and destructive, and available only through the Provisioner in V1.

### Tests and fixtures

Allowed:

- official/published public RFC test vectors
- clearly synthetic credentials generated only for tests
- synthetic QR payloads that cannot authenticate to a real account

Forbidden:

- copied personal authenticator exports
- real QR screenshots with values blurred only visually
- production/user dumps
- credentials copied from local configuration

A fixture must remain safe if somebody decodes or prints it in full.

### Logging and diagnostics

Never log:

- secrets or encoded forms of secrets
- complete `otpauth` URIs
- migration payloads
- Wi-Fi passwords
- encryption keys
- decrypted account records

Identifiers such as issuer/account names may also be personal data. Log them only where necessary and prefer synthetic identifiers in tests and bug reports.

## Repository hygiene

- Keep local secrets and captures in ignored local-only paths.
- Review staged changes before every commit for credentials and private artifacts.
- Do not use actual credentials to reproduce a bug in a public Issue/PR.
- Examples must use unmistakably synthetic values.
- Generated build output, dumps, captures, and local provisioning data must not be committed unless proven secret-free and intentionally versioned.

Automated secret scanning is defense in depth, not permission to handle secrets casually.

## Security review requirement

Any change affecting the following is security-sensitive and must be reviewed as such before merge:

- secret storage or encryption
- eFuse usage
- provisioning/import
- Web Serial / USB protocol
- QR / migration parsing
- logging / diagnostics
- firmware update or Factory Reset
- Wi-Fi credential handling
- BLE authentication/presence
- release/build/signing pipeline
- third-party network dependencies in the Provisioner

Security regressions are blocking defects even when functional verification passes.

## Incident response

If a real secret is exposed anywhere public:

1. Assume the credential is compromised immediately.
2. Revoke, rotate, or replace it at the authoritative source service.
3. Remove the exposed material from current repository/UI surfaces where practical.
4. Review Git history, Actions logs, artifacts, Issues/PRs, caches, mirrors, and attachments for additional exposure.
5. Determine how the value crossed the trust boundary and add a preventive control/test.

Deleting or rewriting a Git commit/comment is NOT sufficient remediation because copies may already exist.

For a leaked TOTP secret, replace/re-enroll the affected 2FA credential at the service. Do not continue trusting the old secret merely because the repository history was cleaned.

## Threat-model boundary

This project aims to prevent accidental disclosure and common loss/theft scenarios. It does not claim resistance to sophisticated physical extraction, BLE relay, compromised endpoint OSes, simultaneous smartphone/device compromise, or realtime TOTP phishing. See `PROJECT.md`.
