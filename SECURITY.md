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
- Vault Master Key (VMK), passphrase-derived KEK, Browser Unlock Key (BUK), or unlock-session key material
- user-generated encrypted Recovery Packages or other credential-bearing backups, even when ciphertext-only
- decrypted user account stores
- NVS, flash, RAM, crash, serial, packet, or filesystem dumps that may contain credentials
- any other value that allows authentication, secret recovery, impersonation, or decryption of user secrets

If unsure whether a value is sensitive, treat it as sensitive and do not publish it.

## V1 vault security invariants

`docs/SECRET_VAULT.md` is the canonical V1 secret-storage/unlock architecture.

- M5Authenticator V1 does not burn project-specific eFuse security material.
- Device Flash must not persist the VMK, user passphrase, passphrase-derived KEK, BUK, plaintext TOTP secret, plaintext Wi-Fi password, or a decrypted credential snapshot.
- Device Flash may persist only an authenticated Encrypted Vault and non-secret/versioning/registration metadata required to operate it.
- VMK exists on the Device only in RAM while the Device is `UNLOCKED`.
- reboot, power loss, explicit Lock, fatal security error, Factory Reset, and entry into credential-state replacement/recovery/re-key operations must wipe VMK and transient secret material.
- USB power, USB enumeration, and ordinary Web Serial connection are not sufficient reasons to destroy an existing unlocked session.
- Trusted Browser quick unlock may avoid repeated Passphrase entry, but explicit Device-side user presence is mandatory before accepting the VMK.
- A Trusted Browser is not a hardware root of trust. Browser/OS compromise, malicious extensions, and XSS remain outside the strong V1 guarantee.
- Release firmware must never depend on a public/synthetic development storage key that would make user credentials decryptable from a Flash dump.
- V1 may export/import the Web canonical encrypted state as a Recovery Package, but that package must not contain plaintext credentials, plaintext VMK, Passphrase/KEK, BUK, or browser-specific quick-unlock material that bypasses Passphrase recovery.
- An encrypted Recovery Package remains security-sensitive because theft permits offline Passphrase guessing; never treat ciphertext-only backup as safe for public disclosure.

## Secret handling requirements

### Firmware

- Public firmware images must not contain user secrets, shared production credentials, universal Vault keys, or reusable release decryption keys.
- Secrets must be provisioned after flashing.
- Release builds must store credential-bearing data only inside the approved authenticated Encrypted Vault.
- TOTP/Wi-Fi plaintext should be opened only for the minimum practical lifetime and explicitly wiped afterward.
- Secret-bearing buffers must not be printed or included in assertions/errors.
- Debug builds do not get an exception to secret-redaction rules.
- Production crash/core-dump behavior must not persist credential-bearing RAM in a way that defeats the RAM-only-key boundary.

### Web Provisioner

- QR decoding and migration parsing must happen locally in the browser.
- TOTP secrets, migration payloads, Wi-Fi credentials, VMK, decrypted account records, and Passphrase material must never be sent to GitHub Pages or another server.
- Do not place sensitive values in URLs, query strings, fragments, analytics events, error reporting, or console logs.
- Plaintext TOTP/Wi-Fi credential records must not be persisted in browser storage.
- Browser persistence may contain the Encrypted Vault, wrapped VMK values, non-secret crypto/version metadata, and a browser-local non-extractable BUK as defined by `docs/SECRET_VAULT.md`.
- The user may explicitly export/import the versioned encrypted Recovery Package defined by `docs/SECRET_VAULT.md`; it must be handled as sensitive local data and must never be uploaded automatically.
- Imported QR images are ephemeral input. Do not upload or persist them by default.
- Network dependencies added to provisioning/security-sensitive paths require explicit security review.

### USB / serial protocol

- The protocol must not provide a release-mode operation that exports stored TOTP secrets.
- Commands and responses must avoid echoing secret values.
- Errors must identify the failing field/account without including its secret-bearing payload.
- VMK delivery must be bound to a fresh unlock session and must not become a reusable plaintext read/write operation.
- A Trusted Browser quick-unlock attempt must require explicit Device user presence before the Device accepts the VMK.
- Factory Reset must be explicit and destructive, and available only through the Provisioner in V1.

### Tests and fixtures

Allowed:

- official/published public RFC test vectors
- clearly synthetic credentials generated only for tests
- synthetic QR payloads that cannot authenticate to a real account
- synthetic VMK/KEK/BUK/session material generated solely for tests
- synthetic Recovery Packages generated entirely from synthetic test credentials

Forbidden:

- copied personal authenticator exports
- real QR screenshots with values blurred only visually
- real/user Recovery Packages, even when encrypted
- production/user dumps
- credentials copied from local configuration

A fixture must remain safe if somebody decodes or prints it in full.

### Logging and diagnostics

Never log:

- secrets or encoded forms of secrets
- complete `otpauth` URIs
- migration payloads
- Wi-Fi passwords
- VMK / KEK / BUK / unlock-session keys
- decrypted account records
- user Recovery Package contents

Identifiers such as issuer/account names may also be personal data. Log them only where necessary and prefer synthetic identifiers in tests and bug reports.

## Repository hygiene

- Keep local secrets, Recovery Packages, and captures in ignored local-only paths.
- Review staged changes before every commit for credentials and private artifacts.
- Do not use actual credentials to reproduce a bug in a public Issue/PR.
- Examples must use unmistakably synthetic values.
- Generated build output, dumps, captures, and local provisioning data must not be committed unless proven secret-free and intentionally versioned.

Automated secret scanning is defense in depth, not permission to handle secrets casually.

## Security review requirement

Any change affecting the following is security-sensitive and must be reviewed as such before merge:

- Vault storage, encryption, key wrapping, KDF, VMK/BUK/session-key lifetime, or zeroization
- encrypted Recovery Package format/import/export
- eFuse usage or any proposal to introduce an irreversible hardware security state
- lock/unlock state machine and Device user-presence behavior
- provisioning/import
- Web Serial / USB protocol
- browser persistence / Trusted Browser registration and recovery
- QR / migration parsing
- logging / diagnostics / crash dumps
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

For an exposed encrypted Recovery Package, treat the package as credential-bearing security material. Exposure does not by itself prove that the enclosed TOTP secrets were decrypted, but it gives an attacker an offline Passphrase-guessing target. Rotate/re-provision if the Passphrase strength or KDF protection is uncertain or if risk tolerance requires it.

## Threat-model boundary

This project aims to prevent accidental disclosure, common powered-off/rebooted-device loss/theft scenarios, Flash copying/dumping from directly revealing credentials, release-interface secret export, and plaintext browser persistence.

It does not claim resistance to sophisticated physical extraction, RAM probing while unlocked, compromised endpoint OS/browser code, malicious extensions/XSS, Evil-Maid firmware replacement, hardware-backed rollback attacks, BLE relay, simultaneous smartphone/device compromise, or realtime TOTP phishing. See `PROJECT.md` and `docs/SECRET_VAULT.md`.
