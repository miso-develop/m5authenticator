# Security Policy

Security of authentication material is the highest-priority invariant of this repository.

This repository is public. Any value committed, pasted into an Issue/PR, uploaded as an attachment, emitted to a public log, or included in an artifact must be assumed publicly disclosed.

## Mandatory rule: never expose real authentication material

The following MUST NOT appear in repository content, Git history, Issues, Pull Requests, review comments, Actions logs, artifacts, screenshots, test fixtures, examples, documentation, release files, or telemetry:

- real TOTP secrets
- real `otpauth://` URIs
- real `otpauth-migration://` payloads
- Google Authenticator migration QR codes or screenshots
- passwords, Wi-Fi SSID/password pairs, recovery codes
- PATs, OAuth tokens, API keys, access/refresh tokens, session credentials
- SSH/TLS/signing/private keys or seed material
- Vault Master Key (VMK)
- Passphrase-derived KEK
- Browser Unlock Key (BUK)
- Browser Registration Key (BRK) private key
- unlock/session key material
- user-generated encrypted Recovery Packages or other credential-bearing backups, even when ciphertext-only
- decrypted user Vault/account stores
- NVS, Flash, RAM, crash/core, serial, packet, or filesystem dumps that may contain credentials/keys
- any value that enables authentication, secret recovery, impersonation, or decryption of user secrets

If unsure whether a value is sensitive, treat it as sensitive and do not publish it.

## V1 security invariants

`docs/SECRET_VAULT.md` is the canonical V1 Vault/key/unlock/recovery architecture.

### Device

- M5Authenticator V1 does not burn project-specific eFuse security material.
- Device Flash must not persist VMK, Passphrase, KEK, BUK, BRK private key, unlock/session keys, plaintext TOTP/Wi-Fi credentials, plaintext account identity metadata, or decrypted Vault snapshots.
- Device credential persistence is one authenticated Encrypted Vault ciphertext per generation plus bounded non-secret framing/registration metadata.
- issuer, account label, display name, TOTP profile/order, Wi-Fi SSID/password, and credential-id mapping belong inside the encrypted Vault.
- VMK exists on Device only in RAM while `UNLOCKED`.
- reboot/power loss, explicit Lock, fatal security error, Factory Reset, recovery provisioning, Trusted Browser replacement, and VMK re-key must wipe VMK and transient secret material.
- USB power/enumeration and ordinary Web Serial connection do not themselves Lock an unlocked Device.
- decrypted Vault plaintext must be bounded/transient for credential operations and must not remain resident for the full unlocked session.
- release firmware must never fall back to a public/synthetic development storage key.

### Vault cryptography

- V1 Vault encryption uses AES-256-GCM with random 256-bit VMK, fresh random 96-bit nonce per encryption, and 128-bit tag.
- nonce must not be derived solely from generation.
- Vault AAD binds version/domain, logical `vault_id`, storage schema, and generation.
- Passphrase protection uses Argon2id v19 with the parameters defined in `docs/SECRET_VAULT.md`, deriving a KEK used to AES-256-GCM-wrap the VMK.
- unsupported format/KDF parameters fail closed; do not silently reinterpret them.

### Trusted Browser

- V1 permits exactly one active Trusted Browser registration per logical Vault/Device.
- BUK is browser-local/non-extractable and used only for the browser-local quick-unlock VMK wrapping path.
- BRK is a browser-local/non-extractable ECDSA P-256 private key used to authenticate fresh Trusted Browser unlock/registration transcripts.
- Device may persist only the BRK public key plus non-secret registration id/epoch.
- BUK and BRK private key are never exported in a Recovery Package.
- Browser replacement requires fresh Device user presence and invalidates the old BRK for future quick unlock.
- importing a Recovery Package alone must not create a second active canonical writer.

### Unlock session / user presence

- VMK delivery uses fresh ephemeral P-256 ECDH, HKDF-SHA-256, and AES-256-GCM as defined by Decision #48 / `docs/SECRET_VAULT.md`.
- normal Trusted Browser quick unlock additionally requires a valid BRK signature over the current transcript.
- pending attempts are bounded and expire after 30 seconds.
- stale/replayed attempts, invalid signature/key/material, authentication failure, user rejection, timeout, cancel, superseding attempt, and disconnect fail closed and wipe pending session state.
- fresh Device physical confirmation is mandatory for initial registration, LOCKED quick unlock, new-Browser recovery, Trusted Browser replacement, and VMK re-key.
- a physical action from before the current request cannot authorize it.
- ordinary same-VMK canonical Vault generation updates while already `UNLOCKED` do not require repeated physical confirmation merely because ciphertext changes.

### Trusted time

- TOTP reveal requires both Device `UNLOCKED` and trusted-time `READY`.
- credential-backed NTP runs only while unlocked.
- non-secret `time.status` may be read while locked.
- `time.sync` may mutate the trusted-time anchor only while unlocked; a locked USB host cannot pre-seed trusted time.
- a current-boot trusted anchor may survive explicit Lock but is cleared by reboot/power loss.

### Recovery Package

V1 may export/import the Web canonical encrypted state as a Recovery Package. It must not contain plaintext credentials/VMK, Passphrase/KEK, BUK, BRK private key, or browser-specific material that bypasses Passphrase recovery.

A Recovery Package remains security-sensitive because theft permits offline Passphrase guessing. Passphrase change or VMK rotation cannot remotely erase/revoke a previously exported package. If leaked historical credentials must be invalidated, rotate/re-enroll them at the authoritative service/source and change affected Wi-Fi credentials.

## Secret handling requirements

### Firmware

- Public firmware images must not contain user secrets, shared production credentials, universal Vault keys, reusable release decryption keys, or browser private keys.
- Secrets are provisioned after flashing.
- TOTP/Wi-Fi plaintext and decrypted Vault data are opened only for the minimum practical lifetime and explicitly wiped afterward.
- Secret-bearing buffers must not be printed or included in assertions/errors.
- Debug builds do not get an exception to redaction rules.
- Production crash/core-dump behavior must not persist credential-bearing RAM in a way that defeats the RAM-only-key boundary.

### Web Provisioner

- QR decoding and migration parsing happen locally.
- TOTP/migration/Wi-Fi plaintext, VMK, KEK, BUK, BRK private key, decrypted Vault data, and Passphrase material must never be sent to GitHub Pages or another server.
- Do not place sensitive values in URLs, query strings, fragments, analytics events, error reporting, or console logs.
- Plaintext credential/account records must not be persisted in browser storage.
- Browser persistence may contain Encrypted Vault, wrapped VMK values, version metadata, non-secret registration metadata, and non-extractable BUK/BRK keys as defined by `docs/SECRET_VAULT.md`.
- Recovery Package export/import is user-initiated and local-only; it must never be automatically uploaded.
- Imported QR images are ephemeral input.
- Network dependencies added to provisioning/security-sensitive paths require explicit security review.

### USB / serial protocol

- Release protocol must not provide stored TOTP/Wi-Fi/VMK/BUK/BRK-private export/read operations.
- Commands/responses avoid echoing secret values.
- Errors identify failure class/field without reproducing credential-bearing payload.
- VMK delivery is bound to a fresh session and never becomes a reusable plaintext operation.
- Trusted Browser quick unlock requires active BRK authentication and current Device user presence.
- Factory Reset is explicit/destructive and available only through the Provisioner in V1.

### Tests and fixtures

Allowed:

- official/published public RFC/cryptographic test vectors
- clearly synthetic credentials generated only for tests
- synthetic QR payloads that cannot authenticate a real account
- synthetic VMK/KEK/BUK/BRK/session material generated only for tests
- synthetic Recovery Packages generated entirely from synthetic test credentials

Forbidden:

- personal authenticator exports
- real QR screenshots, even visually blurred
- user Recovery Packages, even encrypted
- production/user dumps
- credentials copied from local configuration

A fixture must remain safe if somebody decodes or prints it in full.

### Logging and diagnostics

Never log:

- secret or encoded forms of secret
- complete credential-bearing `otpauth`/migration payloads
- Wi-Fi password
- VMK / KEK / BUK / BRK private key / session keys
- decrypted Vault/account records
- user Recovery Package contents

Issuer/account/display names and SSIDs may be personal data and are encrypted-at-rest V1 metadata. Prefer synthetic identifiers in tests/bug reports.

## Repository hygiene

- Keep local secrets, Recovery Packages, backups, captures, and dumps in ignored local-only paths.
- Review staged changes before every commit; `.gitignore` and scanner checks are defense in depth, not authorization to store secrets locally in the repository tree.
- Do not use actual credentials to reproduce a bug in public Issue/PR.
- Examples use unmistakably synthetic values.
- Generated build output/dumps/captures/local provisioning data must not be committed unless proven secret-free and intentionally versioned.

## Security review requirement

Any change affecting the following is security-sensitive and requires explicit review before merge:

- Vault format/storage/encryption/key wrapping/KDF/nonce/AAD/versioning
- VMK/KEK/BUK/BRK/session lifetime or zeroization
- Recovery Package format/import/export/Passphrase change semantics
- eFuse usage or any irreversible hardware security proposal
- lock/unlock/user-presence state machine
- Trusted Browser registration/replacement
- provisioning/import and Web Serial protocol
- browser persistence
- QR/migration parsing
- logging/diagnostics/crash dumps
- firmware update or Factory Reset
- Wi-Fi credential handling / trusted-time mutation
- BLE authentication/presence
- release/build/signing pipeline
- third-party/network dependencies in Provisioner

Security regressions are blocking defects even when functional verification passes.

## Incident response

If a real secret is exposed publicly:

1. Assume it is compromised immediately.
2. Revoke, rotate, replace, or re-enroll it at the authoritative source service.
3. Remove exposed material from current repository/UI surfaces where practical.
4. Review Git history, Actions logs, artifacts, Issues/PRs, caches, mirrors, and attachments for additional exposure.
5. Determine how it crossed the trust boundary and add a preventive control/test.

Deleting/rewriting a Git commit or comment is not sufficient remediation because copies may already exist.

For a leaked TOTP secret, replace/re-enroll the affected 2FA credential at the service.

For an exposed encrypted Recovery Package, exposure does not prove plaintext compromise but creates an offline Passphrase-guessing target. If the package or its Passphrase protection is considered compromised, re-enroll affected source credentials; changing only the current M5Authenticator Passphrase cannot revoke the historical package.

For an exposed BUK/BRK/browser profile, replace the active Trusted Browser registration and assess the endpoint as compromised. Because endpoint compromise is outside the strong V1 guarantee, rotate/re-enroll underlying credentials when risk tolerance requires it.

## Threat-model boundary

This project aims to prevent accidental disclosure, common powered-off/rebooted-device loss/theft scenarios, Flash copying/dumping from directly revealing credentials, release-interface secret export, plaintext browser persistence, and passive/replayed unlock-material reuse.

It does not claim resistance to sophisticated physical extraction, RAM probing while unlocked, compromised endpoint OS/browser code, malicious extensions/XSS, active fake-device/Evil-Maid firmware replacement, hardware-backed rollback attacks, BLE relay, simultaneous source/device compromise, or realtime TOTP phishing. See `PROJECT.md` and `docs/SECRET_VAULT.md`.
