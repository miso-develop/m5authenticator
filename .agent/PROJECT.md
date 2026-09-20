# Project

This file contains only long-lived premises that apply across the project. Feature-specific specs, implementation tasks, and progress belong in GitHub Issues / Pull Requests.

## Purpose

Use a compact M5Stack device as a dedicated TOTP authenticator that is convenient for everyday use.

V1 targets M5StickS3. External services' TOTP enrollment and a smartphone Authenticator or equivalent remain the **authoritative enrollment/recovery source**. A local-only Web Provisioner on the PC manages an encrypted replica for M5Authenticator, and the StickS3 can independently select an account and reveal its OTP for a short time.

Inside M5Authenticator, the Web-side Encrypted Vault is the **canonical encrypted replica**, while the Device-side Encrypted Vault is the runtime/offline-use replica. "Canonical" here does not mean replacing the external service's authoritative enrollment source.

## Scope

### In scope

- V1 target: M5StickS3
- TOTP: RFC 6238 SHA-1 / 6 digits / 30-second period
- Up to 32 accounts
- Device UI:
  - short press: next account
  - double click: previous account
  - long press: reveal selected OTP
  - OTP reveal duration: 10 seconds
  - selection after unlock: last-used account
- account display priority: user-defined display name -> issuer -> account
- PC/Web management UI for add, rename, manual reorder, delete, and settings management
- Google Authenticator migration QR screenshot import
- standard `otpauth://totp/...` QR screenshot import
- Google Authenticator multi-QR migration batch handling
- Web Serial / USB provisioning/management
- static Web application on GitHub Pages; credential/secret processing remains browser-local only
- secret-free firmware distribution through GitHub Releases / M5Burner / GitHub Pages Web Flasher
- application-level authenticated Encrypted Vault without eFuse dependency
- Device RAM-only Vault Master Key (VMK)
- Passphrase recovery + single active Trusted Browser quick unlock
- Device-side fresh user presence for unlock/registration/recovery-root changes
- encrypted Recovery Package export/import
- Wi-Fi credentials stored inside the Vault and used only for NTP after unlock
- OTP reveal prohibited until trusted time has been established during the current boot
- Encrypted Vault / user state preserved by default across firmware updates
- Factory Reset available only through the Web/USB Provisioner
- Device lifecycle that remains erasable/re-provisionable without burning M5Authenticator-specific eFuse state

### Out of scope for V1

- HOTP
- SHA-256/SHA-512 TOTP / 8-digit OTP
- export of stored TOTP secrets from the M5 Device
- smartphone companion application
- BLE Presence authentication
- BLE relay resistance
- realtime phishing resistance
- advanced physical extraction resistance
- strong resistance to compromised endpoint OS / Trusted Browser / malicious browser extension / XSS
- strong resistance to active fake-device / Evil-Maid firmware replacement
- hardware-backed anti-rollback
- mandatory Secure Boot / full Flash Encryption in V1
- PWA / offline Web application support
- official V1 support for Firefox/Safari/Edge

BLE Presence will be re-evaluated in a future phase for feasibility/security benefit and is not required for V1.

## Constraints

### Security — highest priority

Preventing authentication-material leakage takes precedence over functionality, convenience, debugging ease, and development speed.

Never record real values for the following in the repository, Git history, Issues, PRs, review comments, CI logs, artifacts, test fixtures, screenshots, examples, or documentation:

- real TOTP secret / real `otpauth://` URI / real migration payload or QR
- password / Wi-Fi credential
- access token / API token / PAT / OAuth token
- private/signing key / recovery code
- VMK / Passphrase-derived KEK / BUK / BRK private key / unlock-session key
- user-generated encrypted Recovery Package
- device/NVS/Flash/RAM/crash dump that may contain credentials
- decrypted production/user Vault or equivalent authentication material

The Web Provisioner must not transmit TOTP secrets, QR payloads, Wi-Fi credentials, VMK, private browser keys, or decrypted Vault data to GitHub Pages or another server. Parsing, encrypted persistence, Recovery Package handling, and provisioning remain local-only.

Tests use published public vectors or explicitly synthetic credentials only.

See `SECURITY.md` and `docs/SECRET_VAULT.md`.

### Product / operational

- The V1 device power model is primarily always-on USB power; the USB source is not assumed to be a PC.
- StickS3 has no trusted external RTC. Reboot/power loss clears trusted-time readiness.
- A fresh boot with an existing Vault starts `LOCKED` because the VMK is not stored in Flash.
- Trusted Browser quick unlock normally avoids Passphrase re-entry but still requires fresh Device user presence.
- V1 permits exactly one active Trusted Browser registration per logical Vault/Device.
- A new Browser requires an encrypted Recovery Package + Passphrase and explicit Browser replacement/provisioning before becoming the active writer for an existing Device.
- Passphrase alone cannot reconstruct a lost random VMK.
- An exported Recovery Package is an offline Passphrase-guessing target and remains security-sensitive.
- Changing the Passphrase does not remotely revoke previously exported Recovery Packages.
- Factory Reset cannot delete Recovery Packages stored outside the current browser/device.

## Invariants / decisions

### Vault / key hierarchy

- Do not burn eFuse for M5Authenticator-specific security purposes.
- Do not store VMK, Passphrase, Passphrase-derived KEK, BUK, BRK private key, session key, or plaintext credentials in Device Flash.
- Encrypt the Vault itself with AES-256-GCM using a random 256-bit VMK.
- V1 Vault uses one authenticated ciphertext per generation.
- Use a fresh random 96-bit nonce for each Vault encryption; do not derive the nonce deterministically from generation alone.
- Store issuer/account/display name/TOTP profile/manual order/Wi-Fi SSID/password inside the Vault.
- Account-related state persisted outside the Vault is limited to non-secret metadata that does not directly reveal identity, such as opaque credential IDs.
- Derive a 256-bit KEK from the Passphrase using Argon2id v19 (m=32768 KiB, t=3, p=1, random 32-byte salt), then wrap the VMK with AES-256-GCM under that KEK.
- Use UTF-8 after NFC normalization for the Passphrase; require 15–128 Unicode code points and at most 512 UTF-8 bytes. Do not impose character-class composition rules.
- Do not use a low-entropy PIN as an offline-decryptable protection secret.

### Trusted Browser

- V1 has exactly one active Trusted Browser.
- BUK is a browser-local non-extractable AES-256-GCM key used only for a browser-local wrapped copy of the VMK.
- BRK is a browser-local non-extractable ECDSA P-256 private key used only to authenticate fresh unlock/registration requests.
- The Device may persist only the BRK public key and registration id/epoch.
- Do not include BUK/BRK private keys in the Recovery Package.
- Trusted Browser replacement requires Device user presence, replaces the registration epoch/public key, and rejects future quick unlocks signed by the old BRK.
- Recovery Package import alone must not create a silent second writer.

### Unlock session / user presence

- Protect VMK delivery with an ephemeral P-256 ECDH -> HKDF-SHA-256 -> AES-256-GCM session.
- Trusted Browser quick unlock binds a BRK ECDSA P-256/SHA-256 signature to a fresh transcript.
- Each attempt has a fresh 128-bit id + 256-bit Device challenge and expires after 30 seconds.
- Bind user presence to the current attempt; do not reuse previous button state.
- Initial provisioning, quick unlock from `LOCKED`, new Browser recovery, Trusted Browser replacement, and VMK re-key require fresh physical confirmation.
- A normal Vault generation update by the active canonical Browser while using the same VMK and while `UNLOCKED` does not require Lock/physical confirmation every time.

### Lock / persistence

- Zeroize VMK/session secrets on reboot / power loss / explicit Lock / fatal security error / Factory Reset / recovery / Trusted Browser replacement / VMK re-key.
- USB power detection, USB enumeration, and a normal Web Serial connection are not themselves Lock conditions.
- While `LOCKED`, do not display issuer/account/display name/SSID from Flash in plaintext.
- Do not keep the Device's entire decrypted Vault resident throughout the `UNLOCKED` period; perform bounded transient decryption per credential operation and wipe it afterward.
- Web canonical generation updates are transactional, and Device sync must also atomically leave either the old or new generation valid.
- Do not resolve generation mismatch with last-writer-wins.
- Generation is not hardware-backed rollback protection.

### Recovery Package

- The Package may contain: Encrypted Vault, Passphrase-wrapped VMK, KDF/wrap/Vault metadata, generation/vault_id, and required non-secret recovery metadata.
- The Package must not contain: plaintext credential/VMK, Passphrase/KEK, BUK, BRK private key, or any browser-specific secret that bypasses the Passphrase.
- A Passphrase change is a re-wrap of the current VMK; already-exported Packages may remain decryptable with the old Passphrase.
- VMK rotation cannot delete historical Packages that remain outside the system. To reliably invalidate a leaked credential snapshot, rotate TOTP/Wi-Fi credentials at the authoritative source.

### Trusted time

- OTP reveal = `UNLOCKED` AND `READY`.
- Credential-backed NTP is allowed only while `UNLOCKED`.
- `time.status` is a non-secret read allowed while `LOCKED`.
- Trusted-anchor mutation through `time.sync` is allowed only while `UNLOCKED`; a LOCKED host must not be able to pre-seed time.
- The current-boot trusted anchor may survive explicit Lock but is cleared by reboot/power loss.
- Resync becomes due about 6 hours after READY; after more than 24 hours since the last trusted sync the state becomes STALE and OTP reveal is rejected.

### Repository / release

- Do not include user-specific secrets or a shared universal Vault key in the public repository/firmware.
- Do not emit secret-bearing data to logs, errors, telemetry, URLs, analytics, crash reports, or external requests.
- Stored-secret export from the Device is not a release feature.
- Treat browser QR import as ephemeral.
- Release builds must not accept a public synthetic development storage key as production protection.
- Firmware update preserves Encrypted Vault/user state and returns to `LOCKED` after reboot.
- Factory Reset deletes Device Vault/user/registration state but cannot delete external Recovery Packages.
- Security regression is a blocking defect even when functional behavior succeeds.
- Promote Map / Decision / Spec knowledge into the repository when it is required as current truth.

## Threat model

### Intended protections

- accidental secret exposure through source control / Issues / PRs / logs / fixtures / screenshots / artifacts / web requests
- direct plaintext credential extraction from Flash after powered-off/rebooted device loss
- credential disclosure through simple Flash copying/dumping
- stored-secret export through normal release interfaces
- plaintext credential persistence in browser storage
- passive/replayed USB unlock material reuse

### Explicitly not guaranteed

- sophisticated physical extraction
- RAM/debug extraction while the Device is `UNLOCKED`
- compromised endpoint OS / Trusted Browser profile
- malicious browser extension / XSS
- active fake-device/Evil-Maid scenario
- hardware-backed anti-rollback
- BLE relay
- compromised smartphone OS
- simultaneous compromise of source Authenticator and M5Authenticator
- realtime TOTP phishing

## References

- `SECURITY.md`
- `docs/SECRET_VAULT.md`
- `docs/STORAGE.md`
- `docs/PROVISIONING_PROTOCOL.md`
- `docs/TIME.md`
- `AGENTS.md`
- `.agent/WORK-TRACKING.md`
- Decisions #40, #45, #46, #47, #48, #49
- RFC 6238
