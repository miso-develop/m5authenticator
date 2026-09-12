# M5Authenticator V1 Requirements Reference

This document is the durable cross-feature requirements index for M5Authenticator V1. It promotes the settled V1 product/security contract into repository documentation without making GitHub Issue history a runtime dependency.

Detailed normative behavior remains in the focused documents linked from each section. In particular, this file does **not** duplicate `SECURITY.md` as a second security-policy source of truth.

## V1 identity and scope

| Area | V1 requirement | Detailed reference |
| --- | --- | --- |
| Target device | M5StickS3, ESP32-S3, 8 MiB Flash | `docs/DEVELOPMENT.md`, `docs/DISTRIBUTION.md` |
| TOTP profile | RFC 6238, HMAC-SHA-1, 6 digits, 30-second period | `docs/TIME.md` |
| Account capacity | Maximum 32 accounts | `docs/DEVICE_UI.md` |
| Device use | Select an account locally and reveal its OTP for at most 10 seconds | `docs/DEVICE_UI.md` |
| Management | Desktop Chrome Web App over Web Serial; credential processing is browser-local | `docs/WEB_PROVISIONER.md` |
| Import | Standard TOTP QR screenshot and Google Authenticator migration QR screenshot, including migration batches | `docs/WEB_PROVISIONER.md` |
| Canonical M5Authenticator replica | Browser Encrypted Vault is canonical for M5Authenticator browser/device synchronization; Device Vault is runtime/offline-use replica | `docs/SECRET_VAULT.md`, `docs/STORAGE.md` |
| Authoritative enrollment source | The external service enrollment/source Authenticator remains authoritative for credential replacement/re-enrollment | `docs/SECRET_VAULT.md` |
| Firmware distribution | GitHub Pages Web Flasher, GitHub Releases, and M5Burner use secret-free CI-built firmware | `docs/DISTRIBUTION.md` |

V1 does not claim HOTP, SHA-256/SHA-512 or 8-digit TOTP, smartphone companion support, BLE presence authentication, hardware-backed anti-rollback, or strong protection against a compromised endpoint/Trusted Browser, malicious firmware/fake Device, RAM probing while unlocked, or sophisticated physical extraction. See `SECURITY.md` and `docs/SECRET_VAULT.md` for the threat boundary.

## Canonical version boundary

V1 current truth is:

| Boundary | Value | Meaning |
| --- | ---: | --- |
| Firmware version | independent SemVer | Release/application version; not a substitute for protocol/storage compatibility |
| `PROTOCOL_VERSION` | `2` | Canonical Web Serial management/unlock protocol |
| `STORAGE_SCHEMA_VERSION` | `2` | Canonical Device persistence semantics |
| `VAULT_FORMAT_VERSION` | `1` | Canonical authenticated Encrypted Vault format |
| Security profile | `encrypted-vault-ram-only-vmk` v1 | Encrypted Vault in Flash; VMK only in RAM while unlocked |

Protocol 1 / Storage Schema 1 are historical development semantics. They must never be silently interpreted as Protocol 2 / Storage Schema 2, and the release build must not reintroduce their retired credential-management surfaces. Unknown newer protocol/storage/Vault formats fail closed rather than being guessed or automatically erased.

See `docs/PROVISIONING_PROTOCOL.md`, `docs/STORAGE.md`, and `docs/DISTRIBUTION.md`.

## Device security states and user-visible behavior

The user-facing security states are:

| State | Credential access | Device behavior |
| --- | --- | --- |
| `UNPROVISIONED` | none | No usable registered encrypted Vault |
| `LOCKED` | blocked | Encrypted Vault may exist, but VMK is absent; account identity and OTP reveal are unavailable |
| `UNLOCK REQUEST` | blocked | One fresh security-sensitive attempt is waiting for physical confirmation |
| `PROVISIONING` | blocked except bounded provisioning flow | Initial provisioning, recovery, replacement, or re-key transition is active |
| `UNLOCKED` | allowed only through bounded operations | VMK is present in Device RAM; OTP reveal additionally requires trusted time `READY` |
| `VAULT ERROR` / protocol `error` | blocked | Security/Vault state is invalid; fail closed |

A Device with an existing Vault starts `LOCKED` after boot/reboot because the VMK is not persisted. USB power detection, USB enumeration, and opening an ordinary Web Serial connection do not themselves Lock or Unlock the Device.

### StickS3 runtime operations

While `UNLOCKED` and outside `UNLOCK REQUEST`:

| Gesture | Operation |
| --- | --- |
| Single click | Select next account in manual order |
| Double click | Select previous account in manual order |
| Hold | Reveal selected six-digit OTP, only while trusted time is `READY` |

Selection wraps at the ends. The account display label uses this priority:

1. user-defined display name
2. issuer
3. account label

The persisted `last_used` hint outside the Vault is only an opaque random credential id. Its mapping to issuer/account/display-name remains inside the Encrypted Vault. Account identity metadata may be cached only in unlocked-session RAM and is cleared on Lock.

OTP is visible for at most 10 seconds and is cleared earlier if the Device locks, trusted time ceases to be `READY`, selection changes, or the relevant Vault generation changes.

See `docs/DEVICE_UI.md`.

## Trusted time requirements

OTP reveal is permitted only when both gates are true:

```text
Device security state = UNLOCKED
AND
trusted-time state = READY
```

| Time behavior | V1 requirement |
| --- | --- |
| `time.status` | Non-secret read is allowed while `LOCKED` |
| `time.sync` | May mutate the trusted-time anchor only while `UNLOCKED` |
| Credential-backed NTP | Available only while `UNLOCKED`, because Wi-Fi credentials are inside the Vault |
| Current-boot trusted anchor | May survive explicit Lock; cannot authorize OTP while Device is locked |
| Reboot/power loss | Clears trusted-time readiness/anchor |
| Resync due | Approximately 6 hours after successful trusted sync |
| Stale | More than 24 hours without successful trusted sync, or monotonic integrity failure; OTP reveal blocked |

See `docs/TIME.md`.

## Vault and key hierarchy

V1 uses an application-level authenticated Encrypted Vault. M5Authenticator-specific eFuse burn or irreversible project-specific security provisioning is not part of the V1 security root.

```text
Recovery Passphrase
  -> NFC normalize + UTF-8
  -> Argon2id v19
     m=32768 KiB, t=3, p=1, random 32-byte salt
  -> 256-bit Passphrase KEK
  -> AES-256-GCM wrap/unwrap
  -> random 256-bit VMK

VMK
  -> AES-256-GCM
  -> one authenticated Encrypted Vault ciphertext per generation

Active Trusted Browser
  BUK: non-extractable AES-256-GCM key
       -> browser-local VMK wrapping for quick unlock
  BRK: non-extractable ECDSA P-256 private key
       -> fresh unlock/registration request authentication

Device persistence for Trusted Browser
  -> BRK public key + registration id/epoch only
```

### Persistence boundary

| Location | May persist | Must not persist |
| --- | --- | --- |
| Device Flash | Encrypted Vault; Vault/storage framing; generation/`vault_id`; BRK public key and registration metadata; approved non-secret settings; opaque `last_used` credential id | VMK, Passphrase, KEK, BUK, BRK private key, unlock/session keys, plaintext TOTP/Wi-Fi credentials, decrypted Vault |
| Device RAM while `UNLOCKED` | VMK; bounded transient decrypted Vault/credential working state; unlocked-only account display cache | Secret state must not survive Lock/reboot/security-destruction boundaries |
| Browser IndexedDB | Encrypted Vault; Passphrase-wrapped VMK; BUK-wrapped VMK; non-extractable BUK/BRK private key; format/generation/registration metadata | Plaintext credentials, Passphrase, KEK, plaintext VMK, decrypted Vault, QR images/migration payloads |
| Recovery Package | Encrypted Vault; Passphrase-wrapped VMK; KDF/wrap/Vault metadata; generation/`vault_id`; bounded non-secret recovery metadata | Plaintext credentials/VMK, Passphrase/KEK, BUK, BRK private key, browser-specific material that bypasses Passphrase recovery |

Issuer, account label, display name, account order, TOTP profile, Wi-Fi SSID, and Wi-Fi password are Vault-private metadata and remain encrypted at rest.

See `docs/SECRET_VAULT.md` and `docs/STORAGE.md`.

## Vault cryptographic contract

Each V1 Vault generation is exactly one AES-256-GCM authenticated ciphertext under the random VMK.

- VMK: random 256-bit
- nonce: fresh random 96-bit value for every Vault encryption
- authentication tag: 128-bit
- AAD: versioned/domain-separated and binds at least Vault format, logical random `vault_id`, storage schema, and generation
- nonce is never derived solely from `generation`
- decrypted logical Vault is bounded transient working memory, not an unlocked-session resident plaintext database

Generation detects stale/mismatched replicas and interrupted updates, but it is **not** hardware-backed anti-rollback. A complete old Flash/state restore may restore an older generation too. Unexpected divergence is never resolved by last-writer-wins or silent auto-merge.

See `docs/SECRET_VAULT.md` and `docs/STORAGE.md`.

## Recovery Passphrase and Recovery Package

Passphrase policy:

- NFC normalization before UTF-8 KDF input
- 15 to 128 Unicode code points
- at most 512 UTF-8 bytes after normalization
- no mandatory character-class composition rule
- paste/password-manager use allowed
- low-entropy PIN-style values are not acceptable recovery protection

A Passphrase protects the random VMK; it does not deterministically generate the VMK. Therefore **the Passphrase alone cannot reconstruct a lost random VMK**. Recovery requires the encrypted canonical state, normally through a Recovery Package.

A Recovery Package is encrypted but security-sensitive because theft creates an offline Passphrase-guessing target. It is never a safe public fixture/artifact.

Changing the current Passphrase re-wraps the current VMK but does not remotely revoke previously exported packages. An old package can remain decryptable with the Passphrase used when it was exported. VMK rotation also cannot erase a historical package already copied elsewhere. To invalidate leaked historical credential material, rotate/re-enroll the affected TOTP credential at the authoritative service and change affected Wi-Fi credentials as needed.

See `docs/SECRET_VAULT.md` and `docs/WEB_PROVISIONER.md`.

## Single active Trusted Browser

V1 permits exactly one active Trusted Browser registration per logical Vault/Device.

- BUK unwraps the browser-local quick-unlock copy of VMK.
- BRK signs fresh unlock/registration transcripts.
- Device persists only BRK public key plus registration id/epoch.
- Normal quick unlock does not require Passphrase re-entry, but it does require the active BRK signature and fresh Device physical confirmation.
- Recovery Package import into a new Browser creates fresh local BUK/BRK material but leaves that Browser replacement-pending; import alone does not create a silent second writer.
- Trusted Browser replacement/recovery requires Passphrase recovery where applicable plus fresh Device confirmation.
- Successful replacement installs the new BRK public key and advances registration epoch, so the old BRK cannot authorize future quick unlocks.

See `docs/SECRET_VAULT.md`, `docs/WEB_PROVISIONER.md`, and `docs/PROVISIONING_PROTOCOL.md`.

## Fresh unlock/session requirements

Protocol 2 VMK delivery uses a fresh per-attempt protected session:

```text
fresh Device + Web ephemeral P-256 ECDH
  -> shared secret
  -> HKDF-SHA-256 with explicit domain separation and fresh attempt material
  -> 32-byte session key
  -> AES-256-GCM protected VMK delivery
```

Trusted Browser quick unlock additionally binds an ECDSA P-256/SHA-256 BRK signature to the fixed-order versioned transcript.

Each attempt includes a fresh random 128-bit attempt id and 256-bit Device challenge. Pending attempts expire after 30 seconds. User presence is valid only for the current attempt; a prior button state/action cannot be reused.

Replay, stale challenge/registration/generation, invalid signature/key, AEAD failure, rejection, timeout, cancel, superseding attempt, disconnect, and malformed/oversized messages fail closed and wipe pending session material.

See `docs/PROVISIONING_PROTOCOL.md`.

## Lock and VMK-destruction boundaries

The Device clears VMK and pending secret/session material on:

- reboot / power loss / shutdown
- explicit Lock
- fatal security error
- Factory Reset
- recovery provisioning
- Trusted Browser replacement
- VMK rotation/re-key

An ordinary same-VMK account/Wi-Fi generation update by the active canonical Browser while the Device is already `UNLOCKED` does not force a new Lock/physical confirmation for each edit. It must still validate `vault_id`/generation and commit atomically.

See `docs/SECRET_VAULT.md` and `docs/DEVICE_UI.md`.

## Web application requirements

The GitHub Pages Web application is static and credential processing remains local to the browser. The current V1 information architecture is panel-oriented rather than a multi-page credential application:

| Area | Main responsibility |
| --- | --- |
| **Firmware Flash** | Separate flasher page for first install and state-preserving firmware update |
| **Device** | Connect/disconnect, lock/unlock, Device status, trusted-time sync, replacement recovery |
| **Accounts** | QR import, canonical account list, rename/reorder/delete through encrypted generation updates |
| **Settings** | Wi-Fi-for-NTP configuration and other approved Device settings |
| **Security & Recovery** | Recovery Package import/export, Recovery Passphrase change, Trusted Browser state, VMK rotation |
| **Factory Reset** | Explicit destructive Device/browser state reset |

QR decoding, Google migration parsing, standard TOTP parsing, Vault encryption/decryption, Recovery Package processing, BUK/BRK operations, and provisioning stay browser-local. Credential-bearing data is not sent to GitHub Pages or another server.

See `docs/WEB_PROVISIONER.md` and `docs/ARCHITECTURE.md`.

## Main V1 flows

The durable end-to-end flows are documented in `docs/ARCHITECTURE.md`:

- standard TOTP QR import
- Google Authenticator migration QR import
- initial provisioning
- Trusted Browser quick unlock
- Passphrase/Recovery Package browser recovery and Device replacement
- encrypted canonical Vault synchronization
- USB trusted-time synchronization
- Factory Reset
- state-preserving firmware update

## Factory Reset and firmware update

Factory Reset is an explicit destructive Web/USB operation. It wipes Device VMK/session material, Encrypted Vault, user/settings/registration state and returns the Device to `UNPROVISIONED`. The paired browser cleanup removes matching local canonical/pairing state. Recovery Packages stored elsewhere are outside this erase boundary. Factory Reset performs no M5Authenticator-specific eFuse operation.

A normal firmware update uses the same secret-free merged firmware image without erasing `auth_nvs`. The Encrypted Vault and registration state remain, but reboot destroys RAM-only VMK; a provisioned Device therefore returns `LOCKED` after update.

See `docs/DISTRIBUTION.md`.

## Decision lineage

Current V1 security architecture is rooted in Decision #40 and refined by Decisions #45-#49:

| Decision | Durable meaning |
| --- | --- |
| #40 | Application-level Encrypted Vault, RAM-only VMK, Passphrase recovery, Trusted Browser quick unlock; no project-specific eFuse security root |
| #45 | One AES-256-GCM ciphertext per generation, fresh random nonce, versioned AAD, encrypted metadata boundary |
| #46 | Argon2id/AES-GCM Passphrase wrapping and Recovery Package semantics |
| #47 | Exactly one active Trusted Browser; BUK/BRK role separation and replacement semantics |
| #48 | Fresh Protocol 2 ECDH/HKDF/AES-GCM VMK-delivery session plus BRK authentication and user-presence binding |
| #49 | Trusted-time mutation/read boundary and current-boot anchor lifetime |

Decision #20, Task #26, and PR #39 describe the superseded eFuse/HMAC production-security direction. They are historical context only and must not be treated as current V1 architecture.

## Security policy and threat model

This requirements index intentionally does not reproduce the repository security policy. Use:

- `SECURITY.md` for mandatory handling/reporting/secret-exposure policy and threat model
- `docs/SECRET_VAULT.md` for the V1 credential/key trust boundary
- `docs/REPOSITORY_SECURITY.md` for repository secret-protection controls

Never place real TOTP secrets, QR payloads/images, account identifiers, Wi-Fi credentials, VMK/KEK/BUK/BRK private/session material, user-generated Recovery Packages, or credential-bearing dumps in examples, documentation, Issues/PRs, tests, logs, or artifacts.
