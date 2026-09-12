# Secret Vault Architecture

This document is the durable V1 security architecture for protecting TOTP secrets and other credential-bearing M5Authenticator state. Decision #40 defines the security root; Decisions #45-#49 refine the Vault format, Passphrase recovery, Trusted Browser ownership, unlock transport, and trusted-time mutation boundaries.

## Goals and non-goals

V1 requires:

- no M5Authenticator-specific eFuse burn or irreversible project-specific security provisioning
- no plaintext TOTP secret, account identity metadata, Wi-Fi SSID/password, or Vault decryption key persisted in Device Flash
- a random Vault Master Key (VMK) held on Device only in RAM while `UNLOCKED`
- recoverable Factory Reset / erase / re-provision behavior
- practical cold-boot quick unlock without requiring Passphrase entry on every normal boot
- no stored-secret export operation from release firmware
- portable encrypted recovery of the Web canonical M5Authenticator state

This is not a hardware root-of-trust design. It does not claim strong resistance to a compromised endpoint OS/browser, malicious browser extensions/XSS, RAM probing while unlocked, sophisticated physical extraction, active fake-device/Evil-Maid attacks, or hardware-backed rollback attacks.

## Source terminology

Two different authorities exist and must not be conflated:

- **Authoritative enrollment/recovery source:** the original service enrollment plus the user's smartphone Authenticator/source credentials. This is the ultimate source used to replace/re-enroll TOTP credentials.
- **M5Authenticator canonical encrypted replica:** the Web Provisioner's encrypted Vault state. This is canonical only for synchronizing M5Authenticator browser/device replicas.

The Device Vault is a runtime/offline-use replica of the M5Authenticator canonical encrypted state. M5Authenticator does not become the authoritative enrollment source for the external service.

## V1 key hierarchy

```text
User Passphrase
    |
    v
Argon2id v19
m=32768 KiB, t=3, p=1
32-byte random salt
    |
    v
Passphrase KEK (256-bit)
    |
    +-- AES-256-GCM wrap --> VMK (random 256-bit)
                               |
                               +-- AES-256-GCM --> Encrypted Vault

Active Trusted Browser
    |
    +-- BUK (non-extractable AES-256-GCM key)
    |      +-- wraps same VMK for quick unlock
    |
    +-- BRK (non-extractable ECDSA P-256 private key)
           +-- signs fresh unlock/registration transcripts
```

The Passphrase protects the VMK, not the whole Vault directly. Normal Passphrase change re-wraps the current VMK and does not require Vault re-encryption.

BUK and the Browser Registration Key (BRK) have separate roles. BUK protects the browser-local quick-unlock copy of the VMK. BRK proves possession of the currently registered Browser profile to the Device. The Device persists only the BRK public key and registration metadata.

## Passphrase contract

Before KDF processing, the Passphrase is Unicode NFC-normalized and encoded as UTF-8.

V1 accepts:

- minimum 15 Unicode code points
- maximum 128 Unicode code points
- maximum 512 UTF-8 bytes after normalization
- arbitrary characters without character-class composition requirements
- paste and password-manager input

A six-digit PIN or similarly low-entropy value is not an acceptable offline Recovery-Package protection secret.

The Argon2id algorithm/version, memory/time/parallelism parameters, salt, wrapping algorithm, nonce, and package format are encoded explicitly. Unknown or unsupported parameters fail closed and are not silently reinterpreted.

## Vault ciphertext format

V1 uses **one authenticated ciphertext per Vault generation**.

- cipher: AES-256-GCM
- VMK: random 256-bit
- nonce: fresh random 96-bit value for every Vault encryption
- authentication tag: 128-bit
- canonical `VAULT_FORMAT_VERSION = 1`
- canonical persistence semantics: `STORAGE_SCHEMA_VERSION = 2`

The Vault nonce is never derived solely from `generation`. V1 has no hardware-backed monotonic counter, so a restored old state must not cause deterministic nonce reuse under the same VMK.

Vault AAD binds at least:

- protocol/domain magic and Vault format version
- logical random `vault_id`
- storage schema version
- generation

Device ID is not part of the Vault cryptographic binding because the encrypted canonical state must remain portable to an explicit replacement Device/recovery flow.

## Encrypted metadata boundary

The Vault plaintext includes:

- TOTP secret
- opaque credential id
- issuer
- account label
- user display name
- algorithm / digits / period and other credential profile fields
- manual account order
- Wi-Fi SSID
- Wi-Fi password

The following may persist outside the Vault because they are required for framing/compatibility and do not disclose the credential identity:

- Vault/storage format versions
- generation
- random logical `vault_id`
- ciphertext nonce/tag/length/framing metadata
- non-secret Device/registration public metadata
- BRK public key and registration id/epoch
- UI settings unrelated to credential identity, such as brightness
- `last_used` only as an opaque random credential id; the id-to-account mapping remains inside the Vault

While `LOCKED`, firmware must not expose issuer/account/display-name/SSID plaintext from Flash.

## Device persistence boundary

Device Flash must not persist:

- VMK
- user Passphrase
- Passphrase-derived KEK
- BUK
- BRK private key
- unlock/session key material
- plaintext TOTP or Wi-Fi credentials
- decrypted Vault snapshots

The approved Device credential persistence is the authenticated Encrypted Vault plus the bounded non-secret framing/registration state above.

## Device security states

The minimum security states are:

```text
UNPROVISIONED
LOCKED
UNLOCK_REQUEST
PROVISIONING
UNLOCKED
ERROR
```

`UNLOCK_REQUEST` is a dedicated user-presence state for one fresh attempt. It cannot reuse a button action that occurred before that attempt.

A cold boot with an existing Vault starts `LOCKED`. VMK is absent, account identity metadata is unavailable, and TOTP/Wi-Fi credential access is blocked.

## VMK destruction boundary

The following destroy the in-RAM VMK and pending secret/session material:

- reboot / power loss / shutdown
- explicit Lock
- fatal security error
- Factory Reset
- recovery provisioning
- Trusted Browser replacement
- VMK rotation/re-key

USB power detection, USB enumeration, and opening an ordinary Web Serial management connection do not lock by themselves.

### Ordinary same-VMK generation updates

An account/Wi-Fi mutation by the **currently active canonical Browser** while the Device is already `UNLOCKED` is a same-VMK authenticated generation update, not a recovery-root replacement.

It does not destroy the active VMK or require another physical confirmation for each edit. It must still validate the expected `vault_id`/generation, authenticate the new ciphertext, commit atomically, and fail closed on mismatch or interruption.

## Plaintext lifetime

Although V1 uses one ciphertext per generation, the decrypted logical Vault must not remain resident for the full `UNLOCKED` session.

For TOTP/Wi-Fi access:

1. verify the Device is still `UNLOCKED` with the current VMK
2. decrypt the bounded Vault into transient mutable memory
3. locate/use only the required credential record
4. complete the operation
5. zeroize credential working buffers and the decrypted Vault buffer

Account selection/display metadata may be cached in RAM only while unlocked; it is cleared on Lock. OTP rendering buffers are separately short-lived and are never persisted.

## Web canonical state

The Web side may persist in IndexedDB:

- Encrypted Vault
- Passphrase-wrapped VMK
- BUK-wrapped VMK
- non-extractable BUK
- non-extractable BRK private key and corresponding public registration metadata
- KDF/AEAD/Vault/package version metadata
- generation / `vault_id`
- approved non-secret Device metadata

It must not persist plaintext credentials, the Passphrase, Passphrase-derived KEK, plaintext VMK, decrypted Vault records, imported QR images, or decoded migration payloads.

JavaScript cannot guarantee universal memory zeroization. The Web design therefore minimizes plaintext lifetime, uses mutable byte buffers where practical, avoids unnecessary copies, and never claims perfect browser-RAM erasure.

## Single active Trusted Browser

V1 permits exactly **one active Trusted Browser registration per logical Vault/Device**.

The Device stores the active BRK public key and registration id/epoch as non-secret registration state. A normal quick unlock requires proof of the active BRK private key plus fresh Device user presence.

A Recovery Package imported into a different Browser does not silently create a second writer. To operate the existing Device, that Browser must complete an explicit Trusted Browser replacement/recovery flow. A successful replacement installs a new BRK public key, increments the registration epoch, and prevents the old BRK from authorizing future quick unlocks.

This does not remotely erase an old Browser's local data and is not equivalent to revoking already leaked credential snapshots.

## Encrypted Recovery Package

The Recovery Package is a portable copy of the Web canonical **encrypted** state. It may contain:

- Encrypted Vault
- Passphrase-wrapped VMK
- Argon2id / wrapping / Vault format metadata
- generation / `vault_id`
- explicitly non-secret recovery/registration metadata

It must not contain:

- plaintext TOTP/Wi-Fi credentials
- plaintext VMK
- Passphrase or derived KEK
- BUK
- BRK private key
- browser-specific material that bypasses Passphrase recovery

On import, the user enters the Passphrase; the Browser unwraps VMK locally and generates fresh BUK/BRK keys.

Recovery Package theft creates an offline Passphrase-guessing target. User-generated Recovery Packages therefore remain security-sensitive and must never be committed, attached to Issues/PRs, uploaded as CI artifacts, or treated as safe public ciphertext.

### Passphrase change and old packages

A normal Passphrase change updates the current canonical wrapped VMK. It **does not revoke** previously exported Recovery Packages: an old package can still be opened with the Passphrase that wrapped its VMK at export time.

VMK rotation also cannot erase an already exported old package; that package still contains a decryptable historical Vault snapshot if its old wrapping secret remains known. To make leaked historical TOTP/Wi-Fi credential material unusable, rotate/re-enroll the credentials at their authoritative source service and change the Wi-Fi password where applicable.

The UI should prompt the user to export a replacement package and delete controlled old copies after a Passphrase change, but must not claim cryptographic remote revocation.

## Fresh unlock / registration session

Protocol v2 protects VMK delivery using:

- ephemeral P-256 ECDH on Web and Device
- HKDF-SHA-256 to derive a 32-byte session key from the ECDH shared secret with explicit domain separation and fresh attempt material
- AES-256-GCM with fresh random 96-bit nonce and 128-bit tag for VMK delivery
- ECDSA P-256/SHA-256 BRK signature for normal Trusted Browser requests

Each attempt uses a fresh random 128-bit `attempt_id` and random 256-bit Device challenge. The cryptographic transcript is built from a versioned fixed-order encoding, independent of incidental JSON property ordering, and binds at least:

- protocol/domain and operation
- Device ID
- `vault_id` and expected generation
- registration id/epoch where applicable
- attempt id and challenge
- both ephemeral ECDH public keys
- current/proposed BRK identity as applicable

Pending unlock material expires after 30 seconds. Invalid/stale keys, replay, old challenges, wrong generation, invalid signatures, failed AEAD, rejection, timeout, cancel, superseding attempt, or disconnect fail closed and wipe pending session material.

The fresh session protects against passive serial observation/replay and authenticates the active Browser to the Device. Because V1 has no hardware-backed Device private identity, it does not claim protection from a compromised host/OS or active fake-device/Evil-Maid attack.

## Device user-presence scope

Fresh physical confirmation is mandatory before VMK acceptance or browser/recovery-root change for:

- Trusted Browser quick unlock of a locked Device
- initial provisioning / first registration
- new/untrusted Browser recovery of an existing Device
- Trusted Browser replacement
- VMK rotation/re-key

The confirmation is valid only for the current 30-second attempt. Ordinary same-VMK generation updates while already `UNLOCKED` do not require repeated confirmation.

## Generation and conflict semantics

Web and Device track `generation` plus `vault_id` to detect stale or mismatched replicas. Expected generation is checked before accepting updates.

V1 has no secure monotonic counter, so generation is not a hardware-backed rollback guarantee. A full Device Flash restore may also restore older generation metadata.

Unexpected Web/Device divergence never uses last-writer-wins and is not automatically merged. It enters an explicit recovery/reconciliation path. The single-active-Browser rule prevents normal multi-writer operation by construction.

## Trusted time interaction

OTP reveal requires:

```text
Device security state = UNLOCKED
AND
trusted-time state = READY
```

Credential-backed NTP requires unlock because Wi-Fi credentials are in the Vault.

`time.status` may be read while locked because it is non-secret. `time.sync` may **mutate the trusted anchor only while `UNLOCKED`**. A locked/unprovisioned/provisioning request fails with a bounded non-secret invalid-state response.

An already-established current-boot trusted-time anchor is not cleared merely by explicit Lock. OTP remains blocked by the independent security state. If the same boot is unlocked again before the anchor becomes stale, READY may be reused. Reboot/power loss clears the runtime anchor.

## Factory Reset

Factory Reset must:

- wipe VMK and secret/session RAM state
- erase the Device Encrypted Vault
- erase M5Authenticator user/settings/registration state
- remove matching browser canonical/pairing state in the explicitly paired Web reset flow
- return Device to `UNPROVISIONED`
- perform no M5Authenticator-specific eFuse operation

An exported Recovery Package outside the current browser/device is outside this erase boundary and cannot be deleted remotely by Factory Reset.

## Version boundary and implementation status

Canonical V1 is now active end to end:

- `PROTOCOL_VERSION = 2`
- `STORAGE_SCHEMA_VERSION = 2`
- `VAULT_FORMAT_VERSION = 1`

Tasks #51-#56 activated the Vault format, RAM-only VMK runtime, Trusted Browser ownership, Protocol v2 fresh-session transport, canonical Web/Device management flow, and the V1 release contract. Task #15 is the final security closeout: the release remains production-ineligible until its cross-surface verification is green and the final eligibility gate is explicitly enabled.

Legacy Protocol 1 / Storage Schema 1 source may remain only as non-release historical/test material where required. It is not the canonical firmware bootstrap and must not be compiled into the V1 release credential surface or be advertised as current behavior.

## Superseded design

Decision #40 supersedes Decision #20, Task #26, and PR #39. Production HMAC eFuse-backed NVS Encryption and irreversible Production Security initialization are not part of the V1 target architecture.
