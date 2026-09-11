# Secret Vault Architecture

This document is the durable V1 security architecture for protecting TOTP secrets and other credential-bearing device state. Decision #40 is the design history; this document is the current repository truth.

## Goals and non-goals

V1 prioritizes the following properties:

- no M5Authenticator-specific eFuse burn or irreversible project-specific security provisioning
- no plaintext TOTP secret or Wi-Fi password persisted in Device Flash
- no Vault decryption key persisted in Device Flash
- recoverable Factory Reset / erase / re-provision behavior
- practical cold-boot recovery without requiring the user passphrase on every normal unlock
- no stored-secret export operation from release firmware

This is not a hardware root-of-trust design. It does not claim strong resistance to compromised endpoint OS/browser code, malicious browser extensions/XSS, RAM probing while unlocked, sophisticated physical extraction, or Evil-Maid firmware replacement.

## Key hierarchy

V1 uses envelope encryption.

```text
User Passphrase
    |
    v
Password KDF
    |
    v
Passphrase KEK
    |
    +---- unwrap/wrap ----> Vault Master Key (VMK, random 256-bit)
                               |
                               v
                           AEAD Vault

Trusted Browser
    |
    v
Browser Unlock Key (BUK, non-extractable browser-local key)
    |
    +---- unwrap/wrap ----> same VMK
```

The passphrase protects the VMK, not the whole Vault directly. Changing the passphrase therefore normally re-wraps the VMK without requiring the encrypted Vault payload itself to be re-encrypted.

A low-entropy PIN must not be used as an offline-decryptable VMK/Vault protection secret.

The exact KDF, AEAD, nonce, AAD, wrapped-key format, and rotation parameters are versioned implementation details owned by the implementation Task. They must be interoperable between the Web Provisioner and ESP-IDF firmware and must not rely on a project-specific eFuse secret.

## Device persistence boundary

Device Flash may persist only:

- encrypted credential Vault
- Vault format/version metadata
- nonce/authentication data required by the chosen AEAD format
- generation/version metadata
- Device ID / registration metadata that is non-secret
- non-secret settings/metadata that do not allow Vault decryption

Device Flash must not persist:

- VMK
- user passphrase
- passphrase-derived KEK
- Browser Unlock Key
- plaintext TOTP secret
- plaintext Wi-Fi password
- decrypted credential snapshot
- reusable session key capable of recovering the VMK

TOTP and Wi-Fi credential payloads are both inside the approved encrypted credential boundary. This means Wi-Fi credentials are not available until the Device is unlocked.

## Device runtime states

The minimum security states are:

```text
UNPROVISIONED
LOCKED
PROVISIONING
UNLOCKED
ERROR
```

### UNPROVISIONED

No usable encrypted Vault is registered. VMK is absent.

### LOCKED

Encrypted Vault may exist in Flash, but VMK is absent from Device RAM. TOTP and encrypted Wi-Fi credentials cannot be opened.

### PROVISIONING

A security-sensitive Vault replacement, recovery, re-key, or initial registration operation is in progress. Failure or transport loss must wipe transient key material and leave the Device non-decrypting.

### UNLOCKED

Encrypted Vault remains persisted; VMK exists only in RAM. TOTP operations and encrypted Wi-Fi credential access are permitted subject to trusted-time rules.

### ERROR

Secret-bearing transient state is wiped. Recovery must not silently downgrade security or expose an old plaintext/development storage path.

## Lock boundary

The following always destroy the in-RAM VMK and other secret-bearing temporary keys/buffers:

- reboot
- power loss / shutdown
- explicit Lock
- fatal security error
- Factory Reset
- entry into Vault replacement, recovery provisioning, or re-key operations

The following do **not** lock by themselves:

- USB power detection
- USB enumeration
- opening an ordinary Web Serial management connection
- non-destructive status/time communication

This intentionally allows charging or ordinary USB use without destroying an existing unlocked session.

## Cold-boot unlock

After reboot or complete power loss the Device always starts without a VMK:

```text
Power on
  -> encrypted Vault detected
  -> VMK absent
  -> LOCKED
```

The Device cannot autonomously decrypt the Vault from Flash.

### New/untrusted Browser or recovery

```text
LOCKED Device
  -> Web Provisioner connection
  -> user enters Passphrase
  -> KDF derives Passphrase KEK
  -> Web unwraps VMK
  -> protected fresh unlock session
  -> Device user-presence confirmation
  -> VMK accepted into Device RAM
  -> UNLOCKED
```

### Trusted Browser quick unlock

A Trusted Browser has its own browser-local Browser Unlock Key (BUK). The Web Provisioner may persist a BUK-wrapped copy of the VMK for that Browser.

```text
LOCKED Device
  -> registered Trusted Browser connection
  -> BUK unwraps VMK without Passphrase re-entry
  -> protected fresh unlock session
  -> explicit Device user-presence confirmation
  -> VMK accepted into Device RAM
  -> UNLOCKED
```

Trusted Browser quick unlock must not become an unattended automatic unlock. The Device must require explicit physical user presence before accepting the VMK.

The BUK must not be included in backup/export data. Moving to a different Browser therefore requires Passphrase recovery and creation of a new Browser-local BUK.

`extractable=false` is defense in depth only. It does not make the Browser a hardware root of trust and does not protect against arbitrary code executing in the trusted browser context.

## Unlock transport

VMK transfer must use a fresh session mechanism rather than a reusable plaintext protocol operation. The concrete mechanism belongs to the implementation Task, but the following properties are mandatory:

- fresh per-session key establishment or equivalent freshness
- integrity/authentication of transferred unlock material
- no VMK echo in responses, logs, errors, URLs, crash reports, or artifacts
- timeout/cancel/transport failure wipes the pending session material
- Device user presence is bound to the current unlock attempt

Device ID / registration metadata may prevent accidental provisioning to the wrong Device, but it is not described as strong hardware-backed Device authentication.

## Web persistence boundary

The Web side is the canonical Vault state for V1. Browser persistence may contain:

- encrypted Vault
- Passphrase-wrapped VMK
- Trusted-Browser-wrapped VMK
- Browser-local non-extractable BUK
- KDF/crypto format metadata
- generation/version metadata
- registered Device metadata that is non-secret

Browser persistence must not contain plaintext TOTP secrets, plaintext Wi-Fi passwords, the user passphrase, or decrypted Vault records.

Imported QR images and decoded plaintext credential material remain ephemeral and must be discarded after the encrypted canonical Vault and Device runtime copy have been updated successfully.

## Generation and rollback semantics

Web and Device track a Vault `generation` so stale or mismatched copies can be detected. The Web canonical state decides the current generation during management/recovery.

Because V1 intentionally uses no secure monotonic counter/eFuse root, generation is **not** a hardware-backed rollback guarantee. An attacker able to restore the entire Device Flash image may also restore its generation metadata. Documentation and UI must not claim stronger rollback protection than this design provides.

## TOTP use

While `UNLOCKED`, the implementation should minimize plaintext lifetime:

```text
reveal request
  -> open only the selected encrypted credential
  -> calculate TOTP
  -> zeroize plaintext TOTP secret buffer
  -> display OTP for the existing UI timeout
```

The VMK remains in RAM only for the unlocked session. Plaintext per-account secret material should not remain resident for the full session when avoidable.

## Trusted time interaction

Because the encrypted Wi-Fi password is not usable while locked, cold-boot readiness is ordered as:

```text
LOCKED
  -> unlock VMK
  -> UNLOCKED
  -> NTP and/or USB trusted-time sync
  -> READY for TOTP reveal
```

A Device may therefore be unlocked but not yet READY if trusted time has not been established for the current boot.

## Factory Reset

Factory Reset must:

- wipe VMK and all secret-bearing RAM state
- remove the encrypted Vault
- remove user/settings and Device registration state owned by M5Authenticator
- remove/reset browser registration state when the Web side performs the paired reset flow
- return the Device to `UNPROVISIONED`

Factory Reset must not read, burn, rotate, or depend on project-specific eFuse security material.

## Security limitations

This design intentionally does not guarantee protection against:

- a compromised Trusted Browser profile or endpoint OS
- malicious extension/XSS capable of executing in the trusted browser context
- RAM/debug extraction while the Device is `UNLOCKED`
- malicious firmware installed before a later legitimate unlock
- sophisticated physical attacks
- hardware-backed anti-rollback

The primary protected scenarios remain powered-off/rebooted device loss, Flash copying/dumping, accidental or release-interface secret export, and plaintext credential persistence.

## Superseded design

Decision #40 supersedes Decision #20, Task #26, and PR #39. Production HMAC eFuse-backed NVS Encryption and irreversible Production Security initialization are not part of the V1 target architecture.