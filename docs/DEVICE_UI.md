# StickS3 Device UI

M5Authenticator V1 uses the M5StickS3 primary `BtnA` for local account selection, OTP reveal, and explicit user-presence confirmation during security-sensitive unlock/registration attempts. Account management, secret import, deletion, reorder, Wi-Fi settings, recovery, and reset remain Web/USB operations.

`docs/SECRET_VAULT.md` is the canonical V1 security-state reference. `docs/V1_REQUIREMENTS.md` and `docs/ARCHITECTURE.md` provide the cross-feature requirements and flow overview. Decisions #45/#47/#48 define the encrypted metadata boundary, single Trusted Browser model, and user-presence scope.

## Security states shown to the user

The Device UI clearly distinguishes at least:

- `UNPROVISIONED`: no usable encrypted Vault is registered
- `LOCKED`: encrypted Vault may exist, but VMK is absent and account identity/OTP reveal are unavailable
- `UNLOCK REQUEST`: one fresh Browser unlock/registration/recovery attempt is awaiting physical confirmation
- `PROVISIONING`: initial/recovery/re-key/registration replacement is in progress
- `UNLOCKED`: VMK is present in RAM; TOTP use still depends on trusted-time readiness
- `VAULT ERROR`: security/Vault state is invalid and credential access remains blocked

A cold boot or reboot starts `LOCKED` when a Vault exists. Merely having ciphertext in Flash never means the Device is ready to show accounts or OTPs.

## Locked metadata privacy

Issuer, account label, user-defined display name, TOTP profile metadata, Wi-Fi SSID/password, and account ordering are inside the encrypted Vault.

While `LOCKED`, the Device must not display or enumerate those plaintext fields from Flash. Status screens may show only approved non-secret fields such as firmware/protocol/storage/Vault versions, generation, registration status, and trusted-time status.

## User-presence request

Fresh physical confirmation is required for:

- Trusted Browser quick unlock from `LOCKED`
- initial provisioning / first registration
- recovery from a new/untrusted Browser to an existing Device
- Trusted Browser replacement
- VMK rotation/re-key

When such an attempt arrives:

1. Device verifies the bounded protocol/session request far enough to reject stale/invalid attempts before asking the user.
2. Device enters a dedicated `UNLOCK REQUEST` screen.
3. The display identifies the operation category without exposing credential/key material.
4. The user must perform a fresh button action for this specific attempt.
5. Confirmation expires after 30 seconds.
6. A button state/action from before the request cannot authorize it.
7. rejection, timeout, cancellation, superseding attempt, transport failure, or cryptographic failure returns safely to the prior non-decrypting state and wipes pending session material.

Normal account-selection/reveal gestures are disabled while `UNLOCK REQUEST` is active, so confirmation cannot collide with those actions.

Ordinary same-VMK account/Wi-Fi generation updates from the active canonical Browser while already `UNLOCKED` do not create repeated physical-confirmation prompts.

## Normal button behavior while unlocked

Outside `UNLOCK REQUEST`:

- single click: select next account in manual order
- double click: select previous account
- hold: reveal selected account's six-digit TOTP

Selection wraps at both ends and supports the V1 maximum of 32 accounts.

After unlock, selection resumes the previously `last_used` account when that opaque credential id is still present in the current Vault generation. The persistent `last_used` value outside the Vault is only an opaque random credential id; its mapping to account identity is inside the encrypted Vault. Account display metadata may be cached in RAM only while unlocked and is cleared on Lock.

## Account label

When unlocked, display uses the first non-empty value in this order:

1. user-defined display name
2. issuer
3. account label

Those values originate from decrypted Vault state and must not be retained in persistent plaintext UI state.

## OTP reveal boundary

OTP reveal requires both:

- Device security state = `UNLOCKED`
- trusted-time state = `READY`

A reveal request transiently opens the bounded single-ciphertext Vault, locates the selected credential by opaque id, calculates TOTP, and wipes decrypted Vault/secret working buffers as soon as practical.

The numeric OTP is displayed for at most 10 seconds. It is cleared when the deadline expires, time leaves READY, Device locks, selection changes, or the account generation changes. Temporary formatted display buffers are cleared after drawing.

## Lock behavior

The following immediately invalidate OTP reveal and clear account/OTP RAM caches:

- explicit Lock
- reboot/power loss
- fatal security error
- Factory Reset
- recovery provisioning
- Trusted Browser replacement
- VMK rotation/re-key

USB power detection, USB enumeration, and ordinary Web Serial connection do not themselves Lock.

A same-VMK canonical Vault generation update while already unlocked does not force a Lock merely because the encrypted single-Vault ciphertext changes; selection/display state must still refresh against the newly committed generation.

## Trusted time states

Within `UNLOCKED`, UI exposes:

- `NOT SYNCED`: no trusted NTP/USB sync established for current boot; reveal blocked
- `READY`: reveal permitted
- `TIME STALE`: last trusted sync older than 24 hours or monotonic integrity failed; reveal blocked

Fresh boot normally follows:

```text
LOCKED / NOT SYNCED
  -> Browser unlock + Device confirmation
  -> UNLOCKED / NOT SYNCED
  -> NTP or USB time.sync
  -> UNLOCKED / READY
```

`time.sync` mutates the trusted anchor only while `UNLOCKED`. If the Device is explicitly locked after READY, the current-boot trusted anchor may remain internally valid but OTP remains blocked by the Lock gate. Re-unlock during the same boot may reuse that anchor if it has not become stale. Reboot/power loss clears it.

With zero accounts after provisioning, the unlocked Device displays an explicit empty state directing the user to the Web Provisioner.

## Concurrency

UI, Web Serial, lock/unlock, Vault generation commit, recovery/re-key, and trusted-time work serialize security-sensitive transitions so an operation cannot race OTP reveal or leave stale VMK/session/account metadata active.

No UI path exports stored secrets or logs OTP/credential/key material.
