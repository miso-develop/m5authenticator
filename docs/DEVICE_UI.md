# StickS3 Device UI

M5Authenticator V1 uses the M5StickS3 primary `BtnA` for local account selection, OTP reveal, and the explicit user-presence confirmation required by Trusted Browser quick unlock. Account management, secret import, deletion, reorder, Wi-Fi settings, recovery, and reset remain Web/USB operations.

Decision #40 and `docs/SECRET_VAULT.md` define the security state model.

## Security states shown to the user

The Device UI must clearly distinguish at least:

- `UNPROVISIONED`: no usable encrypted Vault is registered
- `LOCKED`: encrypted Vault may exist, but VMK is absent from RAM and OTP reveal is unavailable
- `UNLOCK REQUEST`: a fresh Browser unlock attempt is waiting for physical confirmation
- `PROVISIONING`: credential state is being initialized/replaced/recovered/re-keyed
- `UNLOCKED`: VMK is present in RAM; TOTP use still depends on trusted-time readiness
- `VAULT ERROR`: security/Vault state is invalid and credential access remains blocked

A cold boot or reboot starts `LOCKED` when a Vault exists. The UI must not imply that simply having encrypted data in Flash means the Device is ready to reveal OTPs.

## Trusted Browser user presence

Trusted Browser quick unlock does not require Passphrase re-entry, but it must not unlock unattended.

When a fresh unlock attempt arrives:

1. Device enters an explicit `UNLOCK REQUEST` state.
2. The display makes clear that a connected Browser is requesting unlock.
3. A fresh physical button action is required for that specific attempt.
4. Rejection, timeout, transport failure, or a superseded attempt returns safely to `LOCKED` and wipes pending session material.
5. A button action from a previous attempt must not authorize a later one.

The exact press/hold duration may be finalized by Task #41, but it must not collide ambiguously with normal account-selection/reveal behavior. Unlock confirmation is available only while the dedicated unlock-request screen/state is active.

## Normal button behavior while unlocked

Outside the dedicated unlock-request state:

- single click: select the next account in stored manual order
- double click: select the previous account
- hold: reveal the selected account's six-digit TOTP

Selection wraps at both ends and supports the V1 maximum of 32 accounts. The selected account id may be persisted as non-secret `last_used` metadata; on unlock/boot recovery it is restored when the account still exists.

## Account label

The device displays the first non-empty value in this order:

1. user-defined display name
2. issuer
3. account label

Only non-secret account metadata should be retained in the UI model outside the minimum Vault access needed to refresh the view.

## OTP reveal boundary

OTP reveal requires **both**:

- Device security state = `UNLOCKED`
- trusted-time state = `READY`

A reveal request opens only the selected credential for the minimum practical lifetime, calculates TOTP, wipes plaintext secret buffers, and displays the numeric OTP for at most 10 seconds.

The UI clears its OTP copy when the deadline expires, when time leaves READY, when the Device locks, when selection changes, or when the account metadata generation changes. Temporary formatted display buffers are cleared after drawing.

## Lock behavior

The following security events immediately invalidate OTP reveal and clear any visible OTP:

- explicit Lock
- reboot/power loss
- fatal security error
- Factory Reset
- transition into recovery/re-key/credential-state replacement provisioning

USB power detection, USB enumeration, or opening an ordinary Web Serial connection do not by themselves lock an already-unlocked Device or clear a valid unlocked session.

## Time and empty states

Within `UNLOCKED`, the UI exposes trusted-time readiness:

- `NOT SYNCED`: current boot has not established trusted NTP/USB time; reveal is blocked
- `READY`: reveal is permitted
- `TIME STALE`: more than the allowed trusted-sync age has elapsed; reveal is blocked

Because Wi-Fi credentials are inside the encrypted Vault, a fresh boot normally follows:

```text
LOCKED
  -> Browser unlock + Device confirmation
  -> UNLOCKED / NOT SYNCED
  -> NTP or USB time sync
  -> UNLOCKED / READY
```

With zero accounts after provisioning, the Device displays an explicit empty state directing the user to the Web Provisioner.

## Concurrency

UI, Web Serial, lock/unlock handling, Vault replacement, and trusted-time work must serialize security-sensitive state transitions so a management operation cannot race OTP reveal or leave a stale VMK/session active.

No UI path exports stored secrets or logs OTP/secret/key material.
