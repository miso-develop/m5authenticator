# Trusted Time and TOTP

M5Authenticator V1 treats time readiness as a security boundary. A device that has not established trusted time during the current boot must not reveal TOTP values.

Decision #40 adds an independent Vault lock boundary. OTP reveal therefore requires both:

```text
Device security state = UNLOCKED
AND
trusted-time state = READY
```

## Time state

| State | OTP reveal | Meaning |
| --- | --- | --- |
| `not_synced` | blocked | no NTP or USB time sync has succeeded during the current boot |
| `ready` | allowed only when Device is also `UNLOCKED` | trusted sync exists and is not more than 24 hours old |
| `stale` | blocked | the last trusted sync is more than 24 hours old, or the monotonic clock moved backwards |

The trusted anchor is runtime-only. Rebooting clears readiness. Current trusted Unix time is derived from the successful sync timestamp plus ESP-IDF's monotonic timer, so stale decisions do not depend on later wall-clock changes.

## Cold-boot ordering

Wi-Fi credentials are inside the encrypted credential Vault and cannot be opened while the Device is `LOCKED`. A fresh boot therefore does **not** attempt credential-backed NTP before VMK recovery.

The normal cold-boot sequence is:

```text
Power on
  -> LOCKED / not_synced
  -> Trusted Browser quick unlock or Passphrase recovery
  -> Device user-presence confirmation
  -> UNLOCKED / not_synced
  -> NTP using encrypted Wi-Fi credential, or USB time.sync
  -> UNLOCKED / READY
```

USB `time.sync` carries no stored credential material and may be accepted while locked, but that does not make OTP reveal available until the Device is also unlocked.

## Wi-Fi persistence boundary

The approved encrypted Vault remains the canonical Wi-Fi credential store. Runtime Wi-Fi explicitly selects `WIFI_STORAGE_RAM`, preventing ESP-IDF's default flash-backed Wi-Fi configuration from becoming a second credential store.

After unlock, firmware may open the Wi-Fi credential only for the synchronization operation, configure the driver transiently in RAM, perform NTP, and wipe/deinitialize the credential-bearing runtime state afterward. Wi-Fi/NTP is a time source only, not an authentication factor.

## NTP synchronization

When the Device is `UNLOCKED` and the encrypted Vault contains Wi-Fi credentials, firmware may attempt NTP at boot-unlock readiness and at the periodic resynchronization interval. Retry/backoff remains bounded.

If Wi-Fi is not configured or synchronization fails, the Device remains `not_synced` or eventually `stale` as applicable. USB synchronization remains available.

## USB trusted time

Protocol v2 retains `time.sync` with an integer Unix timestamp bounded to the supported range. Success updates the system wall clock and the current boot's trusted monotonic anchor with source `usb`.

`time.status` and `hello` expose only non-secret fields such as `time_state`, `time_source`, `last_sync`, `time_age_seconds`, and `time_resync_due`.

USB connection or time synchronization by itself does not unlock or lock the Device.

## Periodic resynchronization

Resynchronization becomes due after approximately 6 hours. While `UNLOCKED`, a background task may perform a short NTP attempt using the transient Wi-Fi credential access path. Failure does not immediately revoke READY; attempts are rate-limited by the defined interval.

After more than 24 hours without a trusted sync, state becomes `stale` and TOTP generation is blocked. A later successful USB or NTP sync establishes a new anchor.

When the Device transitions to `LOCKED`, periodic Wi-Fi/NTP work must not retain or reopen the encrypted Wi-Fi credential without a VMK.

## TOTP profile

V1 implements RFC 6238 HMAC-SHA-1, 6 digits, 30-second period.

The selected TOTP secret is decrypted/opened only after both security and trusted-time gates pass. Firmware decodes and uses the secret only for the bounded generation path, then clears plaintext secret/key/digest buffers afterward.

Native tests use published RFC 6238 vectors and synthetic credentials only.

## Reveal boundary

A reveal request must re-check both conditions around the secret-access boundary:

1. Device remains `UNLOCKED` with the current valid VMK session.
2. trusted-time state remains `READY`.

If either changes before/during generation, reveal fails closed and temporary plaintext buffers are wiped.

No time/TOTP path logs TOTP secrets, decoded key bytes, HMAC digests, Wi-Fi passwords, VMK, or session-key material.
