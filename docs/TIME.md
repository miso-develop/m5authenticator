# Trusted Time and TOTP

M5Authenticator V1 treats time readiness as a security boundary. A device that has not established trusted time during the current boot must not reveal TOTP values.

## Time state

| State | OTP reveal | Meaning |
| --- | --- | --- |
| `not_synced` | blocked | no NTP or USB time sync has succeeded during the current boot |
| `ready` | allowed | trusted sync exists and is not more than 24 hours old |
| `stale` | blocked | the last trusted sync is more than 24 hours old, or the monotonic clock moved backwards |

The trusted anchor is runtime-only. Rebooting clears readiness. Current trusted Unix time is derived from the successful sync timestamp plus ESP-IDF's monotonic timer, so stale decisions do not depend on later wall-clock changes.

## Boot synchronization

When encrypted storage contains Wi-Fi credentials, firmware attempts NTP during boot at most three times, with 1-second then 3-second retry delays. Each attempt initializes Wi-Fi only for time synchronization, uses `pool.ntp.org`, and deinitializes the Wi-Fi driver/netif afterward. If all attempts fail, the device remains `not_synced`.

If Wi-Fi is not configured, firmware does not invent another network source. USB synchronization remains available after boot.

## Wi-Fi persistence boundary

`auth_nvs` remains the canonical Wi-Fi credential store. Runtime Wi-Fi explicitly selects `WIFI_STORAGE_RAM`, preventing ESP-IDF's default flash-backed Wi-Fi configuration from becoming a second credential store. The driver/netif is destroyed after each NTP attempt so the transient RAM configuration is not intentionally retained between sync windows. Wi-Fi/NTP is a time source only, not an authentication factor.

## USB trusted time

Protocol v1 adds `time.sync` with integer `unix_seconds`. Accepted timestamps are bounded to 2020-01-01 through 2100-01-01 UTC. Success updates the system wall clock and the current boot's trusted monotonic anchor with source `usb`.

`time.status` and `hello` expose only non-secret fields: `time_state`, `time_source`, `last_sync`, `time_age_seconds`, and `time_resync_due`.

## Periodic resynchronization

Resynchronization becomes due after approximately 6 hours. A background task keeps Wi-Fi deinitialized until the deadline, then performs a short NTP attempt. Failure does not immediately revoke READY; attempts are rate-limited by the six-hour interval. After more than 24 hours without a trusted sync, state becomes `stale` and TOTP generation is blocked. A later successful USB or NTP sync establishes a new anchor.

## TOTP profile

V1 implements RFC 6238 HMAC-SHA-1, 6 digits, 30-second period. Stored secrets are Base32 text. Firmware decodes secret material only in the bounded generation path and clears decoded key and digest buffers afterward. The production primitive is ESP-IDF's pinned mbedTLS HMAC-SHA1 implementation.

Native tests use the published RFC 6238 SHA-1 test secret/digests to verify Base32 decoding, moving counter construction, dynamic truncation, and six-digit output across the published timestamps.

## Reveal boundary

`m5auth::totp::Generator` is the Task #11 interface. It checks time readiness before opening the encrypted account-secret callback: `not_synced` and `stale` reject; only `ready` loads the selected secret briefly, generates the code, then returns through the storage wipe boundary.

No time/TOTP path logs secrets, decoded key bytes, HMAC digests, or Wi-Fi passwords.
