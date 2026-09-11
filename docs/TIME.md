# Trusted Time and TOTP

M5Authenticator V1 treats time readiness as an independent gate for TOTP reveal. Decision #49 defines the security boundary for trusted-time mutation.

OTP reveal requires both:

```text
Device security state = UNLOCKED
AND
trusted-time state = READY
```

## Time state

| State | OTP reveal | Meaning |
| --- | --- | --- |
| `not_synced` | blocked | no trusted NTP or USB sync has succeeded during the current boot |
| `ready` | allowed only while Device is also `UNLOCKED` | trusted sync exists and is not more than 24 hours old |
| `stale` | blocked | the last trusted sync is more than 24 hours old, or monotonic integrity failed |

The trusted anchor is runtime-only. Current trusted Unix time is derived from the successful sync timestamp plus the monotonic timer, so stale decisions do not depend on later arbitrary wall-clock changes.

## Boot and Lock lifetime

Reboot/power loss clears trusted-time readiness.

Explicit Device Lock does **not** need to erase an already-established current-boot trusted-time anchor because the anchor contains no credential material. TOTP is still blocked by the independent `LOCKED` state. If the same boot is subsequently unlocked and the anchor remains within its validity window, READY may be reused.

## Cold-boot ordering

Wi-Fi credentials are inside the encrypted Vault and cannot be opened while `LOCKED`. A fresh boot does not attempt credential-backed NTP before VMK recovery.

```text
Power on
  -> LOCKED / NOT SYNCED
  -> Trusted Browser quick unlock or Passphrase recovery
  -> Device user-presence confirmation
  -> UNLOCKED / NOT SYNCED
  -> NTP using encrypted Wi-Fi credential, or USB time.sync
  -> UNLOCKED / READY
```

## Trusted-time mutation boundary

Non-secret `time.status` may be read while locked.

`time.sync` may **change the trusted-time anchor only while Device security state is `UNLOCKED`**. Requests in `LOCKED`, `UNPROVISIONED`, `UNLOCK REQUEST`, or `PROVISIONING` fail closed with a bounded non-secret invalid-state response and leave the anchor unchanged.

This prevents an unauthenticated USB host from pre-seeding a timestamp that would later be trusted after the owner unlocks the Device.

USB connection or enumeration itself does not Lock or Unlock the Device.

## Wi-Fi persistence boundary

The approved encrypted Vault is the canonical Wi-Fi credential store. Runtime Wi-Fi explicitly selects `WIFI_STORAGE_RAM`, preventing ESP-IDF's default flash-backed Wi-Fi configuration from becoming a second credential store.

The Vault contains both Wi-Fi SSID and password. Firmware may access them only while `UNLOCKED` by transiently opening the Vault, configuring the driver in RAM, performing NTP, then wiping/deinitializing credential-bearing runtime state.

Wi-Fi/NTP is only a time source and is not an authentication factor.

## NTP synchronization

When `UNLOCKED` and a Wi-Fi credential exists, firmware may attempt NTP after unlock and at the periodic resynchronization interval. Retry/backoff remains bounded.

If Wi-Fi is unavailable or synchronization fails, Device remains `not_synced` or later becomes `stale` as applicable. USB time synchronization remains available after unlock.

## USB trusted time

Protocol v2 `time.sync` accepts a bounded integer Unix timestamp only while unlocked. Success updates the wall clock and current boot's trusted monotonic anchor with source `usb`.

`time.status`/`hello` expose only non-secret fields such as state, source, last-sync metadata, age, and resync-due state.

## Periodic resynchronization

Resynchronization becomes due after approximately 6 hours. While `UNLOCKED`, a background task may perform a bounded NTP attempt through the transient Wi-Fi access path.

Failure does not immediately revoke READY. After more than 24 hours without a successful trusted sync, state becomes `stale` and TOTP reveal is blocked. A later successful USB/NTP sync while unlocked establishes a new anchor.

While `LOCKED`, background work must not open Wi-Fi credentials or mutate the trusted anchor. Existing non-secret current-boot anchor metadata may continue aging for later reuse after unlock.

## TOTP profile

V1 implements RFC 6238 HMAC-SHA-1, 6 digits, 30-second period.

The selected TOTP credential is inside the single authenticated Vault ciphertext. Generation occurs only after the security/time gates pass; firmware transiently opens the bounded Vault, obtains the selected secret, derives the OTP, then clears the decrypted Vault and secret/key/digest working buffers.

Native tests use published RFC 6238 vectors and synthetic credentials only.

## Reveal boundary

A reveal request re-checks both gates around secret access:

1. Device remains `UNLOCKED` with the current VMK session.
2. trusted-time state remains `READY`.

If either condition changes before/during generation, reveal fails closed and temporary plaintext is wiped.

No time/TOTP path logs TOTP secrets, decoded key bytes, HMAC digests, Wi-Fi credentials, VMK, KEK, BUK, BRK private key, or session material.
