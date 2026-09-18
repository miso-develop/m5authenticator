# Trusted Time and TOTP

M5Authenticator V1 treats time readiness as an independent gate for TOTP reveal. Decision #49 defines the mutation boundary, and Decision #159 defines network-time authenticity semantics. `READY` is an operational readiness state; it does **not** mean the source was cryptographically authenticated.

OTP reveal requires both:

```text
Device security state = UNLOCKED
AND
trusted-time state = READY
```

## Time state

| State | OTP reveal | Meaning |
| --- | --- | --- |
| `not_synced` | blocked | no accepted NTP or USB anchor exists during the current boot |
| `ready` | allowed only while Device is also `UNLOCKED` | an accepted current-boot anchor exists and is not more than 24 hours old |
| `stale` | blocked | the last accepted anchor is more than 24 hours old, or monotonic integrity failed |

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

Ordinary SNTP remains the V1.x operational network-time source. It is **unauthenticated network time**: DNS, gateway, Wi-Fi, UDP, or NTP-path manipulation can influence the sample, and `READY` must not be interpreted as cryptographic source authenticity.

When `UNLOCKED` and a Wi-Fi credential exists, firmware may attempt NTP after unlock and at the periodic resynchronization interval. Retry/backoff remains bounded.

The first accepted NTP sample in a boot may establish the operational anchor after the existing Unix-range and state gates. Once any current-boot anchor exists, each later NTP sample is compared with the anchor's monotonic-projected Unix time:

- absolute difference **<= 300 seconds**: accept and refresh anchor/source/freshness;
- absolute difference **> 300 seconds**: reject as an implausible jump;
- rejection does not modify the accepted anchor, `last_sync`, or the 24-hour freshness deadline;
- repeated rejected samples therefore cannot extend `READY`;
- the prior accepted anchor remains usable only until the existing 24-hour stale boundary.

If Wi-Fi is unavailable, synchronization fails, or an NTP jump is rejected, Device remains `not_synced` or later becomes `stale` as applicable. USB time synchronization remains available after unlock.

## USB trusted time

Protocol v2 `time.sync` accepts a bounded integer Unix timestamp only while unlocked. Success updates the wall clock and current boot's monotonic anchor with source `usb`. The NTP 300-second jump rule does not apply to this explicit local-host recovery/control path.

`time.status` exposes only non-secret fields. Its additive `source_authenticity` metadata is stable for V1.x: `ntp` reports `unauthenticated_network`, `usb` reports `local_host_asserted`, and no source reports `none`. `local_host_asserted` is not a claim of cryptographic authentication.

## Periodic resynchronization

Resynchronization becomes due after approximately 6 hours. While `UNLOCKED`, a background task may perform a bounded NTP attempt through the transient Wi-Fi access path.

Failure or rejected NTP resynchronization does not immediately revoke READY. After more than 24 hours without an accepted sync, state becomes `stale` and TOTP reveal is blocked. A later acceptable NTP resync or successful USB sync while unlocked establishes a fresh anchor.

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
