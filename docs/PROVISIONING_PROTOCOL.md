# Provisioning Protocol

`PROTOCOL_VERSION = 1` is independent from firmware SemVer and storage schema version. V1 transport is USB Serial / Web Serial using newline-delimited JSON (NDJSON).

Requests use `{"v":1,"id":42,"op":"hello","params":{}}`; responses use the same version/id with either `ok:true,data` or a bounded error code. Errors never echo request payloads, and credential-bearing parsed fields are wiped before release.

## Device/status

### `hello`
Returns device/firmware/protocol/storage/build metadata, security profile/storage readiness/production eligibility, and trusted-time state/source/age/resync metadata. All are non-secret.

The Web Provisioner validates the response envelope and protocol version before enabling management actions. Unsupported protocol versions fail closed.

## Trusted time

### `time.status`
Returns `time_state` (`not_synced`, `ready`, `stale`), `time_source` (`none`, `ntp`, `usb`), `last_sync`, `time_age_seconds`, and `time_resync_due`. `last_sync` and age are `null` before the first successful current-boot sync.

### `time.sync`
Accepts exact integer `unix_seconds` from the local Web Provisioner, bounded to 2020-01-01 through 2100-01-01 UTC. Success establishes USB as the trusted source and returns the same non-secret status. It accepts or returns no TOTP material.

## Account metadata

`accounts.list` returns stable id, manual order, issuer, account label, and display name only. `account.rename`, `account.delete`, `accounts.reorder`, and `selection.get`/`selection.set` manage non-secret account state. There is no stored-secret read/export operation.

## Transactional import

Secret-bearing import is write-directional only: `import.begin -> import.item * N -> import.validate -> import.commit`. At most 32 items are accepted. `import.cancel` wipes the in-memory transaction. A validation/commit failure does not intentionally modify the previously committed snapshot. Import secrets never appear in responses or logs.

The Web Provisioner keeps QR-decoded secret bytes inside its ephemeral import session, converts each secret to Base32 only for the corresponding `import.item` request, and clears the import session after a successful commit.

## Wi-Fi

`wifi.set` stores SSID/password in encrypted `auth_nvs`; password is write-only. `wifi.status` returns only configured state and SSID. `wifi.clear` removes the stored credentials. Runtime NTP explicitly uses ESP-IDF `WIFI_STORAGE_RAM`, so default flash-backed Wi-Fi persistence is not canonical.

## Factory Reset

### `factory.reset`

Erases and reinitializes the `auth_nvs` user partition through the active Security Backend. It clears any in-memory import transaction first. The reset is serialized against NTP synchronization so a periodic Wi-Fi credential read cannot race the partition erase.

Factory Reset removes accounts, stored TOTP secrets, Wi-Fi credentials, selection/settings stored in the user partition, and returns the device to an unprovisioned-equivalent user state. It does **not** read, burn, rotate, or erase eFuse security material.

The Web UI exposes this operation only after an explicit destructive confirmation (`RESET` plus a browser confirmation dialog).

## Fail-closed limits

Maximum request line is 1024 bytes. Malformed JSON, invalid id, unsupported protocol/version/op, oversized requests, and invalid USB timestamps are rejected. Storage schema/security failures block storage operations. Current-boot time starts unsynchronized; TOTP generation remains blocked until NTP or USB succeeds, and becomes blocked again after more than 24 hours without trusted synchronization.

The protocol vocabulary intentionally contains no operation that reads or exports stored TOTP secrets.
