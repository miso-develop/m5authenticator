# StickS3 Device UI

M5Authenticator V1 uses the M5StickS3 primary `BtnA` for local account selection and OTP reveal. Device-side UI is intentionally limited: account management, secret import, deletion, reorder, Wi-Fi settings, and reset remain Web/USB operations.

## Button behavior

- single click: select the next account in stored manual order
- double click: select the previous account
- hold: reveal the selected account's six-digit TOTP

The implementation uses M5Unified's decided click-count events (`wasSingleClicked` / `wasDoubleClicked`) so the first click of a double-click is not incorrectly treated as a completed single-click. Hold uses `wasHold`.

Selection wraps at both ends and supports the V1 maximum of 32 accounts. The selected account id is persisted as `last_used`; on boot, that account is restored when it still exists. If no saved selection exists, the first account in manual order is selected.

## Account label

The device displays the first non-empty value in this order:

1. user-defined display name
2. issuer
3. account label

Only non-secret account metadata is retained in the UI model.

## OTP reveal boundary

A long hold calls the trusted-time-aware TOTP generator through the encrypted storage callback. The generator checks time readiness before opening the stored secret and checks time again after storage access is obtained, preventing a delayed request from using an earlier TOTP time step.

The generated OTP is displayed for at most 10 seconds. The UI model clears its numeric OTP copy when the deadline expires, when time leaves READY, when selection changes, or when the account metadata snapshot changes. The temporary formatted display buffer is explicitly cleared after drawing.

While an OTP is visible, the UI task does not perform periodic storage refreshes. This prevents a concurrent management operation from delaying the 10-second hide deadline. A management change may therefore take up to the remaining reveal window to appear on the screen, but it cannot extend OTP visibility beyond the deadline.

## Time and empty states

The UI always exposes one of the trusted-time states:

- `NOT SYNCED`: current boot has not established trusted NTP/USB time; reveal is blocked
- `READY`: reveal is permitted
- `TIME STALE`: more than 24 hours have elapsed since trusted synchronization; reveal is blocked

With zero accounts, the device displays an explicit empty state directing the user to the Web Provisioner.

## Concurrency

The UI runs in its own FreeRTOS task so the existing USB Serial provisioning loop can remain blocking without freezing button handling or the 10-second reveal timer. Device UI account reads/selection writes and complete provisioning protocol requests share one application mutex, preventing local `last_used` updates from racing with account replacement/reorder/delete operations.

Periodic NTP resynchronization remains independent and uses the existing read-only Wi-Fi credential callback. No device UI path exports stored secrets or logs OTP/secret material.
