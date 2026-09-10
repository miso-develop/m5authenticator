# Web Provisioner

The V1 Web Provisioner is a static Vanilla TypeScript application intended for the latest stable Desktop Chrome. It communicates with M5StickS3 over Web Serial and does not require a server-side API.

## Local-only boundary

Credential-bearing data stays in the browser/device path:

- QR image decoding is local.
- Google migration and standard TOTP parsing are local.
- Imported TOTP secret bytes remain in the ephemeral `ImportSession` until provisioning succeeds or the user clears/leaves the page.
- Wi-Fi passwords are sent only in the USB `wifi.set` request and are not displayed again, persisted, placed in URLs, logged, or sent to analytics/error-reporting services.
- Runtime CDN, remote JS/CSS/font, analytics, telemetry, remote error reporting, and browser persistence are not used.

Account metadata returned by the device never includes stored TOTP secrets.

## Connection and compatibility

A connection is opened only from the user-initiated Connect action. The app establishes a persistent 115200-baud Web Serial session and performs a protocol-v1 `hello` request before management is enabled.

Every response is checked for protocol version and request id. Unsupported protocol versions, malformed envelopes, oversized responses, timeouts, and transport failures fail closed. Device error responses expose only bounded error codes.

## Provisioning

Imported accounts are sent transactionally:

1. `import.begin`
2. one `import.item` per imported account
3. `import.validate`
4. `import.commit`

If an operation fails while the transaction is active, the Web app makes a best-effort `import.cancel` request and preserves the original error. After a successful commit, browser-side imported secret state is cleared.

## Account management

The Web UI supports non-secret management only:

- list account metadata
- set user display name
- manual reorder
- delete

There is no stored-secret read/export UI or protocol call.

## Settings and trusted time

The UI supports:

- Wi-Fi SSID/password set
- Wi-Fi clear
- PC current-time sync over USB
- non-secret device/security/time/account status display

The password input uses `autocomplete="new-password"` and is cleared from the visible form immediately on submit.

## Factory Reset

Factory Reset is available only over the Web/USB path. The user must type `RESET` and then accept a destructive confirmation. The operation erases user state through `factory.reset` but does not attempt to change eFuse security material.

## Browser lifetime

On `pagehide`, the app clears the QR import session and visible Wi-Fi password field and closes the device session on a best-effort basis. JavaScript strings cannot provide a guaranteed zeroization primitive; the application therefore minimizes credential-bearing string lifetime and never persists or logs those values.
