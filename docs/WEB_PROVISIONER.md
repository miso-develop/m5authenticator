# Web Provisioner

The V1 Web Provisioner is a static Vanilla TypeScript application intended for the latest stable Desktop Chrome. It communicates with M5StickS3 over Web Serial and does not require a server-side API.

Decision #40 changes the Web Provisioner from a purely ephemeral import/provisioning surface into the **canonical encrypted Vault holder** for V1. Plaintext credentials remain browser-local and ephemeral; only encrypted Vault/key-wrapping state is persisted.

## Local-only boundary

Credential-bearing data stays in the browser/device path:

- QR image decoding is local.
- Google migration and standard TOTP parsing are local.
- TOTP secret and Wi-Fi credential plaintext exist only in transient browser memory while editing/importing the logical Vault.
- VMK recovery and wrapping are local.
- Runtime CDN, remote JS/CSS/font, analytics, telemetry, remote error reporting, and remote credential APIs are not used.
- No TOTP secret, Wi-Fi password, VMK, Passphrase, Passphrase-derived KEK, BUK, decrypted Vault record, or migration payload is sent to GitHub Pages or another server.

## Browser persistence

Browser persistence is allowed for encrypted/key-wrapping state only. The canonical V1 browser state may contain:

- Encrypted Vault
- Passphrase-wrapped VMK
- Trusted-Browser-wrapped VMK
- browser-local non-extractable Browser Unlock Key (BUK)
- KDF/AEAD/version/generation metadata
- non-secret registered Device metadata

Browser persistence must not contain:

- plaintext TOTP secrets
- plaintext Wi-Fi passwords
- the user Passphrase
- Passphrase-derived KEK
- decrypted Vault records
- imported QR images

IndexedDB is the intended structured persistence surface. The exact Web Crypto / KDF implementation and data schema are finalized by Task #41.

`extractable=false` on the BUK is defense in depth, not a hardware-backed guarantee. Code executing in the trusted browser/origin context may still be able to use the key. Compromised endpoint/browser/XSS is therefore outside the strong V1 threat-model guarantee.

## Key hierarchy

The Web Provisioner uses envelope encryption:

```text
Passphrase -> password KDF -> KEK -> wrapped VMK
VMK -> AEAD -> Encrypted Vault
BUK -> Trusted-Browser-wrapped VMK
```

The Passphrase does not directly encrypt the full Vault. Passphrase change normally re-wraps the VMK.

A low-entropy PIN must not be accepted as the offline-decryptable protection secret for VMK recovery.

## First registration / new Browser / recovery

A Browser that has no valid Trusted Browser registration must require the Passphrase:

```text
Passphrase
  -> derive KEK
  -> unwrap VMK
  -> open/update canonical encrypted Vault as needed
  -> establish a new Browser-local BUK
  -> create Trusted-Browser-wrapped VMK
  -> perform Device unlock/provisioning with explicit Device user presence
```

The BUK is never exported as part of a Vault backup. Restoring on another Browser therefore requires the Passphrase and creates a new BUK.

## Trusted Browser quick unlock

For a registered Browser:

```text
Connect Device
  -> confirm registered Device / generation compatibility
  -> BUK unwraps VMK locally
  -> start fresh protected Device unlock session
  -> Device displays unlock request
  -> user confirms physically on Device
  -> VMK is delivered for that fresh session
  -> Device becomes UNLOCKED
```

Normal Trusted Browser unlock does **not** require Passphrase re-entry.

Quick unlock is not fully automatic. The Web UI must show an explicit pending state and the Device must require physical user presence before accepting the VMK.

## Connection and compatibility

A connection is opened only from a user-initiated Connect action. The app establishes Web Serial and performs `hello` before management is enabled.

After Task #41, the V1 security flow requires protocol v2. Every response is checked for protocol version and request id. Unsupported protocol versions, malformed envelopes, oversized responses, timeouts, invalid generations, and transport failures fail closed for security-sensitive operations.

Opening a Web Serial connection by itself does not Lock an already-unlocked Device.

## Canonical Vault management

Web is the canonical V1 Vault copy. Account import, rename, reorder, delete, and Wi-Fi setting changes operate on a transient logical Vault, then produce a new authenticated encrypted generation.

The externally visible update sequence is:

1. unlock canonical VMK using Passphrase or Trusted Browser BUK
2. decrypt only the required logical state in browser memory
3. apply the requested mutation
4. encrypt a new Vault generation under the same/current VMK
5. persist the new canonical encrypted generation transactionally
6. synchronize the encrypted generation to Device using the protocol-v2 provisioning flow
7. wipe plaintext/transient credential and crypto buffers as far as the Web platform permits

A failed Device synchronization must be surfaced explicitly. Generation metadata is used to detect stale Device state on the next connection.

There is no stored-secret read/export UI from the Device.

## QR import

Imported QR images and decoded migration/TOTP payloads are transient inputs. They must not be persisted as images or plaintext payloads.

After a successful encrypted Vault update, the Web app clears import-session plaintext. Leaving/reloading the page also clears transient import state on a best-effort basis.

## Settings and trusted time

The UI supports:

- encrypted Wi-Fi credential update through the canonical Vault flow
- Wi-Fi clear through the canonical Vault flow
- PC current-time sync over USB
- non-secret Device/lock/security/time/Vault-generation status display
- explicit Lock
- Trusted Browser registration/recovery state

Because Wi-Fi credentials are inside the encrypted Vault, Device-side NTP is available only after the Device is unlocked. USB time sync can remain available independently.

## Security-sensitive management operations

Ordinary status/time communication and USB connection do not Lock the Device.

Operations that replace or re-key credential state must transition through the safe lock/provisioning boundary, including:

- initial provisioning
- Vault replacement where required by protocol state
- recovery provisioning
- VMK re-key/rotation
- Factory Reset

The UI must make these transitions explicit rather than silently destroying an active unlocked session.

## Factory Reset

Factory Reset remains available only over the Web/USB path and requires explicit destructive confirmation.

It must wipe Device VMK/session material, remove the Device encrypted Vault/registration state, and return the Device to `UNPROVISIONED`. The paired Web flow must remove the matching canonical/Trusted-Browser registration state according to the finalized UX.

Factory Reset performs no M5Authenticator-specific eFuse operation.

## Browser lifetime and zeroization limits

On page lifecycle termination, the app clears transient QR/import state, Passphrase/credential form values, unwrapped VMK/KEK working references, and open Device sessions on a best-effort basis.

JavaScript/Web platform memory does not provide a universal guaranteed zeroization primitive for all strings/objects. The design therefore minimizes plaintext lifetime, prefers byte-oriented buffers where practical, avoids unnecessary copies, and relies on encrypted-at-rest browser persistence rather than pretending browser RAM can be perfectly scrubbed.
