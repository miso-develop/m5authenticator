# Web Provisioner

The V1 Web Provisioner is a static Vanilla TypeScript application intended for the latest stable Desktop Chrome. It communicates with M5StickS3 over Web Serial and does not require a server-side credential API.

The Web Provisioner holds the **M5Authenticator canonical encrypted replica**. The external service enrollment / source Authenticator remains the authoritative source for replacing or re-enrolling a compromised TOTP credential.

For the cross-feature requirements and component/flow view, see `docs/V1_REQUIREMENTS.md` and `docs/ARCHITECTURE.md`.

## Information architecture

The current V1 app is panel-oriented rather than a tab-routed credential application. Its durable information architecture is:

- **Firmware Flash** — separate flasher page for first install and state-preserving Update.
- **Device** — connect, status, Trusted Browser unlock, clean replacement restore, Lock & Disconnect, refresh, and PC trusted-time sync.
- **Accounts** — local QR import and canonical account management.
- **Settings** — Wi-Fi-for-NTP and approved Device settings.
- **Security & Recovery** — browser Vault/Trusted Browser status, Recovery Package import/export, Recovery Passphrase change, and VMK rotation.
- **Factory Reset** — explicit destructive normal/recovery reset.

The visual layout may evolve, but these responsibility/security boundaries remain V1 current truth.

## Local-only boundary

Credential-bearing data stays in the browser/device path:

- QR image decoding is local.
- Google migration and standard TOTP parsing are local.
- TOTP secret, account identity metadata, and Wi-Fi credentials exist as plaintext only in transient browser memory while editing/importing the logical Vault.
- VMK recovery/wrapping and Trusted Browser key operations are local.
- Runtime CDN, remote JS/CSS/font, analytics, telemetry, remote error reporting, dynamic module loading, and remote credential/key APIs are not used.
- No TOTP secret, Wi-Fi password, VMK, Passphrase, Passphrase-derived KEK, BUK, BRK private key, decrypted Vault record, or migration payload is sent to GitHub Pages or another server.

## Browser persistence

IndexedDB is the structured persistence surface for V1 state.

Browser persistence may contain:

- Encrypted Vault
- Passphrase-wrapped VMK
- BUK-wrapped VMK
- browser-local non-extractable AES-256-GCM Browser Unlock Key (BUK)
- browser-local non-extractable ECDSA P-256 Browser Registration Key (BRK) private key
- BRK public registration metadata / registration id / epoch
- KDF/AEAD/Vault/package version and generation metadata
- logical `vault_id`
- approved non-secret Device metadata

Browser persistence must not contain:

- plaintext TOTP secrets
- plaintext issuer/account/display-name or Wi-Fi credential records outside the encrypted Vault
- the user Passphrase
- Passphrase-derived KEK
- plaintext VMK
- decrypted Vault records
- imported QR images / decoded migration payloads

`extractable=false` is defense in depth, not a hardware-backed guarantee. Code executing in the trusted browser/origin context may still use these keys. Endpoint/browser/XSS compromise remains outside the strong V1 threat-model guarantee.

## Vault format

V1 uses one AES-256-GCM authenticated ciphertext per generation under a random 256-bit VMK. Every Vault encryption uses a fresh random 96-bit nonce and 128-bit tag. AAD binds format/domain, `vault_id`, storage schema, and generation.

The encrypted Vault contains credential identity metadata as well as credential secrets: issuer/account/display name, TOTP profile/order, Wi-Fi SSID/password, and opaque credential ids.

See Decision #45 and `docs/SECRET_VAULT.md`.

## Passphrase recovery

The Passphrase protects the VMK, not the full Vault directly:

```text
NFC-normalized Passphrase UTF-8
  -> Argon2id v19 (m=32768 KiB, t=3, p=1, 32-byte random salt)
  -> 256-bit KEK
  -> AES-256-GCM unwrap VMK
```

Passphrase policy:

- minimum 15 Unicode code points
- maximum 128 Unicode code points
- maximum 512 UTF-8 bytes after NFC normalization
- no character-class composition requirement
- paste/password-manager input allowed
- six-digit PIN or similarly low-entropy value rejected

KDF/wrap parameters are versioned with the state. Unknown parameters fail closed.

A Passphrase alone cannot reconstruct a lost random VMK. Recovery requires the encrypted canonical state, normally through the Recovery Package.

## Single active Trusted Browser

V1 permits exactly **one active Trusted Browser registration per logical Vault/Device**.

That Browser owns two separate non-extractable keys:

- **BUK:** AES-256-GCM key used only to unwrap the browser-local quick-unlock copy of VMK.
- **BRK:** ECDSA P-256 private key used to sign fresh unlock/registration transcripts. Device stores only the BRK public key and registration id/epoch.

Normal quick unlock:

```text
Connect Device
  -> confirm vault_id/generation/registration compatibility
  -> BUK unwraps VMK locally
  -> BRK signs the fresh unlock transcript
  -> Device validates registered Browser request
  -> Device displays UNLOCK REQUEST
  -> user confirms physically within the current attempt
  -> fresh ECDH/HKDF/AES-GCM session delivers VMK
  -> Device becomes UNLOCKED
```

Passphrase re-entry is not required for this normal path, but physical Device confirmation remains mandatory.

## Trusted Browser replacement

A second Browser must not become a silent concurrent writer.

A new Browser can import a Recovery Package and recover VMK with the Passphrase, then generates fresh BUK/BRK keys. To manage an existing Device it must complete an explicit Trusted Browser replacement/recovery flow with Device user presence. Success replaces the Device BRK public key, increments the registration epoch, and prevents the old BRK from authorizing future quick unlocks.

This replacement does not remotely erase the old browser profile or invalidate credential snapshots it already possesses.

## Encrypted Recovery Package

V1 exports/imports a versioned encrypted package containing only portable canonical encrypted state:

- Encrypted Vault
- Passphrase-wrapped VMK
- Argon2id / wrapping / Vault metadata
- generation / `vault_id`
- explicitly non-secret recovery/registration metadata

It must not contain plaintext credentials, plaintext VMK, Passphrase/KEK, BUK, BRK private key, or browser-specific quick-unlock material that bypasses Passphrase recovery.

The package is security-sensitive because theft permits offline Passphrase guessing. It must never be automatically uploaded, used as public debugging evidence, or treated as safe merely because encrypted.

### Passphrase change and old packages

Normal Passphrase change re-wraps the **current** VMK in the canonical browser state.

Previously exported Recovery Packages remain decryptable with their old Passphrase. They cannot be remotely revoked. The UI therefore instructs the user to export a new package and delete old copies they control, but must not claim cryptographic invalidation of copies elsewhere.

If a historical Recovery Package is leaked and must be made unusable, rotate/re-enroll the affected TOTP credential at its authoritative service and change affected Wi-Fi credentials where necessary. VMK rotation alone cannot erase an already exported historical snapshot.

## Connection and compatibility

Connection begins only from a user-initiated Connect action. The app opens Web Serial and performs `hello` before management is enabled.

Canonical V1 uses **Protocol 2 / Storage Schema 2 / Vault Format 1**. Unsupported or mismatched versions, request ids, malformed envelopes, oversized responses, timeouts, invalid registration epoch, invalid generation, and transport failures fail closed for security-sensitive operations. Protocol 1 / Storage Schema 1 remain historical development semantics and are never silently reinterpreted as V1.

Opening Web Serial by itself does not Lock an already-unlocked Device.

## Canonical Vault management

Only the active Trusted Browser is the normal canonical writer for an existing Vault/Device pair.

Account import, rename, reorder, delete, and Wi-Fi changes operate as:

1. recover/use the current VMK through Passphrase or active BUK as appropriate
2. decrypt bounded logical Vault state into transient mutable memory
3. apply mutation
4. encrypt a new Vault generation with a fresh random nonce
5. persist the Web canonical encrypted generation transactionally
6. synchronize only the encrypted generation to Device
7. verify expected `vault_id`/generation and atomic Device commit
8. wipe transient plaintext/crypto buffers as far as the Web platform permits

When Device is already validly `UNLOCKED` under the same VMK, this ordinary generation update does not force another Lock/user-presence cycle for each edit.

Unexpected generation divergence is not last-writer-wins and is not auto-merged; the UI enters explicit recovery/reconciliation.

There is no stored-secret read/export UI from Device.

## QR import

QR screenshots and decoded migration/TOTP payloads are transient. They are not persisted as images/plaintext or uploaded.

### Standard TOTP QR

A standard TOTP QR is decoded and parsed locally, validated against the supported V1 TOTP profile, placed in the transient import session, then committed through one encrypted canonical Vault generation update.

### Google Authenticator migration QR

Migration QR screenshots are also decoded and parsed locally. Multi-QR migration batches may accumulate only in transient import-session state until the batch is complete. Applying the batch performs the same canonical encrypted-generation mutation/synchronization path. Successful import clears the QR/migration working state best-effort.

After a successful encrypted Vault update, the import session is cleared. Leaving/reloading the page clears transient state on a best-effort basis.

## Trusted time

The UI supports non-secret `time.status` while locked, but trusted-time mutation follows Decision #49:

- `time.sync` is enabled only when Device is `UNLOCKED`
- a locked/unprovisioned/provisioning/unlock-pending sync request fails closed
- credential-backed NTP is available only while unlocked because Wi-Fi credentials are in the Vault
- an existing current-boot trusted anchor may survive explicit Lock; reboot/power loss clears it

Time is not an authentication factor. OTP reveal still requires both `UNLOCKED` and time `READY`.

## Security-sensitive Device operations

Fresh Device user presence is required for:

- initial provisioning / first registration
- Trusted Browser quick unlock from LOCKED
- recovery to an existing Device from a new/untrusted Browser
- Trusted Browser replacement
- VMK rotation/re-key

Ordinary same-VMK canonical generation updates while already unlocked do not require repeated confirmation.

## Factory Reset

Factory Reset is available only through the Web/USB management path and requires explicit destructive confirmation.

It wipes Device VMK/session material, Device encrypted Vault/registration/user state, and removes matching browser canonical/pairing state in the paired flow before returning Device to `UNPROVISIONED`.

Factory Reset performs no M5Authenticator-specific eFuse operation and cannot delete Recovery Packages saved outside the current browser/device.

## Firmware update

Firmware Flash is a separate same-origin page. A normal Update uses the exact validated secret-free CI-built merged firmware image with non-erasing semantics so `auth_nvs` remains intact. Reboot destroys the RAM-only VMK, so a provisioned Device returns `LOCKED` after update while the Encrypted Vault/registration state remains.

First install is the explicitly destructive path. See `docs/DISTRIBUTION.md`.

## Browser lifetime and zeroization limits

On lifecycle termination, the app clears transient QR/import state, Passphrase/credential form values, unwrapped VMK/KEK references, decrypted Vault buffers, and open Device sessions on a best-effort basis.

JavaScript/Web memory has no universal guaranteed zeroization primitive for all values. The design minimizes plaintext lifetime, prefers byte-oriented mutable buffers, avoids unnecessary copies, and relies on encrypted-at-rest persistence rather than claiming perfect browser-RAM scrubbing.

## Implementation status and lineage

The canonical V1 implementation chain is complete:

- #51 Vault crypto/format interoperability foundation
- #52 browser canonical Vault / Recovery / Trusted Browser state
- #53 Device RAM-only Vault runtime
- #54 fresh Protocol 2 unlock/session primitives
- #55 end-to-end Protocol 2 management activation
- #56 V1 release contract transition
- #15 final V1 security closeout and production eligibility

Decision #40 is the current security root and Decisions #45-#49 are its refinements. Decision #20 / Task #26 / PR #39 are superseded eFuse/HMAC-path history only.
