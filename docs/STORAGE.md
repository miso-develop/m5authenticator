# Secure Account Storage

V1 uses an application-level authenticated Encrypted Vault as the canonical Device credential boundary. Decision #40 and Decisions #45-#49 define the security architecture; `docs/SECRET_VAULT.md` is the durable consolidated security reference.

Canonical production state is **Protocol 2 / Storage Schema 2 / Vault Format 1** with the `encrypted-vault-ram-only-vmk` security profile. The former development Protocol 1 / Storage Schema 1 / public synthetic encrypted-NVS path is retired from the release credential surface and is not a production fallback.

See `docs/V1_REQUIREMENTS.md` for the cross-feature requirements index and `docs/ARCHITECTURE.md` for responsibility/flow boundaries.

## Partition layout

The V1 8 MiB M5StickS3 release layout is defined by `firmware/partitions.csv`:

| Partition | Offset | Size | Purpose |
| --- | ---: | ---: | --- |
| `nvs` | `0x9000` | `0x6000` | ESP-IDF/system NVS boundary; not the canonical authenticator credential store |
| `otadata` | `0xf000` | `0x2000` | dual-OTA selection metadata |
| `phy_init` | `0x11000` | `0x1000` | PHY initialization data |
| `ota_0` | `0x30000` | `0x3d0000` | firmware OTA slot 0 |
| `ota_1` | `0x400000` | `0x3d0000` | firmware OTA slot 1 |
| `auth_nvs` | `0x7d0000` | `0x30000` | Encrypted Vault and bounded non-secret Vault/registration metadata |

`auth_nvs` occupies the final 192 KiB of the 8 MiB flash and begins exactly where `ota_1` ends. Ordinary non-erasing firmware updates must not overwrite it.

The earlier development move from `0x12000` to `0x7d0000` remains a one-time pre-release layout transition. Development devices that crossed that boundary may require clean reprovisioning. Future relocation requires explicit migration design.

## Canonical persistence versions

V1 uses independent compatibility boundaries:

- `STORAGE_SCHEMA_VERSION = 2`
- `VAULT_FORMAT_VERSION = 1`
- `PROTOCOL_VERSION = 2`
- firmware SemVer remains independent from all of the above

Known development Schema 1 may be explicitly rejected/reprovisioned because no production release used it. Unknown newer storage/Vault versions fail closed and must not trigger automatic Factory Reset or speculative migration.

Firmware/Web advertise the canonical versions only because the corresponding end-to-end semantics are active. A matching firmware SemVer never overrides an incompatible protocol/storage/Vault boundary.

## V1 Vault representation

Decision #45 selects **one authenticated ciphertext per Vault generation**.

The Vault uses:

- AES-256-GCM
- random 256-bit VMK
- fresh random 96-bit nonce for every Vault encryption
- 128-bit authentication tag
- versioned AAD including the Vault format/domain, logical random `vault_id`, storage schema, and generation

The nonce is never derived solely from `generation`. Because V1 has no hardware-backed monotonic counter, restoring an old complete state must not create deterministic nonce reuse under the same VMK.

Device ID is not part of the Vault cryptographic binding because an encrypted Recovery Package must be explicitly portable to a replacement Device.

## Encrypted credential/privacy boundary

The Vault plaintext includes:

- TOTP secret
- opaque credential id
- issuer
- account label
- user-defined display name
- algorithm/digits/period and other credential profile fields
- manual order
- Wi-Fi SSID
- Wi-Fi password

These account/Wi-Fi identity fields are intentionally not persisted in plaintext merely because they are not decryption keys. A locked Device must not expose account labels, issuer names, or SSIDs from Flash.

The Device may persist outside the Vault only bounded non-secret state such as:

- storage/Vault format versions
- generation
- random logical `vault_id`
- ciphertext nonce/tag/length/framing metadata
- Device/registration public metadata
- active BRK public key plus registration id/epoch
- non-credential UI settings such as brightness
- `last_used` only as an opaque random credential id; its mapping to account identity remains encrypted

The Device must not persist:

- VMK
- user Passphrase
- Passphrase-derived KEK
- BUK
- BRK private key
- unlock/session keys
- plaintext TOTP/Wi-Fi credential material
- decrypted Vault snapshots

## Canonical replica model

Within M5Authenticator:

```text
Web Encrypted Vault = canonical encrypted replica
Device Encrypted Vault = runtime/offline-use replica
```

This does **not** make Web/M5Authenticator the authoritative service-enrollment source. The original service enrollment and the user's source Authenticator credentials remain the authoritative recovery source for rotating/re-enrolling a compromised TOTP credential.

Credential mutation is coordinated from the single active Trusted Browser. Device-side account editing is not a canonical write path.

## Generation and update semantics

The Vault carries `vault_id` and `generation` to detect stale/mismatched Web/Device replicas and interrupted updates.

Generation is not hardware-backed anti-rollback. Restoring an old complete Flash image may restore old generation metadata as well.

Unexpected divergence never uses last-writer-wins and is not auto-merged. It enters an explicit recovery/reconciliation path.

A same-VMK update from the currently active canonical Browser while the Device is `UNLOCKED` is transactional:

1. open the bounded logical Web Vault transiently
2. apply the mutation
3. encrypt a new generation under the current VMK with a fresh random nonce
4. persist the Web canonical encrypted generation transactionally
5. stage the new encrypted generation on Device
6. verify expected `vault_id` / generation and authenticated structure
7. commit atomically or retain the previous valid generation
8. wipe plaintext/transient crypto buffers

This ordinary generation update does **not** destroy the active VMK or require a new physical confirmation merely because the single ciphertext is replaced.

Recovery provisioning, Trusted Browser replacement, VMK rotation/re-key, Factory Reset, explicit Lock, reboot/power loss, and fatal security error remain VMK-destruction boundaries.

## Runtime access and plaintext lifetime

The VMK exists only while Device state is `UNLOCKED`.

Because V1 uses one ciphertext per generation, firmware may transiently decrypt the bounded Vault for an operation, but it must not keep the decrypted Vault resident for the unlocked session.

TOTP access follows:

```text
verify UNLOCKED + trusted time READY
  -> decrypt bounded Vault to mutable transient memory
  -> locate selected credential by opaque id
  -> use secret for TOTP
  -> wipe credential working buffers
  -> wipe decrypted Vault buffer
```

Wi-Fi credential access is permitted only while unlocked and follows the same transient Vault-open boundary. Runtime Wi-Fi configuration remains RAM-only at the ESP-IDF driver layer so default flash-backed Wi-Fi persistence does not become a second credential store.

Account display metadata may be cached only in unlocked-session RAM and is wiped on Lock.

## Lock and cryptographic erase

Locking normally leaves encrypted ciphertext intact and destroys the VMK/session material instead:

```text
Encrypted Vault remains in Flash
VMK is zeroized from RAM
=> credential plaintext and account identity metadata are unavailable to normal Device code
```

Mandatory VMK-destruction events:

- reboot / power loss / shutdown
- explicit Lock
- fatal security error
- Factory Reset
- recovery provisioning
- Trusted Browser replacement
- VMK rotation/re-key

USB power, USB enumeration, and ordinary Web Serial connection do not themselves lock an existing unlocked session.

## Factory Reset boundary

Factory Reset removes M5Authenticator user/security state from `auth_nvs`, including the Encrypted Vault and registration metadata, wipes secret-bearing RAM state, and returns to `UNPROVISIONED`.

Factory Reset performs no M5Authenticator-specific eFuse operation.

An encrypted Recovery Package exported elsewhere is outside the Device erase boundary.

## Firmware update persistence boundary

Normal firmware Update writes the secret-free merged firmware image without erasing `auth_nvs`. The Encrypted Vault and registration state therefore survive the update. Reboot destroys the RAM-only VMK, so a provisioned Device returns `LOCKED` after Update.

First install and Factory Reset are separate intentionally destructive paths. See `docs/DISTRIBUTION.md`.

## Development history

The earlier `DevSecurityBackend` and planned `HmacEfuseSecurityBackend` architecture are superseded by Decision #40. A public synthetic development XTS/NVS key is never an acceptable V1 release protection boundary because public material cannot protect a copied Flash image.

Tasks #51-#55 introduced and activated the V1 Vault/runtime/Protocol 2 semantics, Task #56 replaced the development release contract, and Task #15 completed the security closeout before production eligibility was enabled. Legacy source may remain only as historical/non-release context and must not be restored to the production component surface.

## Memory, logging, and crash handling

VMK, KEK, BUK, BRK private key, session keys, TOTP secrets, Wi-Fi passwords, decrypted Vault data, plaintext account identity metadata, encoded plaintext snapshots, and credential-bearing protocol buffers must never be logged.

Secret-bearing memory must be wiped using a zeroization method that is not optimized away. Production firmware explicitly disables ESP-IDF core dumps so credential-bearing RAM is not persisted through crash capture.
