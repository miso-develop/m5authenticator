# Secure Account Storage

V1 uses an application-level authenticated Encrypted Vault as the canonical Device credential boundary. The Vault is stored in the dedicated `auth_nvs` partition, while the Vault Master Key (VMK) is never persisted on the Device and exists only in RAM during an `UNLOCKED` session.

Decision #40 and `docs/SECRET_VAULT.md` define the canonical security architecture. Task #41 tracks implementation of this architecture. Until #41 is merged and release validation is updated, the existing development storage backend must not be treated as production-ready security.

## Partition layout

The V1 8 MiB M5StickS3 release layout is defined by `firmware/partitions.csv`:

| Partition | Offset | Size | Purpose |
| --- | ---: | ---: | --- |
| `nvs` | `0x9000` | `0x6000` | ESP-IDF/system NVS boundary; not the canonical store for authenticator credentials |
| `otadata` | `0xf000` | `0x2000` | dual-OTA selection metadata |
| `phy_init` | `0x11000` | `0x1000` | PHY initialization data |
| `ota_0` | `0x30000` | `0x3d0000` | firmware OTA slot 0 |
| `ota_1` | `0x400000` | `0x3d0000` | firmware OTA slot 1 |
| `auth_nvs` | `0x7d0000` | `0x30000` | Encrypted Vault and non-secret Vault metadata |

`auth_nvs` occupies the final 192 KiB of the 8 MiB flash and starts exactly where `ota_1` ends. Ordinary non-erasing firmware updates must not overwrite it.

The existing pre-release move from `0x12000` to `0x7d0000` remains a one-time development layout transition. Development devices that crossed that boundary may require clean reprovisioning. Future relocation requires explicit migration design.

## Persistent data boundary

The Device may persist:

- authenticated Encrypted Vault ciphertext
- Vault format/schema version
- AEAD nonce/authentication metadata
- generation/version metadata
- non-secret Device/registration metadata
- non-secret UI/settings metadata where appropriate

The Device must not persist:

- VMK
- user Passphrase
- Passphrase-derived KEK
- Browser Unlock Key (BUK)
- plaintext TOTP secrets
- plaintext Wi-Fi passwords
- decrypted credential snapshots
- reusable unlock-session secrets

TOTP credential data and Wi-Fi credentials are both inside the encrypted credential boundary.

## Storage/Vault versioning

The pre-Decision-#40 development implementation uses `STORAGE_SCHEMA_VERSION = 1` for a logical snapshot protected by the development encrypted-NVS backend. The new Encrypted Vault representation changes the persisted security meaning and must not silently reuse that schema.

Task #41 must therefore introduce the V1 target as:

- **`STORAGE_SCHEMA_VERSION = 2`** for the Device persistence layout/metadata semantics
- **`VAULT_FORMAT_VERSION = 1`** for the first application-level Encrypted Vault ciphertext format

Both remain independent from firmware SemVer and provisioning protocol version.

Known development schema 1 may be explicitly rejected/reprovisioned because no production release was created with it. Unknown newer schema/Vault versions must fail closed and must not trigger automatic Factory Reset or speculative migration.

The Vault also carries a `generation` value coordinated with the Web canonical copy. Generation is used to detect stale or mismatched Device/Web copies and interrupted updates.

Generation is not a hardware-backed monotonic counter. Because V1 intentionally does not use an eFuse/secure-counter root, restoring an old complete Flash image may also restore old generation metadata. Device-only cryptographic rollback resistance is therefore not claimed.

## Canonical state model

For V1:

```text
Web Encrypted Vault = canonical copy
Device Encrypted Vault = runtime/offline-use copy
```

Credential mutation is coordinated from the Web Provisioner. Device-side account editing is not a canonical write path.

A Vault update must be transactional/atomic from the externally observable perspective:

1. build/validate the new logical state in transient memory
2. encrypt it under the active VMK using the versioned AEAD format
3. stage the new ciphertext/metadata/generation
4. commit atomically or retain the previous valid generation
5. wipe plaintext/transient crypto buffers

Power loss or USB failure must not leave a partially accepted generation as the canonical state.

## Runtime access

The VMK exists only while the Device is `UNLOCKED`.

TOTP access should narrow plaintext lifetime:

```text
selected credential request
  -> decrypt/open only required credential material
  -> calculate TOTP
  -> wipe plaintext TOTP secret
```

Wi-Fi credential access is also permitted only while unlocked. Runtime Wi-Fi configuration remains RAM-only at the ESP-IDF driver layer so ESP-IDF's default flash-backed Wi-Fi persistence does not become a second credential store.

## Lock and cryptographic erase

Locking does not require repeatedly erasing the Vault ciphertext. Instead the Device destroys the VMK and other transient secret material:

```text
Encrypted Vault remains in Flash
VMK is zeroized from RAM
=> credential plaintext becomes unavailable to normal Device code
```

Mandatory VMK-destruction events are:

- reboot
- power loss/shutdown
- explicit Lock
- fatal security error
- Factory Reset
- entry into Vault replacement, recovery provisioning, or re-key

USB power, USB enumeration, and ordinary Web Serial connection do not themselves lock an existing unlocked session.

## Factory Reset boundary

Factory Reset removes the M5Authenticator user/security state from `auth_nvs`, including the Encrypted Vault and registration metadata, and wipes all secret-bearing RAM state before returning to `UNPROVISIONED`.

Factory Reset performs no project-specific eFuse read/burn/rotation and leaves no irreversible M5Authenticator security state behind.

## Development-to-V1 transition

The earlier `DevSecurityBackend`/planned `HmacEfuseSecurityBackend` architecture is superseded by Decision #40. A public synthetic development XTS/NVS key may still exist in pre-#41 code for development verification, but it is not an acceptable V1 release protection boundary because a Flash dump would be decryptable using public material.

Release validation must remain fail closed until Task #41 replaces that path with the application-level Encrypted Vault + RAM-only VMK design.

## Memory, logging, and crash handling

VMK, KEK, BUK-derived working material, session keys, TOTP secrets, Wi-Fi passwords, decrypted Vault data, encoded plaintext snapshots, and credential-bearing protocol buffers must never be logged.

Secret-bearing memory must be wiped using a zeroization method that is not optimized away. Production crash/core-dump settings must not persist credential-bearing RAM in a form that defeats the RAM-only VMK design.
