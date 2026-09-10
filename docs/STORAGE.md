# Secure Account Storage

V1 keeps user/security state in the dedicated `auth_nvs` partition. This partition is separate from both OTA application slots and from the normal merged firmware write range so ordinary firmware updates preserve provisioned state.

## Partition layout

The V1 8 MiB M5StickS3 release layout is defined by `firmware/partitions.csv`:

| Partition | Offset | Size | Purpose |
| --- | ---: | ---: | --- |
| `nvs` | `0x9000` | `0x6000` | ESP-IDF/system NVS boundary; not the canonical store for authenticator credentials |
| `otadata` | `0xf000` | `0x2000` | dual-OTA selection metadata |
| `phy_init` | `0x11000` | `0x1000` | PHY initialization data |
| `ota_0` | `0x30000` | `0x3d0000` | firmware OTA slot 0 |
| `ota_1` | `0x400000` | `0x3d0000` | firmware OTA slot 1 |
| `auth_nvs` | `0x7d0000` | `0x30000` | canonical encrypted authenticator/Wi-Fi user state |

`auth_nvs` occupies the final 192 KiB of the 8 MiB flash and starts exactly where `ota_1` ends. The OTA offsets and 0x3d0000-byte slot sizes remain unchanged.

Task #14 deliberately moved `auth_nvs` from the early development offset `0x12000` to the end of flash before a production release existed. ESP-IDF `idf.py merge-bin -f raw` produces an offset-0 merged image containing the bootloader, partition table, OTA metadata/application and required build outputs. Without `--pad-to-size`, that merged image ends within the application write range. Keeping `auth_nvs` after both OTA slots therefore prevents a normal non-erasing merged-image update from writing `0xFF` gap bytes over authenticator state.

This one-time pre-release layout transition does **not** preserve development data written by firmware using the old `0x12000` layout. Development devices crossing this boundary must be treated as requiring a clean reprovision. After this V1 release layout is established, further `auth_nvs` relocation requires an explicit migration/update design and must not be done casually.

## Storage schema

`STORAGE_SCHEMA_VERSION` is independent from firmware SemVer and protocol version. V1 uses schema `1`.

Initialization behavior is fail closed:

- missing schema on an erased/new partition initializes schema 1 and an empty state
- schema 1 is validated before normal read/write use
- an unknown schema value is not read, migrated, erased, or reset automatically
- no older schema exists before V1 schema 1, so there is currently no legacy migration path

Future known migrations must be explicit. Unknown newer schemas must remain untouched.

## Snapshot model

The storage component persists one bounded binary `snapshot` blob inside the encrypted NVS namespace. It contains:

- account ids and manual order
- issuer/account/display-name metadata
- TOTP secret material
- last-used account id
- Wi-Fi SSID/password

Maximum account count is 32. Field and snapshot sizes are bounded before persistence.

A complete account import is staged in RAM and committed by replacing the single snapshot blob only after `import.validate`. A failed validation or failed commit leaves the previously committed snapshot as the canonical state.

Metadata APIs intentionally return only id/order/issuer/account/display name. There is no generic stored-secret read/export API. Firmware consumers that need a TOTP secret or Wi-Fi password use callback-style `with_*` methods so decrypted secret material has a narrow lifetime and is wiped after the consumer returns.

## Development Security Backend

Development builds use `DevSecurityBackend` only until Task #26 replaces it for production.

- It does **not** read or burn eFuse.
- Its XTS key material is deliberately public and synthetic.
- `production_release_allowed()` is always false.
- `hello` reports `security_profile: development` so Web/device status makes the profile explicit.
- Production HMAC/eFuse-backed keying remains exclusively owned by Task #26.

The development backend calls `nvs_flash_secure_init_partition()` with explicit synthetic XTS configuration. It never falls back to plaintext NVS initialization.

### Encryption self-check

After a recognized schema is established, the development backend writes a public synthetic probe value through encrypted `auth_nvs`, reads the raw partition bytes, and fails with `security_invariant` if that exact probe is visible in plaintext. The probe is then erased from its namespace.

NVS encryption is configured for the entire `auth_nvs` partition, so this write-through/raw-read check exercises the same encryption boundary used by the snapshot containing TOTP and Wi-Fi credential data. It deliberately avoids scanning, printing, dumping, or comparing credential values themselves.

This verifies the encrypted NVS path without exposing credential-bearing data. The check is deliberately skipped before schema validation so unknown newer schemas are not modified.

## Wi-Fi persistence boundary

The canonical Wi-Fi credential copy is stored only in `auth_nvs`. Runtime time synchronization explicitly configures ESP-IDF with `WIFI_STORAGE_RAM` before applying the transient station configuration, so ESP-IDF's default flash-backed Wi-Fi persistence does not become a second authoritative credential store.

No serial response returns the Wi-Fi password.

## Memory and logging

Credential-bearing request fields, serial input buffers, temporary encoded snapshots, imported secrets, Wi-Fi passwords, and loaded internal state are explicitly wiped when their lifetime ends. Account draft/storage secret types also wipe source or destination values around relocation/destruction so vector movement and short-string storage do not intentionally leave stale secret copies behind. Errors return only bounded status codes and never echo the source payload.

No storage path logs TOTP secrets, passwords, encryption keys, decrypted snapshots, or credential-bearing flash/NVS data.

## Factory Reset boundary

`Store::factory_reset()` erases only the `auth_nvs` user-state partition and recreates schema 1 through the active security backend. It does not touch eFuse or device identity/security state.

V1 exposes this only through the explicit Web/USB confirmation flow. A normal firmware update is a separate path and must not erase `auth_nvs`.
