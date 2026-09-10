# Secure Account Storage

V1 keeps user/security state in the dedicated `auth_nvs` partition. This partition is separate from both OTA application slots so normal firmware updates preserve provisioned state.

## Partition layout

The current 8 MiB M5StickS3 layout is defined by `firmware/partitions.csv`:

| Partition | Purpose |
| --- | --- |
| `nvs` | ESP-IDF/system NVS boundary; not the canonical store for authenticator credentials |
| `otadata` | dual-OTA selection metadata |
| `phy_init` | PHY initialization data |
| `auth_nvs` | canonical encrypted authenticator/Wi-Fi user state |
| `ota_0` / `ota_1` | dual firmware OTA slots |

`auth_nvs` starts at `0x12000` and is `0x1e000` bytes. App partitions start at `0x30000`, so user state does not overlap either OTA slot.

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

Metadata APIs intentionally return only id/order/issuer/account/display name. There is no generic stored-secret read/export API. Firmware consumers that later need a TOTP secret or Wi-Fi password use callback-style `with_*` methods so decrypted secret material has a narrow lifetime and is wiped after the consumer returns.

## Development Security Backend

Task #9 uses `DevSecurityBackend` only.

- It does **not** read or burn eFuse.
- Its XTS key material is deliberately public and synthetic.
- `production_release_allowed()` is always false.
- `hello` reports `security_profile: development` so later Web/device status can make the profile explicit.
- Production HMAC/eFuse-backed keying is not implemented here and remains exclusively owned by Task #26.

The development backend calls `nvs_flash_secure_init_partition()` with explicit synthetic XTS configuration. It never falls back to plaintext NVS initialization.

### Encryption self-check

After a recognized schema is established, the development backend writes a public synthetic probe value through encrypted `auth_nvs`, reads the raw partition bytes, and fails with `security_invariant` if that exact probe is visible in plaintext. The probe is then erased from its namespace.

This verifies the encrypted NVS path without scanning for, printing, dumping, or comparing real credential values. The check is deliberately skipped before schema validation so unknown newer schemas are not modified.

## Wi-Fi persistence boundary

The canonical Wi-Fi credential copy is stored only in `auth_nvs`. Task #10 must configure the ESP-IDF Wi-Fi driver to use RAM storage for runtime connection configuration rather than making the default ESP-IDF NVS copy authoritative.

No serial response returns the Wi-Fi password.

## Memory and logging

Credential-bearing request fields, serial input buffers, temporary encoded snapshots, imported secrets, Wi-Fi passwords, and loaded internal state are explicitly wiped when their lifetime ends. Errors return only bounded status codes and never echo the source payload.

No storage path logs TOTP secrets, passwords, encryption keys, decrypted snapshots, or credential-bearing flash/NVS data.

## Factory Reset boundary

`Store::factory_reset()` erases only the `auth_nvs` user-state partition and recreates schema 1 through the active security backend. It does not touch eFuse or device identity/security state.

Task #9 does not expose Factory Reset as an unauthenticated/accidental device-side UI operation. The explicit destructive Web/USB confirmation flow remains owned by Task #13.
