# Production HMAC eFuse Security

This document is the runbook for Task #26: promoting one M5StickS3 from the synthetic development storage backend to device-specific HMAC eFuse-backed NVS encryption.

## Safety boundary

Production Security Initialization is intentionally irreversible.

The normal production-backend boot path may inspect eFuse state and derive NVS encryption keys, but it must not program eFuse. The only firmware path permitted to program eFuse is the explicit production-security initialization path, and that path requires all of the following in one session:

1. runtime hardware identity verified by M5Unified as `board_M5StickS3`,
2. a successful non-destructive preflight,
3. the exact Web confirmation text `INITIALIZE PRODUCTION SECURITY`, and
4. a physical long-hold confirmation on the StickS3 within the on-device confirmation window.

Runtime hardware identity is checked immediately after M5Unified initialization and **before the storage backend is constructed**. If the connected hardware is not detected as M5StickS3, firmware halts fail-closed and cannot enter storage or production-security initialization. Do not treat successful ESP32-S3 flashing, `esptool chip_id`, a COM-port identity, or a redacted eFuse inspection result as proof of the physical M5Stack product model; multiple M5Stack devices use ESP32-S3 and can have indistinguishable unused eFuse slots.

The redacted eFuse inspection helper classifies eFuse state only. It does not identify the M5Stack board model.

If any eFuse operation reports an error, do not guess, change slots, or retry the burn. Power-cycle only after recording the non-secret status, inspect eFuse again, and treat the device as fail-closed until the state is understood.

Never use a real TOTP secret or a real Wi-Fi password during this validation. Use only clearly synthetic values.

## Current fixed configuration

The V1 production backend is configured by:

- `CONFIG_M5AUTH_SECURITY_BACKEND_PRODUCTION=y`
- `CONFIG_M5AUTH_HMAC_KEY_ID=0` by default
- `firmware/release-profile.json` with `security_backend: "hmac-efuse"`

The firmware never automatically switches to another eFuse key slot. If inspection shows that the configured slot is unsuitable, stop and change the configured key ID deliberately before any initialization attempt.

If a suitable existing, fully protected `HMAC_UP` key is already present in the deliberately selected slot, the normal boot path reuses it and does not burn another key. Such a reusable-key boot is **not** eligible for the destructive Production Security Initialization flow. If storage fails with a reusable key, the firmware preserves that failure and must not erase `auth_nvs` as a repair action.

## Local machine settings

For Windows physical validation, copy the repository template once and keep machine-specific settings in the ignored root `.env` file:

```text
copy .env.example .env
notepad .env
call scripts\load-env.cmd
```

The tracked `.env.example` defines keys only; all values must remain empty there. Set the required tool version, target, and COM port only in the local ignored `.env`. Do not place authentication material in `.env`; it is only for non-secret local tooling configuration.

## Phase 1: non-destructive device inspection

Before crossing the irreversible boundary, physically verify that the connected unit is the intended M5StickS3, build and flash the production-backend firmware, confirm that the firmware reaches the on-device `PRODUCTION SETUP` screen, then inspect eFuse state. A non-M5StickS3 must halt before storage initialization and cannot reach Production Setup. Building, flashing normal firmware partitions, booting into Production Setup, `hello`, `security.status`, `security.prepare`, and `security.cancel` must not burn eFuse.

On Windows with Espressif EIM, from the repository root:

```text
call scripts\load-env.cmd
cd firmware
eim run "idf.py set-target %M5AUTH_CHIP%" %M5AUTH_IDF_VERSION%
eim run "idf.py build" %M5AUTH_IDF_VERSION%
eim run "idf.py -p %M5AUTH_PORT% flash" %M5AUTH_IDF_VERSION%
cd ..
eim run "python scripts\inspect_production_efuse.py" %M5AUTH_IDF_VERSION%
```

`inspect_production_efuse.py` uses `M5AUTH_PORT` when `--port` is omitted. An explicit `--port` still overrides the environment value.

The helper internally uses only `espefuse summary --format json` against `KEY_PURPOSE_0..5` and `BLOCK_KEY0..5`. It never invokes a burn command, never saves an eFuse dump, and never prints raw key-block values. Its output is safe to paste into the Task/PR because it contains only slot classification, purpose, and protection flags.

Do **not** paste a full raw `espefuse summary` into a public Issue/PR/chat. A readable populated key block can appear in that output. If direct local inspection is required for troubleshooting, keep it on the local machine and redact all block values before sharing anything.

For the configured key slot, the helper accepts one of these two structural states:

- **Free**: the key block is all-zero, readable/writeable, purpose is `USER`, and the key-purpose field remains writeable. Only this state may become a first-time initialization candidate.
- **Reusable**: the key purpose is `HMAC_UP`, the key is read-protected, the key block is write-protected, and the key-purpose field is write-protected. The normal boot path must consume this key without a new burn.

If the configured slot is free but another key slot already has `HMAC_UP`, the helper returns a blocked review state. Verify ownership before any new burn; do not create another HMAC key merely because the configured slot is free.

Stop before initialization if the selected key block is populated for another purpose, only partially protected, has an unexpected protection state, or the inspection is otherwise ambiguous.

A `verdict=first-time-init-candidate` result is an eFuse-state result only. It is not authorization to burn eFuse and is not evidence that the board itself is M5StickS3.

## Phase 2: Web preflight

Connect the Production Setup firmware to the local Web Provisioner. The Production Security panel must show:

- configured HMAC slot,
- selected key state,
- read protection,
- key write protection,
- key-purpose write protection,
- unused key-block count,
- whether a burn has already been attempted this boot, and
- preflight eligibility.

Run **Run non-destructive preflight**. This only prepares the current protocol session; it does not write eFuse.

Before proceeding, verify that:

- the firmware reached the M5StickS3 `PRODUCTION SETUP` path after runtime board identification,
- `preflight_ok` is true,
- `burn_attempted` is false,
- the selected key state is `free` and matches the separately inspected eFuse summary,
- the redacted helper reports `verdict=first-time-init-candidate`, and
- the selected key ID is the one intentionally chosen for this device.

If the selected key is already reusable, normal boot should initialize storage without this preflight. A reusable key combined with an unsupported schema, corrupt storage, or other storage failure is a blocked investigation state, not an initialization state.

`Cancel preparation`, disconnecting, or reconnecting is always safe before the physical confirmation step and requires a fresh preflight.

## Phase 3: irreversible initialization

Only after Phases 1 and 2 are complete for a runtime-identified M5StickS3 and a deliberately selected **free** key slot:

1. Type the exact Web confirmation text `INITIALIZE PRODUCTION SECURITY`.
2. Confirm the Web irreversible-operation dialog.
3. Read the StickS3 display. It must explicitly show the irreversible eFuse warning.
4. Long-hold the physical StickS3 button only if the displayed operation is expected.

Firmware temporarily enables the ESP-IDF internal SAR ADC entropy source, generates a device-specific random 256-bit key, and immediately disables the entropy source before normal Wi-Fi/ADC use. It then stages the key, `HMAC_UP` purpose, automatic read protection, key write protection, and key-purpose write protection. The eFuse changes are committed through ESP-IDF batch mode. The plaintext generated key is zeroized from RAM after the call and is never exported.

After eFuse security is established, the old development `auth_nvs` partition is erased and reinitialized using HMAC-derived NVS XTS keys. This erase is allowed only from the first-time `production_init_required` state; it is not a recovery mechanism for later storage failures.

## Phase 4: post-initialization validation

Use only synthetic credentials for this validation.

Confirm all of the following before release promotion:

1. Reconnect after normal boot. Storage reports ready and the security profile is `production-hmac-efuse`.
2. Re-run the redacted helper through the pinned EIM environment. The selected key must now report `reusable` with `HMAC_UP`, read protection, key-write protection, and purpose-write protection.
3. Provision a synthetic TOTP account and synthetic Wi-Fi credentials.
4. Reboot and confirm the synthetic account remains usable.
5. Rename/reorder/delete or otherwise update synthetic account metadata and confirm persistence.
6. Factory Reset from the Web Provisioner.
7. Run the redacted eFuse inspection again and confirm the same device-specific HMAC key slot and protections remain intact.
8. Re-provision synthetic data after Factory Reset and confirm normal operation.

To verify plaintext-at-rest behavior, use only synthetic markers. A local raw read of `auth_nvs` may be inspected for those exact synthetic markers, but the dump must remain local, must never be committed or uploaded, and must be deleted immediately after the check. Never perform this check after real credentials have been provisioned.

## Release promotion gate

Until the complete physical validation above succeeds, keep both values in `firmware/release-profile.json` false:

```json
{
  "production_security_validated": false,
  "production_release_allowed": false
}
```

Only after the physical evidence is complete may both values be promoted to true. `scripts/validate_release.py --require-production` must continue to fail until then. Development synthetic-backend builds are never production eligible.

## Failure handling

After any failure at or beyond the physical confirmation boundary:

- do not issue another burn attempt in the same boot,
- do not select another key slot by trial and error,
- do not erase eFuse,
- do not weaken release validation,
- do not provision real credentials,
- inspect the non-secret eFuse/protocol status first.

A partially programmed or unexpectedly protected key slot is an investigation state, not a retry state.
