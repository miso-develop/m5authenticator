# Test-only sanitized screen snapshot diagnostics

This procedure is for Issue #117 auxiliary Device diagnostics during #75 investigation. It is **not** a production/release acceptance procedure.

## Security boundary

`M5AUTH_TEST_SCREEN_SNAPSHOT` is default OFF. A diagnostics-ON build is a different test firmware from the default-OFF production firmware used for release acceptance.

The diagnostic returns only coarse allowlisted state:

- runtime state
- trusted-time readiness
- presence active / confirmed / operation
- coarse `screen_mode`

It never returns framebuffer pixels, rendered text, OTP digits, credential labels/metadata, Device ID, attempt ID, TOTP secret, Passphrase, Recovery Package, VMK/KEK/BUK/BRK/session keys, Wi-Fi credentials, Vault/ciphertext, generation, UI selection, or reveal deadline.

Do **not** perform Factory Reset, re-Provisioning, site-data/IndexedDB clearing, `erase-flash`, or any eFuse read/write/burn/provisioning merely to use this diagnostic.

## 1. Use a dedicated diagnostics build directory

Activate the exact ESP-IDF environment required by the repository first. For #117 verification this is ESP-IDF v5.5.5.

From the repository `firmware` directory, use a build directory that is **not** the normal `build` directory:

```bat
idf.py --version
idf.py -B build-screen-snapshot set-target esp32s3
idf.py -B build-screen-snapshot -DM5AUTH_TEST_SCREEN_SNAPSHOT=ON build
findstr /C:"M5AUTH_TEST_SCREEN_SNAPSHOT:BOOL=ON" build-screen-snapshot\CMakeCache.txt
```

Expected version:

```text
ESP-IDF v5.5.5
```

Expected cache guard:

```text
M5AUTH_TEST_SCREEN_SNAPSHOT:BOOL=ON
```

Do not reuse `firmware\build` for this test profile. If a clean diagnostics rebuild is required, delete or `fullclean` **only** `build-screen-snapshot`.

## 2. Flash only the diagnostics build

Identify the M5StickS3 serial port, then flash using the same dedicated build directory. Example for `COM8`:

```bat
idf.py -B build-screen-snapshot -p COM8 flash
```

Do not run `erase-flash`. This diagnostic does not require Factory Reset, re-Provisioning, browser site-data clearing, or eFuse operations.

## 3. Understand serial ownership before collecting evidence

The diagnostic uses the same USB Serial/JTAG transport as Protocol v2. Only one process can normally own the COM/serial port at a time.

Before the helper can open the port, close any `idf.py monitor` session and release any Web Serial or other serial-terminal ownership. However, **disconnecting Chrome/Web Serial can itself cancel the active Protocol v2 transport session and its physical-presence attempt**. That means releasing the port is not observationally neutral during an active unlock flow.

Consequently this diagnostic is appropriate for auxiliary checks such as:

- steady-state screen mode;
- LOCKED display before a Web connection, or after the system has intentionally returned to a steady state;
- account-view / OTP-revealed coarse modes when the serial port can safely be released.

It may **not** be suitable for simultaneously observing an active `UNLOCK REQUEST` while the Web app still owns the serial transport. Do not disconnect Web Serial solely to capture an unlock-request snapshot and then treat the resulting state as evidence of what existed before the disconnect.

No Factory Reset, re-Provisioning, site-data/IndexedDB clearing, `erase-flash`, or eFuse operation is needed to transfer port ownership.

## 4. Read one fresh sanitized snapshot

From the repository root, use the read-only helper. Run it from the activated ESP-IDF Python environment so `pyserial` is available.

```bat
python tools\diagnostics\screen_snapshot.py --port COM8
```

For every invocation the helper generates a fresh positive request ID in the Device parser's safe integer range and sends exactly one request with that ID, conceptually:

```json
{"v":2,"id":182736451,"op":"diagnostics.screen_snapshot","params":{}}
```

The numeric ID above is only an example; it is **not fixed**. The Device echoes the current request ID in its response. The helper accepts a success only when `response.id` exactly matches the fresh ID generated for that invocation.

Delayed/stale responses from previous helper runs therefore cannot become current test evidence. The helper may purge the input buffer as defense-in-depth, but freshness does **not** depend on purge behavior: wrong-ID lines are ignored, malformed stale lines are ignored, and the helper keeps reading only until its bounded timeout for the current ID.

A successful response is one validated JSON line such as:

```json
{"v":2,"id":182736451,"ok":true,"data":{"runtime_state":"locked","trusted_time_readiness":"not_synced","presence":{"active":false,"confirmed":false,"operation":"none"},"screen_mode":"open_web"}}
```

The snapshot represents the **last sanitized state committed by a completed LCD render transaction**. Protocol-side presence/time changes that have not yet been rendered are intentionally not reported early.

Before the first render has completed, including a UI task that has not started or failed to start, the Device must fail closed rather than return the default cache. The expected error shape is:

```json
{"v":2,"id":182736451,"ok":false,"error":{"code":"snapshot_not_ready"}}
```

`snapshot_not_ready` is a **FAIL / re-check condition**, not evidence for `unprovisioned`, `not_synced`, `open_web`, or any other default-looking screen state. Do not record it as a successful snapshot.

Repeated diagnostic requests are read-only and do not start/cancel sessions or presence attempts and do not modify Vault, trusted time, UI selection, reveal deadline, or persistent generation. Port ownership changes outside the diagnostic request itself can still affect the existing Protocol v2 transport/session as described above.

## 5. #75 release acceptance remains default-OFF only

Diagnostics-ON testing is auxiliary/preflight evidence only. **Never record a diagnostics-ON firmware run as the #75 release PASS.**

After diagnostics-assisted checks are finished, #75 security/release acceptance must be performed again according to the #75 Human E2E procedure using the exact default-OFF production firmware delivered from GitHub Pages/main. Verify the exact production build identity required by #75 before recording PASS.

Switching back to production firmware does not require Factory Reset, re-Provisioning, site-data clearing, `erase-flash`, or eFuse operations unless a separate approved Issue explicitly requires one of those actions. eFuse operations remain prohibited for this workflow.
