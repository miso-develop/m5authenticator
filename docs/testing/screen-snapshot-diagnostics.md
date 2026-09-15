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

## 3. Understand serial ownership and control-line behavior before collecting evidence

The diagnostic uses the same USB Serial/JTAG transport as Protocol v2. Only one process can normally own the COM/serial port at a time.

The helper constructs the pySerial object while it is still closed, explicitly configures:

```text
DTR = inactive / False
RTS = inactive / False
```

and only then calls `open()`. It does not intentionally toggle either line after open or during close. `rtscts=False` / `dsrdtr=False` are also configured, but those flow-control settings are not treated as a substitute for the explicit pre-open DTR/RTS states.

pySerial applies the configured RTS/DTR state when the port is opened. However, pySerial also documents that some operating systems and USB/serial drivers may momentarily activate or glitch RTS/DTR as the port is opened. Software configuration alone therefore cannot prove that every Windows/driver/device combination is electrically glitch-free. **The Windows + M5StickS3 Human Gate in this document is mandatory before using this helper as auxiliary evidence.**

Before the helper can open the port, close any `idf.py monitor` session and release any Web Serial or other serial-terminal ownership. However, **disconnecting Chrome/Web Serial can itself cancel the active Protocol v2 transport session and its physical-presence attempt**. That means releasing the port is not observationally neutral during an active unlock flow.

Consequently this diagnostic is appropriate for auxiliary checks such as:

- steady-state screen mode;
- LOCKED display before a Web connection, or after the system has intentionally returned to a steady state;
- account-view / OTP-revealed coarse modes when the serial port can safely be released.

It may **not** be suitable for simultaneously observing an active `UNLOCK REQUEST` while the Web app still owns the serial transport. Do not disconnect Web Serial solely to capture an unlock-request snapshot and then treat the resulting state as evidence of what existed before the disconnect.

If helper startup visibly causes any of the following, **do not use that run's snapshot as evidence**:

- Device reboot;
- `Starting...` appearing unexpectedly;
- download/bootloader mode;
- unexpected runtime or screen-state transition;
- any other indication that opening the observation transport perturbed the state being observed.

If such behavior reproduces even with pre-open DTR/RTS inactive, stop the #119 Human Gate and escalate the observation design. Do not mark the helper PASS by adding delays/retries or by hiding the transition.

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

The `--timeout` value must be finite and greater than zero. `0`, negative values, `nan`, `inf`, and `-inf` are rejected before opening the serial port.

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

### Completed malformed current-ID frames

Serial input is framed by newline. A per-read timeout may return only part of a line, so the helper buffers fragments until `\n` is actually received. An unterminated fragment is therefore **not** classified as malformed JSON merely because one read ended.

If a newline-terminated frame clearly contains the current fresh request ID but cannot be parsed, the helper fails immediately. It does **not** skip that current frame, wait for a later valid frame, or retry automatically. A later successful manual invocation must not overwrite the failed run when evaluating a Human Gate.

For investigation, the failure text contains structural facts only. It may report:

- `frame_len`: total completed frame length;
- `utf8`: valid / invalid;
- `first_object`: whether the first non-whitespace byte looks like `{`;
- `last_object`: whether the last non-whitespace byte looks like `}`;
- `nul`: NUL-byte presence;
- `control`: non-whitespace control-byte presence;
- `json_error`: decoder-position bucket (`near-start`, `middle`, `near-end`, or `unknown`);
- `id_position`: current-ID-token position bucket;
- `object_starts` / `object_ends`: zero/one/multiple top-level JSON-object-looking boundaries;
- `shape`: structural classification such as `prefix-contamination`, `suffix-contamination`, `middle-interleave-corruption`, `concatenated-objects`, `truncated-looking`, `invalid-utf8`, or `unknown`.

These diagnostics never print the raw serial payload, decoded frame text, byte values, credential labels, OTP digits, secrets, or other Device data. Record only this sanitized structural result when reporting a malformed current response.

### Device TX framing and residual transport risk

The Device writes every Protocol-v2 response through the common `write_response()` path. The response body and terminating newline are assembled into one frame and sent with one logical stdio write while the `stdout` FILE lock remains held through `fflush()` and USB Serial/JTAG `fsync()`. This prevents normal concurrent `stdout` writers from entering between the JSON body and its newline. The same common TX hardening is present in default-OFF production firmware; it does **not** enable the screen-snapshot operation when `M5AUTH_TEST_SCREEN_SNAPSHOT` is OFF and does not change the Protocol-v2 JSON format.

ESP-IDF logging uses the console standard stream, and USB Serial/JTAG is the configured primary console for this firmware. The USB Serial/JTAG VFS also serializes individual writes to the shared physical port. Direct/early/ROM writers that bypass the ordinary stdio locking model are not proven to be covered by the application FILE lock.

ESP-IDF's simplified USB Serial/JTAG VFS can also abandon bytes if the host is not draining the TX FIFO within its bounded transmit window. `fflush()` / `fsync()` help drain buffered output but cannot reconstruct bytes already lost below stdio. Therefore a `truncated-looking` or other corruption classification remains a transport finding requiring investigation; it must not be repaired on the host by skipping the malformed current frame or automatically retrying.

## 5. #119 Windows + M5StickS3 Human Gate

CI cannot prove that the actual Windows USB/serial driver and M5StickS3 hardware exhibit no open-time control-line glitch or intermittent transport corruption. Perform this gate only when Integration has explicitly authorized a new attempt after reviewing the exact helper/firmware head.

Use only sanitized/non-secret observations. Do not record Device ID, credential labels, TOTP digits/secrets, Recovery Package/Passphrase, VMK/KEK/BUK/BRK/session material, Wi-Fi credentials, or Vault material.

Minimum gate:

1. Put the diagnostics-ON M5StickS3 into a steady-state **LOCKED** screen.
2. Ensure Chrome/Web Serial, `idf.py monitor`, and other serial terminals do not own the COM port.
3. Run the helper at least **5 consecutive times without power cycling**.
4. On every run verify:
   - `Starting...` does not appear;
   - the Device does not reboot;
   - download/bootloader mode does not appear;
   - the screen/runtime state does not change unexpectedly;
   - the sanitized snapshot matches the physical LCD coarse state;
   - no unsolicited serial output appears.
5. If practical, repeat the same observation pattern in additional steady states such as `account_view` and `otp_revealed`, without recording credential labels or OTP digits.

Any visible reset/glitch/state transition **or malformed current-ID completed frame** is **FAIL**, even if a later invocation succeeds. Stop that gate attempt, record only the sanitized failure class/structural diagnostics, and return to Integration. Do not continue until a later success overwrites the failure.

## 6. #75 release acceptance remains default-OFF only

Diagnostics-ON testing is auxiliary/preflight evidence only. **Never record a diagnostics-ON firmware run as the #75 release PASS.**

After diagnostics-assisted checks are finished, #75 security/release acceptance must be performed again according to the #75 Human E2E procedure using the exact default-OFF production firmware delivered from GitHub Pages/main. Verify the exact production build identity required by #75 before recording PASS.

Switching back to production firmware does not require Factory Reset, re-Provisioning, site-data clearing, `erase-flash`, or eFuse operations unless a separate approved Issue explicitly requires one of those actions. eFuse operations remain prohibited for this workflow.
