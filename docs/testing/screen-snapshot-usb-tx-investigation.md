# Screen Snapshot: exact-64 USB Serial/JTAG TX investigation

This note records the source-level investigation behind PR #120 / Issue #119 after the first-open physical failure on exact head `5fda73d11f59e67e0ecf559603ae874de926100b`.

The Human Gate remains FAIL / STOP. This document does not authorize another physical run.

## Latest physical evidence

The authorized first-open run was performed only once after a fresh diagnostics-ON build, flash, reboot, and steady LOCKED state. The helper had never opened the COM port since that reboot. The physical screen did not change.

Sanitized evidence established:

- `prefix_len=64`;
- `prefix_equals_request_prefix=no`;
- `prefix_equals_request_first64=no`;
- `request_prefix_match_len=none`;
- `suffix_json_valid=yes`;
- `suffix_id_matches_current=yes`;
- `suffix_allowlist_valid=yes`;
- `pre_request_data=no` after 250 ms continuous quiet;
- first post-request byte observed within 50 ms.

For this run, the current diagnostic request echo / current-request-first-64 hypothesis is therefore excluded. The completed line is structurally consistent with:

```text
<unrelated 64 bytes><otherwise-valid current response>\n
```

The exact content of the 64-byte prefix was not exposed and must not be exposed in later diagnostics.

## ESP-IDF v5.5.5 exact-64 transaction mechanics

Primary sources:

- `components/hal/esp32s3/include/hal/usb_serial_jtag_ll.h`
  - https://github.com/espressif/esp-idf/blob/v5.5.5/components/hal/esp32s3/include/hal/usb_serial_jtag_ll.h
- `components/esp_driver_usb_serial_jtag/src/usb_serial_jtag_vfs.c`
  - https://github.com/espressif/esp-idf/blob/v5.5.5/components/esp_driver_usb_serial_jtag/src/usb_serial_jtag_vfs.c
- `components/esp_driver_usb_serial_jtag/src/usb_serial_jtag.c`
  - https://github.com/espressif/esp-idf/blob/v5.5.5/components/esp_driver_usb_serial_jtag/src/usb_serial_jtag.c
- `components/esp_driver_usb_serial_jtag/src/usb_serial_jtag_connection_monitor.c`
  - https://github.com/espressif/esp-idf/blob/v5.5.5/components/esp_driver_usb_serial_jtag/src/usb_serial_jtag_connection_monitor.c

### Endpoint completion

The ESP32-S3 low-level header explicitly documents the 64-byte case in `usb_serial_jtag_ll_txfifo_flush()`:

- a full 64-byte FIFO is automatically flushed by hardware;
- an immediate software flush can therefore become a no-op;
- a full 64-byte USB packet is interpreted as an incomplete USB transaction by the CDC-ACM receiving side;
- more data or a zero-length packet is required to terminate that transaction;
- to send the ZLP, software must flush again after `usb_serial_jtag_ll_txfifo_writable()` becomes true.

This is a packet-size-specific mechanism and directly explains why 63-byte and 65-byte cases do not have the same termination edge.

### `fflush(stdout)` versus `fsync(STDOUT_FILENO)`

For this console:

- `fflush(stdout)` drains libc buffering into the USB Serial/JTAG VFS;
- it does not by itself guarantee that an exact-full endpoint transaction has received its terminating short/ZLP transfer;
- the simplified VFS `fsync` path flushes the FIFO, waits for host pickup/FIFO writability, and then flushes again to cover the exact-64 case.

The second flush is the important transaction-finalization step.

### Bounded no-driver behavior

The simplified/no-driver VFS uses a bounded progress interval of about 50 ms for TX. If the CDC side does not consume data, low-level writes can stop making progress and bytes can be abandoned while the upper VFS write path can still report the requested write length. `fsync` can return an error when TX completion cannot be established within its bounded wait.

Consequently, calling startup `fsync` while no user-space COM listener is known to be active is not a proof that startup TX was finalized.

### USB bus connection is not COM-reader ownership

The USB Serial/JTAG connection monitor derives connected state from USB SOF/bus activity. It does not prove that the Windows COM device is open by a user-space process which is actively consuming the CDC stream.

This distinction explains why Device-side startup can consider USB connected while the diagnostics helper has not yet opened the COM port.

## Startup output producer inventory

The project uses `CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y`, so console and Protocol-v2 share the same physical transport.

Potential pre-request writers are:

1. **ROM boot output** — outside application stdio ownership. The project does not disable Boot ROM logging because ESP-IDF's `BOOT_ROM_LOG_ALWAYS_OFF` option is a permanent eFuse-backed change and is forbidden for this project/task.
2. **Second-stage bootloader logs** — ESP-IDF bootloader logging uses ROM print output; default bootloader verbosity is INFO unless explicitly changed.
3. **ESP-IDF application startup logs** — default application verbosity is INFO unless explicitly changed.
4. **Constrained/early ESP-IDF logs** — may use `esp_rom_vprintf`, bypassing the application `stdout` FILE lock.
5. **M5Unified logging** — M5Unified 0.2.21 serial logging ultimately uses `printf`; its normal level follows `CONFIG_LOG_DEFAULT_LEVEL`. Project first-party source currently has no identified `M5.Log` producer matching this failure.
6. **Application stdout/stderr** — ordinary stdio writers share the console VFS, but the common Protocol-v2 response writer now holds the stdout FILE lock across body/newline/flush/fsync.
7. **Panic/reset/runtime diagnostics and direct low-level writers** — can bypass ordinary application response serialization.
8. **Libraries / initialization code** — may emit through ESP-IDF or ROM logging before the protocol loop begins.

Project-source review did not find a first-party `ESP_LOG*` call or an application request-echo path that explains the observed 64 bytes. Display initialization writes `Starting...` to the LCD, not to stdout.

Therefore the exact producer remains unproven. The evidence is stronger for a text-capable startup/console class than for arbitrary binary corruption because the observed prefix was UTF-8 valid and contained no control byte, but that is not enough to identify a specific message.

## Safe fingerprinting decision

The helper may continue to report structural metadata such as length, UTF-8 validity, control/newline presence, and fixed booleans about the current request/response relationship.

It must not print or persist:

- raw prefix bytes;
- decoded prefix text;
- hex dumps;
- hashes of arbitrary frame content;
- any payload that could include credential labels, OTP data, Vault material, or other secrets.

A boolean such as `matches_known_boot_log=yes|no` is acceptable only if the compared candidate is proved to be a completely fixed compile-time, non-secret string. No such exact 64-byte producer has been proved yet, so no producer-specific fingerprint is added in this change.

## Fix alternatives

### A. Unconditional application-startup `fflush` / `fsync`

Rejected as the root fix.

At startup, USB SOF can be present while no user-space CDC listener is open. The v5.5.5 no-driver `fsync` path can therefore time out/fail rather than proving that an exact-full packet has been consumed and terminated. Adding only a startup wait would also be a timing workaround rather than a transport invariant.

### B. Suppress startup console output

Not selected in PR #120.

Reducing boot/application logs lowers producer probability, but it does not eliminate ROM output and it reduces debugging/supportability. Permanently disabling Boot ROM output would require an eFuse-backed configuration and is prohibited. Production logging remains unchanged by this fix.

### C. Driver-backed USB Serial/JTAG

Not selected as the minimal #119 fix.

Driver mode adds TX/RX ring buffers and ISR handling, but it is installed only after application startup. The ESP-IDF driver source explicitly accounts for ROM print routines placing bytes in the TX FIFO outside driver-owned output. It therefore cannot by itself eliminate pre-driver ROM/boot output, and it adds RAM/ISR complexity. This remains part of Issue #121's architectural follow-up.

### D. Listener-time transaction finalization plus test-only delimiter

Selected for the test-only screen-snapshot operation after the alternatives above fail to provide a reliable first-open boundary.

Receipt of a valid diagnostics request proves that a user-space serial listener is now active. Immediately before the diagnostics response, diagnostics-ON firmware:

1. `fflush(stdout)`;
2. `fsync(STDOUT_FILENO)` to finish a previously pending exact-full USB transaction while a listener is known to exist;
3. emits one newline delimiter;
4. `fflush` + `fsync` that delimiter;
5. only then emits the unchanged current JSON response through the existing response writer.

If any boundary-finalization step fails, the current JSON response is not emitted. The helper therefore times out/fails rather than accepting ambiguous evidence.

This turns the modeled failure from:

```text
<stale64><current-response>\n
```

into two framing units:

```text
<stale64>\n
<current-response>\n
```

The host helper already ignores an unrelated stale completed line but fails immediately if a malformed completed line clearly carries the current fresh request ID. No prefix is stripped, no JSON is parsed from the first `{`, and no current response is retried or skipped.

The delimiter path is compiled only when `M5AUTH_TEST_SCREEN_SNAPSHOT=1`; the production/default-OFF Protocol-v2 wire format does not receive this delimiter.

## Production impact

The physical cause class is shared-transport behavior, so the architectural concern is not inherently diagnostics-only. Production Web Serial already has bounded special handling for the initial read-only `hello`: it can skip bounded startup text and retry that initial hello. Normal post-handshake exchanges remain strict and fail closed.

PR #120 does not relax the production parser and does not add the diagnostics delimiter to production traffic. Long-term Protocol-v2 / console separation and steady-state transport integrity remain tracked by Issue #121.

## Test model

`tests/screen_snapshot_usb_tx_boundary_test.py` models:

- 64-byte stale TX followed by a valid response;
- 63-byte stale TX;
- 65-byte stale TX;
- exact-64 plus transaction finalization/ZLP;
- finalization after listener-open followed by host purge;
- listener-time delimiter separation;
- clean response body unchanged;
- diagnostics-only source boundary and fail-closed ordering;
- default-OFF production boundary;
- no eFuse-backed ROM-log suppression.

The model is not a replacement for the physical Human Gate. A future physical run requires a new explicit Integration authorization after zero-based review of the exact head.
