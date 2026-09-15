# Screen Snapshot: exact-64 USB Serial/JTAG TX investigation

This note records the source-level investigation behind PR #120 / Issue #119. It is diagnostic engineering documentation only and does **not** authorize a Human Gate.

## Governing physical evidence

### `5fda73d...`: unrelated exact-64 prefix

The first-open Human Gate on exact head `5fda73d11f59e67e0ecf559603ae874de926100b` established:

```text
prefix_len=64
prefix_equals_request_prefix=no
prefix_equals_request_first64=no
request_prefix_match_len=none
suffix_json_valid=yes
suffix_id_matches_current=yes
suffix_allowlist_valid=yes
pre_request_data=no
quiet_ms=250
```

For that observation, current-request echo/current-request-first64 is excluded. The completed line was structurally:

```text
<unrelated 64 bytes><otherwise-valid current response>\n
```

The exact producer of those 64 bytes remains unproven and raw payload inspection remains prohibited.

### `71f766...`: listener-time boundary timed out

Integration then authorized one first-open Human Gate on exact head `71f7667673302c076a1aceb01cd3587c0999b0cd` after a fresh diagnostics-ON rebuild, flash, reboot, and steady LOCKED state. The helper had not opened the COM port since reboot.

LCD: no visible change.

```text
SCREEN_SNAPSHOT_SYNC=pre_purge_waiting=no,pre_request_data=no,pre_request_bytes=0,pre_request_newline=no,first_byte=none,quiet_ms=266,invocation=first
SCREEN_SNAPSHOT=FAIL: no valid response for the current request id before timeout
```

The gate stopped immediately. No second invocation or repeated-open test was performed.

## ESP-IDF v5.5.5 source findings

Primary sources:

- `components/esp_driver_usb_serial_jtag/src/usb_serial_jtag_vfs.c`
- `components/hal/esp32s3/include/hal/usb_serial_jtag_ll.h`
- `components/esp_driver_usb_serial_jtag/src/usb_serial_jtag.c`
- `components/esp_driver_usb_serial_jtag/src/usb_serial_jtag_connection_monitor.c`

### Exact-64 completion

ESP32-S3 USB Serial/JTAG uses a 64-byte full-speed endpoint packet. The low-level header documents the special exact-full case:

- a full 64-byte TX FIFO is automatically flushed by hardware;
- an immediate software flush can therefore be a no-op;
- a full 64-byte USB packet is an unterminated transaction from the CDC-ACM receiver's perspective;
- later data or a ZLP/short packet is required to terminate it;
- the ZLP-producing flush must occur after the FIFO becomes writable again.

This is why the 63-, 64-, and 65-byte stale cases are not equivalent.

### `last_tx_ts` is the v5.5.5 no-driver deadline origin

The simplified VFS stores `s_ctx.last_tx_ts`, described by ESP-IDF as the timestamp of the last time it managed to write something to the TX buffer.

`usb_serial_jtag_tx_char_no_driver()` first checks whether the FIFO is writable. If it is writable, it writes and refreshes `last_tx_ts`. If the FIFO is full, however, its progress loop continues only while:

```text
now - last_tx_ts < 50 ms
```

If `last_tx_ts` is already stale, the byte may therefore be abandoned immediately while the upper VFS write path still reports the requested write size.

`usb_serial_jtag_wait_tx_done_no_driver()` / `fsync` has the same critical property. It calls a low-level flush and then enters its FIFO-writable wait only while the timestamp is still within the 50 ms window. A stale timestamp means it can return `EIO` **without performing a fresh FIFO-writable check**.

Consequently, opening the COM listener later does not create a new `fsync` timeout window.

## Why the `71f766...` algorithm can produce the observed complete timeout

The `71f766...` diagnostics boundary did:

```text
valid request received
-> fflush(stdout)
-> fsync(STDOUT_FILENO)
-> newline delimiter
-> fflush/fsync
-> current JSON response
```

and failed closed before JSON when the pre-`fsync` failed.

If an exact-64 startup transfer filled the FIFO seconds earlier, its `last_tx_ts` is also seconds old. The later helper request proves a user-space listener exists, but that fact does not refresh the VFS timestamp. The pre-`fsync` can therefore return `EIO` immediately, causing the diagnostics handler to return without sending either the delimiter or current JSON.

That behavior directly explains the `71f766...` result where host synchronization succeeded but no valid current response arrived before timeout.

## Why simply sending `fputc('\n')` first is not enough

A bare delimiter-before-`fsync` is not a sufficient correction. If the FIFO is still full, `usb_serial_jtag_tx_char_no_driver()` can also encounter the stale `last_tx_ts` window and abandon the newline immediately. Because the upper VFS write reports the requested size, the caller cannot use the apparent write count alone as proof that the delimiter entered the FIFO.

A fresh FIFO-writable observation must therefore precede the delimiter attempt.

## Selected next boundary algorithm

The diagnostics-only screen-snapshot path now uses a fresh local deadline which does not depend on ESP-IDF's private `last_tx_ts`:

```text
valid diagnostics request received
-> start fresh local monotonic deadline
-> poll TX FIFO writable directly
-> when writable, send one newline via existing stdio/VFS path
-> fflush(stdout)
-> fsync(STDOUT_FILENO)
-> unchanged current JSON response
```

The wait is bounded to 50 ms and uses `esp_timer_get_time()` as its own origin. It yields between polls rather than using a fixed sleep as the correctness condition.

### Why the delimiter still uses stdio/VFS

The private/low-level ESP32-S3 HAL call is used only to observe FIFO writability. The newline itself remains on the existing stdio/VFS path.

Once the FIFO is known writable, a successful no-driver character TX refreshes `last_tx_ts`. The following `fflush`/`fsync` therefore operates from a fresh VFS timestamp and finalizes the short transfer normally.

If a race means the newline does not actually enter the FIFO, `last_tx_ts` remains stale and the following `fsync` fails; the diagnostics handler then fails closed and does not emit current JSON.

### Bounded failure

If the FIFO never becomes writable within the fresh 50 ms local window, the boundary fails and current JSON is not emitted. No retry, parser relaxation, or timeout extension is used.

## API and concurrency boundary

`hal/usb_serial_jtag_ll.h` is a low-level ESP32-S3 implementation interface, not the stable public USB Serial/JTAG driver abstraction. This usage is therefore deliberately constrained:

- it is compiled into the boundary only under `M5AUTH_TEST_SCREEN_SNAPSHOT`;
- the diagnostics target is StickS3 / ESP32-S3;
- the LL interface is used only for a read-only FIFO-writable observation;
- production/default-OFF Protocol-v2 does not execute this boundary;
- the boundary holds the `stdout` FILE lock while waiting/sending, preventing normal competing stdout writers from entering that FILE stream;
- stderr, ROM, constrained/direct, or other low-level writers cannot be globally serialized by the stdout FILE lock and remain residual transport risk.

A concurrent bypass writer can therefore still affect the shared physical stream. The later `fsync` and strict host framing remain fail-closed protection, not proof that all writers are globally serialized.

## Sticky `FILE` error indicator

The prior boundary also checked `ferror(stdout)` at the end. A stdio stream error indicator is sticky historical state until explicitly cleared, so it is not suitable evidence that the **current** boundary attempt failed.

Prior stdout operations whose underlying stdio write/flush fails can set that indicator. Separately, the USB Serial/JTAG no-driver silent character-drop path may still return a nominal write size, so not every physical drop necessarily creates a FILE error.

The new boundary therefore:

- does **not** call `clearerr(stdout)` as a root fix;
- does **not** use historical `ferror(stdout)` as current-attempt evidence;
- does check the current `fputc`, `fflush`, and `fsync` return values;
- fails closed if any of those current operations fail.

This preserves historical stream state rather than erasing it merely to make the gate pass.

## Host timeout diagnostics

Timeout remains a FAIL. Acceptance logic is unchanged.

The helper now records structural counters only so a future authorized Human Gate can distinguish "nothing arrived" from "the stale boundary line arrived but current JSON did not":

```text
post_request_data=yes|no
completed_lines=none|one|multiple
first_completed_frame_len=<number|none>
malformed_unrelated_lines=none|one|multiple
valid_wrong_id_lines=none|one|multiple
post_request_first_byte=<bucket>
```

No raw serial bytes, decoded text, hex, hash, or arbitrary payload content is included. A malformed completed line carrying the current fresh request ID still fails immediately; this instrumentation never converts a timeout or malformed response to PASS.

## Producer status

The exact producer of the earlier unrelated 64-byte packet is still unknown. Candidate classes remain ROM boot output, second-stage bootloader output, ESP-IDF startup/constrained logging, M5Unified/library initialization output, stdout/stderr, panic/reset diagnostics, and direct low-level writers.

A source message need not itself be exactly 64 bytes or omit a newline. With no listener consuming TX, the first full packet can survive while later message bytes (including a newline) fail to make progress.

Raw-content fingerprinting remains prohibited. Producer-specific boolean matching is permitted only if a candidate can first be proved fixed, compile-time, and secret-free.

## Production impact

The root transport behavior is shared with production Protocol-v2, so Issue #121 remains the architectural follow-up. This PR does **not** relax the production parser and does not add the diagnostics delimiter to production/default-OFF traffic.

Longer-term console/Protocol transport separation and steady-state transport integrity should be solved independently of this test-only Human Gate boundary.

## Test model

`tests/screen_snapshot_usb_tx_boundary_test.py` covers:

- existing v5.5.5 `fsync` with fresh `last_tx_ts`;
- existing v5.5.5 `fsync` with stale `last_tx_ts`, including zero FIFO-writable checks;
- stale `last_tx_ts` TX-character drop when FIFO remains full;
- fresh local deadline independent of `last_tx_ts`;
- bounded never-writable failure;
- 63-, 64-, and 65-byte stale transfers;
- exact-64 finalization;
- listener-after-stale64 plus delimiter framing;
- clean response unchanged;
- diagnostics-only source boundary;
- default-OFF production boundary;
- no eFuse-backed ROM-log suppression;
- sticky FILE error is neither cleared nor used as fresh-boundary evidence.

`tests/screen_snapshot_host_helper_test.py` additionally fixes the timeout metadata contract while retaining strict current-ID failure behavior.

The model and CI are not substitutes for physical evidence. A new Human Gate may run only after Integration reviews and explicitly authorizes the exact head.
