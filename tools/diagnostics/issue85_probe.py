import json
import time

import serial
from serial.tools import list_ports

PORT = "COM8"
BAUD = 115200
FIRST_ID = 9101
SECOND_ID = 9102


def port_present() -> bool:
    return any((p.device or "").upper() == PORT for p in list_ports.comports())


def send_hello(ser: serial.Serial, request_id: int) -> None:
    payload = (
        json.dumps(
            {"v": 2, "id": request_id, "op": "hello", "params": {}},
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    ser.write(payload)
    ser.flush()


def open_port_earliest(reappeared_at: float) -> tuple[serial.Serial, float]:
    deadline = time.monotonic() + 3.0
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        ser = serial.Serial()
        ser.port = PORT
        ser.baudrate = BAUD
        ser.timeout = 0.05
        ser.write_timeout = 1
        ser.dtr = False
        ser.rts = False
        try:
            ser.open()
            opened_at = time.monotonic()
            print(
                "PORT_OPEN_AFTER_REAPPEAR_MS="
                + str(round((opened_at - reappeared_at) * 1000))
            )
            return ser, opened_at
        except serial.SerialException as exc:
            last_error = exc
            try:
                ser.close()
            except Exception:
                pass
            time.sleep(0.02)

    raise SystemExit(f"FAIL: COM8 reappeared but could not be opened within 3 seconds: {last_error}")


def main() -> None:
    print("READY: press the physical RESET button on M5StickS3.")

    deadline = time.monotonic() + 30
    while port_present() and time.monotonic() < deadline:
        time.sleep(0.02)

    if port_present():
        raise SystemExit("FAIL: COM8 did not disappear within 30 seconds")

    disappeared_at = time.monotonic()
    print("COM_DISAPPEARED")

    deadline = time.monotonic() + 30
    while not port_present() and time.monotonic() < deadline:
        time.sleep(0.02)

    if not port_present():
        raise SystemExit("FAIL: COM8 did not reappear within 30 seconds")

    reappeared_at = time.monotonic()
    print(
        "COM_REAPPEARED_AFTER_MS="
        + str(round((reappeared_at - disappeared_at) * 1000))
    )

    ser, _ = open_port_earliest(reappeared_at)

    # Intentionally do not call reset_input_buffer(). Startup bytes must remain
    # observable. Only bounded, read-only Protocol 2 hello requests are sent.
    send_hello(ser, FIRST_ID)
    first_sent_at = time.monotonic()
    print(
        "FIRST_HELLO_SENT_AFTER_REAPPEAR_MS="
        + str(round((first_sent_at - reappeared_at) * 1000))
    )

    buffer = b""
    responses: dict[int, float] = {}
    second_sent_at: float | None = None
    deadline = first_sent_at + 15

    while time.monotonic() < deadline:
        now = time.monotonic()

        if FIRST_ID not in responses and second_sent_at is None and now - first_sent_at >= 4:
            send_hello(ser, SECOND_ID)
            second_sent_at = time.monotonic()
            print(
                "SECOND_HELLO_SENT_AFTER_FIRST_MS="
                + str(round((second_sent_at - first_sent_at) * 1000))
            )

        chunk = ser.read(ser.in_waiting or 1)
        if not chunk:
            continue

        buffer += chunk

        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            try:
                obj = json.loads(line.decode("utf-8", "replace").strip())
            except Exception:
                # Ignore startup/non-JSON output without printing it.
                continue

            if not isinstance(obj, dict):
                continue

            request_id = obj.get("id")
            if request_id not in (FIRST_ID, SECOND_ID):
                continue
            if request_id in responses:
                continue

            received_at = time.monotonic()
            responses[request_id] = received_at
            base = first_sent_at if request_id == FIRST_ID else second_sent_at
            if base is None:
                continue

            print(
                f"RESPONSE_ID={request_id} "
                f"OK={obj.get('ok') is True} "
                f"AFTER_SEND_MS={round((received_at - base) * 1000)}"
            )

    ser.close()

    if FIRST_ID in responses:
        print("RESULT=FIRST_HELLO_RECEIVED")
    elif SECOND_ID in responses:
        print("RESULT=FIRST_HELLO_NOT_SEEN_SECOND_RECEIVED")
    else:
        print("RESULT=NO_HELLO_RESPONSE")


if __name__ == "__main__":
    main()
