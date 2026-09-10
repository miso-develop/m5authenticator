import { buildHelloRequest, parseHelloResponse, type HelloData } from "./protocol";

const MAX_RESPONSE_BYTES = 4096;
const HELLO_TIMEOUT_MS = 5000;

interface SerialPortOptions {
  baudRate: number;
}

interface SerialPortLike {
  readable: ReadableStream<Uint8Array> | null;
  writable: WritableStream<Uint8Array> | null;
  open(options: SerialPortOptions): Promise<void>;
  close(): Promise<void>;
}

interface SerialLike {
  requestPort(): Promise<SerialPortLike>;
}

function browserSerial(): SerialLike | undefined {
  return (navigator as Navigator & { readonly serial?: SerialLike }).serial;
}

async function readHelloLine(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<string> {
  const decoder = new TextDecoder();
  let pending = "";
  let receivedBytes = 0;
  let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

  const timeout = new Promise<never>((_, reject) => {
    timeoutHandle = setTimeout(() => {
      reject(new Error("Device hello response timed out"));
    }, HELLO_TIMEOUT_MS);
  });

  try {
    while (receivedBytes <= MAX_RESPONSE_BYTES) {
      const { value, done } = await Promise.race([reader.read(), timeout]);
      if (done) {
        break;
      }
      if (value) {
        receivedBytes += value.byteLength;
        if (receivedBytes > MAX_RESPONSE_BYTES) {
          throw new Error("Device hello response was too large");
        }
        pending += decoder.decode(value, { stream: true });
      }

      const newline = pending.indexOf("\n");
      if (newline >= 0) {
        return pending.slice(0, newline).replace(/\r$/, "");
      }
    }

    throw new Error("Device hello response was missing");
  } finally {
    if (timeoutHandle !== undefined) {
      clearTimeout(timeoutHandle);
    }
    try {
      await reader.cancel();
    } catch {
      // Best-effort cancellation so the serial port can close cleanly.
    }
  }
}

export async function requestHello(): Promise<HelloData> {
  const serial = browserSerial();
  if (!serial) {
    throw new Error("Web Serial is unavailable. Use the latest stable Desktop Chrome.");
  }

  const port = await serial.requestPort();
  await port.open({ baudRate: 115200 });

  try {
    if (!port.readable || !port.writable) {
      throw new Error("Serial port did not expose readable and writable streams");
    }

    const requestId = 1;
    const writer = port.writable.getWriter();
    try {
      await writer.write(new TextEncoder().encode(buildHelloRequest(requestId)));
    } finally {
      writer.releaseLock();
    }

    const reader = port.readable.getReader();
    try {
      const line = await readHelloLine(reader);
      return parseHelloResponse(line, requestId);
    } finally {
      reader.releaseLock();
    }
  } finally {
    await port.close();
  }
}
