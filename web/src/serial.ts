import { buildHelloRequest, parseHelloResponse, type HelloData } from "./protocol";

const MAX_RESPONSE_BYTES = 4096;

export async function requestHello(): Promise<HelloData> {
  if (!navigator.serial) {
    throw new Error("Web Serial is unavailable. Use the latest stable Desktop Chrome.");
  }

  const port = await navigator.serial.requestPort();
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
    const decoder = new TextDecoder();
    let pending = "";

    try {
      while (pending.length <= MAX_RESPONSE_BYTES) {
        const { value, done } = await reader.read();
        if (done) {
          break;
        }
        if (value) {
          pending += decoder.decode(value, { stream: true });
        }

        const newline = pending.indexOf("\n");
        if (newline >= 0) {
          const line = pending.slice(0, newline).replace(/\r$/, "");
          return parseHelloResponse(line, requestId);
        }
      }
    } finally {
      reader.releaseLock();
    }

    throw new Error("Device hello response was missing or too large");
  } finally {
    await port.close();
  }
}
