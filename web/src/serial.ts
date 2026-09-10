import {
  buildRequest,
  DeviceProtocolError,
  parseHelloData,
  parseResponseData,
  type HelloData,
} from "./protocol";

const MAX_RESPONSE_BYTES = 4096;
const RESPONSE_TIMEOUT_MS = 5000;

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

export interface DeviceTransport {
  request(op: string, params?: Record<string, unknown>): Promise<Record<string, unknown>>;
  close(): Promise<void>;
}

function browserSerial(): SerialLike | undefined {
  return (navigator as Navigator & { readonly serial?: SerialLike }).serial;
}

export class SerialSession implements DeviceTransport {
  private readonly port: SerialPortLike;
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private readonly writer: WritableStreamDefaultWriter<Uint8Array>;
  private readonly decoder = new TextDecoder();
  private pending = "";
  private pendingBytes = 0;
  private nextId = 1;
  private inFlight = false;
  private closed = false;

  private constructor(
    port: SerialPortLike,
    reader: ReadableStreamDefaultReader<Uint8Array>,
    writer: WritableStreamDefaultWriter<Uint8Array>,
  ) {
    this.port = port;
    this.reader = reader;
    this.writer = writer;
  }

  public static async connect(): Promise<{ session: SerialSession; hello: HelloData }> {
    const serial = browserSerial();
    if (!serial) {
      throw new Error("Web Serial is unavailable. Use the latest stable Desktop Chrome.");
    }

    const port = await serial.requestPort();
    await port.open({ baudRate: 115200 });
    if (!port.readable || !port.writable) {
      await port.close();
      throw new Error("Serial port did not expose readable and writable streams");
    }

    const session = new SerialSession(port, port.readable.getReader(), port.writable.getWriter());
    try {
      const data = await session.request("hello");
      return { session, hello: parseHelloData(data) };
    } catch (error) {
      await session.closeSilently();
      throw error;
    }
  }

  public isClosed(): boolean {
    return this.closed;
  }

  public async request(
    op: string,
    params: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    if (this.closed) {
      throw new Error("Device is not connected");
    }
    if (this.inFlight) {
      throw new Error("Another device request is already in progress");
    }

    this.inFlight = true;
    const id = this.allocateRequestId();
    try {
      const request = buildRequest(id, op, params);
      const payload = new TextEncoder().encode(request);
      try {
        await this.writer.write(payload);
      } finally {
        payload.fill(0);
      }
      const line = await this.readLine();
      return parseResponseData(line, id);
    } catch (error) {
      if (!(error instanceof DeviceProtocolError)) {
        await this.closeSilently();
      }
      throw error;
    } finally {
      this.inFlight = false;
    }
  }

  public async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.pending = "";
    this.pendingBytes = 0;

    try {
      await this.reader.cancel();
    } catch {
      // Best-effort cancellation before releasing the lock.
    }
    try {
      this.reader.releaseLock();
    } catch {
      // The browser may already have released the reader.
    }
    try {
      this.writer.releaseLock();
    } catch {
      // The browser may already have released the writer.
    }
    await this.port.close();
  }

  private allocateRequestId(): number {
    const id = this.nextId;
    this.nextId = this.nextId >= Number.MAX_SAFE_INTEGER ? 1 : this.nextId + 1;
    return id;
  }

  private async readLine(): Promise<string> {
    while (this.pendingBytes <= MAX_RESPONSE_BYTES) {
      const newline = this.pending.indexOf("\n");
      if (newline >= 0) {
        const line = this.pending.slice(0, newline).replace(/\r$/, "");
        this.pending = this.pending.slice(newline + 1);
        this.pendingBytes = new TextEncoder().encode(this.pending).byteLength;
        return line;
      }

      let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<never>((_, reject) => {
        timeoutHandle = setTimeout(() => reject(new Error("Device response timed out")), RESPONSE_TIMEOUT_MS);
      });
      try {
        const { value, done } = await Promise.race([this.reader.read(), timeout]);
        if (done) throw new Error("Device disconnected before responding");
        if (value) {
          this.pendingBytes += value.byteLength;
          if (this.pendingBytes > MAX_RESPONSE_BYTES) {
            throw new Error("Device response was too large");
          }
          this.pending += this.decoder.decode(value, { stream: true });
        }
      } finally {
        if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
      }
    }
    throw new Error("Device response was too large");
  }

  private async closeSilently(): Promise<void> {
    try {
      await this.close();
    } catch {
      // Preserve the original protocol/transport failure.
    }
  }
}

export async function requestHello(): Promise<HelloData> {
  const { session, hello } = await SerialSession.connect();
  await session.close();
  return hello;
}
