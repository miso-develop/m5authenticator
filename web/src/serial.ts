import {
  buildRequest,
  DeviceProtocolError,
  parseResponseData,
} from "./protocol";
import {
  buildCanonicalV2Request,
  CanonicalProtocolV2Error,
  parseCanonicalHelloData,
  parseCanonicalV2Response,
  type CanonicalHelloData,
  type CanonicalWireOperation,
} from "./canonical-protocol-v2";
import {
  buildSessionV2Request,
  parseSessionV2Response,
  SessionProtocolV2Error,
  type SessionWireOperation,
} from "./security/session-protocol-v2";

const MAX_RESPONSE_BYTES = 4096;
const RESPONSE_TIMEOUT_MS = 5000;
const MAX_STARTUP_NOISE_LINES = 64;
const MAX_STARTUP_NOISE_BYTES = 8192;

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

// Legacy Protocol 1 transport is retained only for isolated compatibility tests.
// Canonical application code must use CanonicalV2Transport / SessionV2Transport.
export interface DeviceTransport {
  request(op: string, params?: Record<string, unknown>): Promise<Record<string, unknown>>;
  close(): Promise<void>;
}

export interface SessionV2Transport {
  requestV2(op: SessionWireOperation, params?: Record<string, unknown>): Promise<Record<string, unknown>>;
  close(): Promise<void>;
}

export interface CanonicalV2Transport extends SessionV2Transport {
  requestCanonicalV2(
    op: CanonicalWireOperation,
    params?: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
  close(): Promise<void>;
}

function browserSerial(): SerialLike | undefined {
  return (navigator as Navigator & { readonly serial?: SerialLike }).serial;
}

export class SerialSession implements DeviceTransport, CanonicalV2Transport {
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

  public static async connect(): Promise<{ session: SerialSession; hello: CanonicalHelloData }> {
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
      const data = await session.requestInitialHello();
      return { session, hello: parseCanonicalHelloData(data) };
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
    return this.exchange(
      (id) => buildRequest(id, op, params),
      parseResponseData,
      (error) => error instanceof DeviceProtocolError,
    );
  }

  public async requestV2(
    op: SessionWireOperation,
    params: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    return this.exchange(
      (id) => buildSessionV2Request(id, op, params),
      parseSessionV2Response,
      (error) => error instanceof SessionProtocolV2Error,
    );
  }

  public async requestCanonicalV2(
    op: CanonicalWireOperation,
    params: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    return this.exchange(
      (id) => buildCanonicalV2Request(id, op, params),
      parseCanonicalV2Response,
      (error) => error instanceof CanonicalProtocolV2Error,
    );
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

  private async requestInitialHello(): Promise<Record<string, unknown>> {
    return this.exchange(
      (id) => buildCanonicalV2Request(id, "hello", {}),
      parseCanonicalV2Response,
      (error) => error instanceof CanonicalProtocolV2Error,
      true,
    );
  }

  private async exchange(
    build: (id: number) => string,
    parse: (raw: string, expectedId: number) => Record<string, unknown>,
    isDeviceRejection: (error: unknown) => boolean,
    allowInitialStartupNoise = false,
  ): Promise<Record<string, unknown>> {
    if (this.closed) throw new Error("Device is not connected");
    if (this.inFlight) throw new Error("Another device request is already in progress");

    this.inFlight = true;
    const id = this.allocateRequestId();
    try {
      const request = build(id);
      const payload = new TextEncoder().encode(request);
      try {
        await this.writer.write(payload);
      } finally {
        payload.fill(0);
      }

      const deadlineMs = Date.now() + RESPONSE_TIMEOUT_MS;
      const line = allowInitialStartupNoise
        ? await this.readInitialProtocolLine(deadlineMs)
        : await this.readLine(deadlineMs, MAX_RESPONSE_BYTES);
      return parse(line, id);
    } catch (error) {
      if (!isDeviceRejection(error)) await this.closeSilently();
      throw error;
    } finally {
      this.inFlight = false;
    }
  }

  private allocateRequestId(): number {
    const id = this.nextId;
    this.nextId = this.nextId >= Number.MAX_SAFE_INTEGER ? 1 : this.nextId + 1;
    return id;
  }

  private async readInitialProtocolLine(deadlineMs: number): Promise<string> {
    let skippedLines = 0;
    let skippedBytes = 0;
    const encoder = new TextEncoder();

    while (true) {
      const line = await this.readLine(deadlineMs, MAX_STARTUP_NOISE_BYTES);
      const lineBytes = encoder.encode(line).byteLength;
      if (line.trimStart().startsWith("{")) {
        if (lineBytes > MAX_RESPONSE_BYTES) throw new Error("Device response was too large");
        return line;
      }

      skippedLines += 1;
      skippedBytes += lineBytes + 1;
      if (skippedLines > MAX_STARTUP_NOISE_LINES || skippedBytes > MAX_STARTUP_NOISE_BYTES) {
        throw new Error("Device startup output exceeded synchronization limits");
      }
    }
  }

  private async readLine(deadlineMs: number, maxBufferedBytes: number): Promise<string> {
    while (this.pendingBytes <= maxBufferedBytes) {
      const newline = this.pending.indexOf("\n");
      if (newline >= 0) {
        const line = this.pending.slice(0, newline).replace(/\r$/, "");
        this.pending = this.pending.slice(newline + 1);
        this.pendingBytes = new TextEncoder().encode(this.pending).byteLength;
        return line;
      }

      const remainingMs = deadlineMs - Date.now();
      if (remainingMs <= 0) throw new Error("Device response timed out");

      let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<never>((_, reject) => {
        timeoutHandle = setTimeout(() => reject(new Error("Device response timed out")), remainingMs);
      });
      try {
        const { value, done } = await Promise.race([this.reader.read(), timeout]);
        if (done) throw new Error("Device disconnected before responding");
        if (value) {
          this.pendingBytes += value.byteLength;
          if (this.pendingBytes > maxBufferedBytes) throw new Error("Device response was too large");
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

export async function requestHello(): Promise<CanonicalHelloData> {
  const { session, hello } = await SerialSession.connect();
  await session.close();
  return hello;
}
