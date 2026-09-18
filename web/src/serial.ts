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
const INITIAL_HELLO_RESPONSE_TIMEOUT_MS = 15_000;
const INITIAL_HELLO_RETRY_INTERVAL_MS = 1000;
const MAX_STARTUP_NOISE_LINES = 64;
const MAX_STARTUP_NOISE_BYTES = 8192;

class DeviceResponseTimeoutError extends Error {
  public constructor() {
    super("Device response timed out");
    this.name = "DeviceResponseTimeoutError";
  }
}

interface SerialPortOptions {
  baudRate: number;
}

interface SerialOutputSignals {
  dataTerminalReady?: boolean;
  requestToSend?: boolean;
}

interface SerialPortLike {
  readable: ReadableStream<Uint8Array> | null;
  writable: WritableStream<Uint8Array> | null;
  open(options: SerialPortOptions): Promise<void>;
  setSignals?(signals: SerialOutputSignals): Promise<void>;
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

function responseIdCandidate(raw: string): number | undefined {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
    const id = (parsed as { id?: unknown }).id;
    return typeof id === "number" && Number.isSafeInteger(id) ? id : undefined;
  } catch {
    return undefined;
  }
}

export class SerialSession implements DeviceTransport, CanonicalV2Transport {
  private readonly port: SerialPortLike;
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private readonly writer: WritableStreamDefaultWriter<Uint8Array>;
  private readonly decoder = new TextDecoder();
  private pending = "";
  private pendingBytes = 0;
  private pendingRead: Promise<ReadableStreamReadResult<Uint8Array>> | undefined;
  private nextId = 1;
  private inFlight = false;
  private closed = false;
  private staleInitialHelloResponseId: number | undefined;
  private staleInitialHelloResponsesRemaining = 0;

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
    await session.normalizeUsbSerialJtagControlLines();
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
    this.staleInitialHelloResponseId = undefined;
    this.staleInitialHelloResponsesRemaining = 0;

    await this.normalizeUsbSerialJtagControlLines();

    try {
      await this.reader.cancel();
    } catch {
      // Best-effort cancellation before releasing the lock.
    }
    this.pendingRead = undefined;
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

  private async normalizeUsbSerialJtagControlLines(): Promise<void> {
    const setSignals = this.port.setSignals?.bind(this.port);
    if (!setSignals) return;

    // Keep ESP32-S3 USB Serial/JTAG in a safe host-control state throughout
    // the open session and immediately before close. RTS=1,DTR=0 is a reset
    // request. Web Serial applies DTR before RTS when both are supplied
    // together, so never normalize both lines in one call. Deassert RTS first;
    // only after that succeeds is it safe to deassert DTR.
    try {
      await setSignals({ requestToSend: false });
    } catch {
      return;
    }

    try {
      await setSignals({ dataTerminalReady: false });
    } catch {
      // RTS is already deasserted. Port/resource teardown must still proceed.
    }
  }

  private async requestInitialHello(): Promise<Record<string, unknown>> {
    if (this.closed) throw new Error("Device is not connected");
    if (this.inFlight) throw new Error("Another device request is already in progress");

    this.inFlight = true;
    const id = this.allocateRequestId();
    const request = buildCanonicalV2Request(id, "hello", {});
    const deadlineMs = Date.now() + INITIAL_HELLO_RESPONSE_TIMEOUT_MS;
    let nextRetryMs = Date.now();
    let attempts = 0;
    let skippedLines = 0;
    let skippedBytes = 0;
    const encoder = new TextEncoder();

    try {
      while (true) {
        const now = Date.now();
        if (now >= deadlineMs) throw new DeviceResponseTimeoutError();

        if (attempts === 0 || now >= nextRetryMs) {
          await this.writeRequest(request);
          attempts += 1;
          nextRetryMs = Math.min(deadlineMs, Date.now() + INITIAL_HELLO_RETRY_INTERVAL_MS);
        }

        const readDeadlineMs = Math.min(deadlineMs, nextRetryMs);
        let line: string;
        try {
          line = await this.readLine(readDeadlineMs, MAX_STARTUP_NOISE_BYTES);
        } catch (error) {
          if (error instanceof DeviceResponseTimeoutError && readDeadlineMs < deadlineMs) {
            continue;
          }
          throw error;
        }

        const lineBytes = encoder.encode(line).byteLength;
        if (!line.trimStart().startsWith("{")) {
          skippedLines += 1;
          skippedBytes += lineBytes + 1;
          if (skippedLines > MAX_STARTUP_NOISE_LINES || skippedBytes > MAX_STARTUP_NOISE_BYTES) {
            throw new Error("Device startup output exceeded synchronization limits");
          }
          continue;
        }

        if (lineBytes > MAX_RESPONSE_BYTES) throw new Error("Device response was too large");
        const data = parseCanonicalV2Response(line, id);
        if (attempts > 1) {
          this.staleInitialHelloResponseId = id;
          this.staleInitialHelloResponsesRemaining = attempts - 1;
        }
        return data;
      }
    } finally {
      this.inFlight = false;
    }
  }

  private async exchange(
    build: (id: number) => string,
    parse: (raw: string, expectedId: number) => Record<string, unknown>,
    isDeviceRejection: (error: unknown) => boolean,
  ): Promise<Record<string, unknown>> {
    if (this.closed) throw new Error("Device is not connected");
    if (this.inFlight) throw new Error("Another device request is already in progress");

    this.inFlight = true;
    const id = this.allocateRequestId();
    try {
      await this.writeRequest(build(id));

      const deadlineMs = Date.now() + RESPONSE_TIMEOUT_MS;
      const line = await this.readResponseLine(deadlineMs);
      return parse(line, id);
    } catch (error) {
      if (!isDeviceRejection(error)) await this.closeSilently();
      throw error;
    } finally {
      this.inFlight = false;
    }
  }

  private async writeRequest(request: string): Promise<void> {
    const payload = new TextEncoder().encode(request);
    try {
      await this.writer.write(payload);
    } finally {
      payload.fill(0);
    }
  }

  private allocateRequestId(): number {
    const id = this.nextId;
    this.nextId = this.nextId >= Number.MAX_SAFE_INTEGER ? 1 : this.nextId + 1;
    return id;
  }

  private async readResponseLine(deadlineMs: number): Promise<string> {
    while (true) {
      const line = await this.readLine(deadlineMs, MAX_RESPONSE_BYTES);
      const staleId = this.staleInitialHelloResponseId;
      if (staleId === undefined || this.staleInitialHelloResponsesRemaining <= 0) return line;
      if (!line.trimStart().startsWith("{")) return line;
      if (responseIdCandidate(line) !== staleId) return line;

      // Initial hello is the only retried operation. A late duplicate may arrive
      // after synchronization, so fully validate and quarantine at most the
      // number of extra hello writes that were actually issued.
      parseCanonicalV2Response(line, staleId);
      this.staleInitialHelloResponsesRemaining -= 1;
      if (this.staleInitialHelloResponsesRemaining <= 0) {
        this.staleInitialHelloResponseId = undefined;
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

      const { value, done } = await this.readChunkUntil(deadlineMs);
      if (done) throw new Error("Device disconnected before responding");
      if (value) {
        this.pendingBytes += value.byteLength;
        if (this.pendingBytes > maxBufferedBytes) throw new Error("Device response was too large");
        this.pending += this.decoder.decode(value, { stream: true });
      }
    }
    throw new Error("Device response was too large");
  }

  private async readChunkUntil(
    deadlineMs: number,
  ): Promise<ReadableStreamReadResult<Uint8Array>> {
    const remainingMs = deadlineMs - Date.now();
    if (remainingMs <= 0) throw new DeviceResponseTimeoutError();

    const readPromise = this.pendingRead ?? this.reader.read();
    this.pendingRead = readPromise;

    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timeoutHandle = setTimeout(() => reject(new DeviceResponseTimeoutError()), remainingMs);
    });

    try {
      const result = await Promise.race([readPromise, timeout]);
      if (this.pendingRead === readPromise) this.pendingRead = undefined;
      return result;
    } catch (error) {
      // A retry timer must never abandon reader.read(). Keep the same pending
      // read Promise so the next bounded wait observes the eventual chunk.
      if (!(error instanceof DeviceResponseTimeoutError) && this.pendingRead === readPromise) {
        this.pendingRead = undefined;
      }
      throw error;
    } finally {
      if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
    }
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
