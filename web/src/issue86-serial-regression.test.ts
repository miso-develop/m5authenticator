import { afterEach, describe, expect, it, vi } from "vitest";

import { SerialSession } from "./serial";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

type Emission =
  | string
  | { value: string; delayMs: number }
  | { chunks: string[] }
  | null;

interface SerialDebugView {
  pendingBytes?: unknown;
  pendingRead?: unknown;
  inFlight?: unknown;
  closed?: unknown;
  staleInitialHelloResponseId?: unknown;
  staleInitialHelloResponsesRemaining?: unknown;
}

function helloResponse(id = 1): string {
  return JSON.stringify({
    v: 2,
    id,
    ok: true,
    data: {
      device: "M5StickS3",
      device_id: "synthetic-device",
      firmware: "0.1.0",
      protocol: 2,
      storage_schema: 2,
      vault_format: 1,
      build_commit: "synthetic-test-build",
      state: "unprovisioned",
      storage_ready: true,
      recovery_reset_required: false,
      vault_present: false,
      vault_id: null,
      generation: "0",
      registration_present: false,
      registration_id: null,
      registration_epoch: 0,
      brk_public_key: null,
    },
  }) + "\n";
}

function response(id: number, data: Record<string, unknown> = {}): string {
  return JSON.stringify({ v: 2, id, ok: true, data }) + "\n";
}

function makePort(emissions: Emission[]) {
  let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
  const writes: string[] = [];

  const readable = new ReadableStream<Uint8Array>({
    start(value) {
      controller = value;
    },
  });

  const enqueue = (value: string) => {
    try {
      controller?.enqueue(encoder.encode(value));
    } catch {
      // A fail-closed timeout may cancel the stream before a synthetic late emission.
    }
  };

  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      writes.push(decoder.decode(chunk));
      const next = emissions.shift();
      if (next === undefined || next === null) return;
      if (typeof next === "string") {
        enqueue(next);
        return;
      }
      if ("chunks" in next) {
        for (const value of next.chunks) enqueue(value);
        return;
      }
      setTimeout(() => enqueue(next.value), next.delayMs);
    },
  });

  const port = {
    readable,
    writable,
    open: vi.fn(async () => undefined),
    close: vi.fn(async () => undefined),
  };

  vi.stubGlobal("navigator", {
    serial: {
      requestPort: vi.fn(async () => port),
    },
  });

  return { port, writes };
}

function parsedWrites(writes: string[]): Array<Record<string, unknown>> {
  return writes.map((value) => JSON.parse(value.trim()) as Record<string, unknown>);
}

function debugView(session: SerialSession): SerialDebugView {
  return session as unknown as SerialDebugView;
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("#86 established Web Serial regression boundaries", () => {
  it("quarantines a very late duplicate initial hello without consuming later session.status", async () => {
    vi.useFakeTimers();
    const { writes } = makePort([
      { value: helloResponse(), delayMs: 3000 },
      helloResponse(),
      response(2),
      response(3),
      response(4, { state: "awaiting_presence" }),
      response(5, { state: "confirmed" }),
    ]);

    const connecting = SerialSession.connect();
    await vi.advanceTimersByTimeAsync(1000);
    const { session } = await connecting;

    await session.requestV2("session.begin");
    await session.requestV2("session.authorize");
    expect(await session.requestV2("session.status")).toEqual({ state: "awaiting_presence" });

    // The delayed response to the first initial hello write now arrives after
    // several established requests have already completed.
    await vi.advanceTimersByTimeAsync(2000);
    expect(await session.requestV2("session.status")).toEqual({ state: "confirmed" });

    expect(parsedWrites(writes)).toEqual([
      expect.objectContaining({ id: 1, op: "hello" }),
      expect.objectContaining({ id: 1, op: "hello" }),
      expect.objectContaining({ id: 2, op: "session.begin" }),
      expect.objectContaining({ id: 3, op: "session.authorize" }),
      expect.objectContaining({ id: 4, op: "session.status" }),
      expect.objectContaining({ id: 5, op: "session.status" }),
    ]);

    const internal = debugView(session);
    expect(internal.pendingRead).toBeUndefined();
    expect(internal.staleInitialHelloResponsesRemaining).toBe(0);
    expect(internal.staleInitialHelloResponseId).toBeUndefined();
    expect(session.isClosed()).toBe(false);
    await session.close();
  });

  it("reassembles a Protocol 2 status response split across readable chunks", async () => {
    const statusLine = response(2, { state: "awaiting_presence" });
    const split = Math.floor(statusLine.length / 2);
    makePort([
      helloResponse(),
      { chunks: [statusLine.slice(0, split), statusLine.slice(split)] },
    ]);

    const { session } = await SerialSession.connect();
    expect(await session.requestV2("session.status")).toEqual({ state: "awaiting_presence" });

    const internal = debugView(session);
    expect(internal.pendingBytes).toBe(0);
    expect(internal.pendingRead).toBeUndefined();
    expect(session.isClosed()).toBe(false);
    await session.close();
  });

  it("enters the first transport close from the in-flight established timeout path", async () => {
    vi.useFakeTimers();
    const { port } = makePort([helloResponse(), null]);
    const originalClose = SerialSession.prototype.close;
    const closeSnapshots: Array<{ inFlight: boolean; pendingRead: boolean; pendingBytes: number; closed: boolean }> = [];

    vi.spyOn(SerialSession.prototype, "close").mockImplementation(async function observedClose() {
      const internal = debugView(this);
      closeSnapshots.push({
        inFlight: internal.inFlight === true,
        pendingRead: internal.pendingRead !== undefined,
        pendingBytes: typeof internal.pendingBytes === "number" ? internal.pendingBytes : -1,
        closed: internal.closed === true,
      });
      await originalClose.call(this);
    });

    const { session } = await SerialSession.connect();
    const request = expect(session.requestV2("session.status")).rejects.toThrow("Device response timed out");
    await vi.advanceTimersByTimeAsync(5000);
    await request;

    expect(closeSnapshots).toEqual([{
      inFlight: true,
      pendingRead: true,
      pendingBytes: 0,
      closed: false,
    }]);
    expect(session.isClosed()).toBe(true);
    expect(port.close).toHaveBeenCalledOnce();
  });

  it("distinguishes a partial line timeout from a zero-byte response by pending byte count", async () => {
    vi.useFakeTimers();
    const full = response(2, { state: "confirmed" });
    const partial = full.slice(0, Math.max(1, full.length - 2));
    makePort([helloResponse(), partial]);

    const originalClose = SerialSession.prototype.close;
    let pendingBytesAtClose = -1;
    vi.spyOn(SerialSession.prototype, "close").mockImplementation(async function observedClose() {
      const internal = debugView(this);
      pendingBytesAtClose = typeof internal.pendingBytes === "number" ? internal.pendingBytes : -1;
      await originalClose.call(this);
    });

    const { session } = await SerialSession.connect();
    const request = expect(session.requestV2("session.status")).rejects.toThrow("Device response timed out");
    await vi.advanceTimersByTimeAsync(5000);
    await request;

    expect(pendingBytesAtClose).toBeGreaterThan(0);
    expect(session.isClosed()).toBe(true);
  });
});
