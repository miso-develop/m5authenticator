import { afterEach, describe, expect, it, vi } from "vitest";

import { SerialSession } from "./serial";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

type MockResponse = string | { value: string; delayMs: number } | null;

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

function makeMockPort(startup: string, responses: MockResponse[]) {
  let readableController: ReadableStreamDefaultController<Uint8Array> | undefined;
  const writes: string[] = [];
  const closeEvents: string[] = [];

  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      readableController = controller;
      if (startup.length > 0) controller.enqueue(encoder.encode(startup));
    },
  });

  function enqueue(value: string): void {
    try {
      readableController?.enqueue(encoder.encode(value));
    } catch {
      // A timed-out transport may close/cancel the stream before a synthetic late response arrives.
    }
  }

  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      writes.push(decoder.decode(chunk));
      const next = responses.shift();
      if (next === undefined || next === null) return;
      if (typeof next === "string") {
        enqueue(next);
      } else {
        setTimeout(() => enqueue(next.value), next.delayMs);
      }
    },
  });

  const port = {
    readable,
    writable,
    open: vi.fn(async () => undefined),
    setSignals: vi.fn(async (signals: { requestToSend?: boolean; dataTerminalReady?: boolean }) => {
      if ("requestToSend" in signals) closeEvents.push(`rts:${String(signals.requestToSend)}`);
      if ("dataTerminalReady" in signals) closeEvents.push(`dtr:${String(signals.dataTerminalReady)}`);
    }),
    close: vi.fn(async () => {
      closeEvents.push("close");
    }),
  };

  return { port, writes, closeEvents };
}

function installSerial(port: ReturnType<typeof makeMockPort>["port"]): void {
  vi.stubGlobal("navigator", {
    serial: {
      requestPort: vi.fn(async () => port),
    },
  });
}

function parsedWrites(writes: string[]): Array<Record<string, unknown>> {
  return writes.map((write) => JSON.parse(write.trim()) as Record<string, unknown>);
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("SerialSession USB Serial/JTAG close boundary", () => {
  it("deasserts RTS before DTR in separate operations before closing the port", async () => {
    const { port, closeEvents } = makeMockPort("", [helloResponse()]);
    installSerial(port);

    const { session } = await SerialSession.connect();
    await session.close();

    expect(port.setSignals).toHaveBeenNthCalledWith(1, { requestToSend: false });
    expect(port.setSignals).toHaveBeenNthCalledWith(2, { dataTerminalReady: false });
    expect(closeEvents).toEqual(["rts:false", "dtr:false", "close"]);
    expect(port.close).toHaveBeenCalledOnce();
  });

  it("does not deassert DTR when RTS deassertion cannot be established", async () => {
    const { port, closeEvents } = makeMockPort("", [helloResponse()]);
    port.setSignals.mockImplementationOnce(async () => {
      closeEvents.push("rts:failed");
      throw new Error("synthetic RTS failure");
    });
    installSerial(port);

    const { session } = await SerialSession.connect();
    await session.close();

    expect(port.setSignals).toHaveBeenCalledTimes(1);
    expect(port.setSignals).toHaveBeenCalledWith({ requestToSend: false });
    expect(closeEvents).toEqual(["rts:failed", "close"]);
    expect(port.close).toHaveBeenCalledOnce();
  });

  it("still closes after DTR deassertion fails once RTS is safely deasserted", async () => {
    const { port, closeEvents } = makeMockPort("", [helloResponse()]);
    port.setSignals.mockImplementationOnce(async (signals) => {
      closeEvents.push(`rts:${String(signals.requestToSend)}`);
    });
    port.setSignals.mockImplementationOnce(async () => {
      closeEvents.push("dtr:failed");
      throw new Error("synthetic DTR failure");
    });
    installSerial(port);

    const { session } = await SerialSession.connect();
    await session.close();

    expect(port.setSignals).toHaveBeenCalledTimes(2);
    expect(closeEvents).toEqual(["rts:false", "dtr:failed", "close"]);
    expect(port.close).toHaveBeenCalledOnce();
  });
});

describe("SerialSession initial Protocol 2 synchronization", () => {
  it("skips bounded ESP-IDF startup and blank lines before the first hello response", async () => {
    const { port, writes } = makeMockPort(
      "ESP-ROM:esp32s3-20210327\r\nI (18) boot: ESP-IDF startup\r\n\r\n",
      [helloResponse()],
    );
    installSerial(port);

    const { session, hello } = await SerialSession.connect();

    expect(hello.state).toBe("unprovisioned");
    expect(hello.firmware).toBe("0.1.0");
    expect(writes).toHaveLength(1);
    expect(parsedWrites(writes)[0]).toMatchObject({ v: 2, id: 1, op: "hello" });
    await session.close();
  });

  it("recovers when the first initial hello write is completely lost before Device RX readiness", async () => {
    vi.useFakeTimers();
    const { port, writes } = makeMockPort("", [null, helloResponse()]);
    installSerial(port);

    const connecting = SerialSession.connect();
    await vi.advanceTimersByTimeAsync(1000);
    const { session, hello } = await connecting;

    expect(hello.state).toBe("unprovisioned");
    expect(writes).toHaveLength(2);
    expect(parsedWrites(writes)).toEqual([
      expect.objectContaining({ v: 2, id: 1, op: "hello" }),
      expect.objectContaining({ v: 2, id: 1, op: "hello" }),
    ]);
    expect(session.isClosed()).toBe(false);
    await session.close();
  });

  it("reuses the same pending reader across retry timers and quarantines a late duplicate hello response", async () => {
    vi.useFakeTimers();
    const { port, writes } = makeMockPort("", [
      { value: helloResponse(), delayMs: 1200 },
      helloResponse(),
      response(2, { readiness: "not_synced" }),
    ]);
    installSerial(port);

    const connecting = SerialSession.connect();
    await vi.advanceTimersByTimeAsync(1000);
    const { session } = await connecting;

    expect(writes).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(200);

    const status = await session.requestCanonicalV2("time.status");
    expect(status).toEqual({ readiness: "not_synced" });
    expect(parsedWrites(writes)[2]).toMatchObject({ v: 2, id: 2, op: "time.status" });
    expect(session.isClosed()).toBe(false);
    await session.close();
  });

  it("allows a boot-delayed initial hello beyond the established-session 5 second deadline", async () => {
    vi.useFakeTimers();
    const { port, writes } = makeMockPort("", [{ value: helloResponse(), delayMs: 6000 }]);
    installSerial(port);

    const connecting = SerialSession.connect();
    await vi.advanceTimersByTimeAsync(6000);
    const { session, hello } = await connecting;

    expect(hello.state).toBe("unprovisioned");
    expect(writes.length).toBeGreaterThan(1);
    for (const write of parsedWrites(writes)) {
      expect(write).toMatchObject({ v: 2, id: 1, op: "hello" });
    }
    expect(session.isClosed()).toBe(false);
    await session.close();
  });

  it("fails closed when the bounded 15 second initial synchronization deadline expires", async () => {
    vi.useFakeTimers();
    const { port, writes } = makeMockPort("", []);
    installSerial(port);

    const assertion = expect(SerialSession.connect()).rejects.toThrow("Device response timed out");
    await vi.advanceTimersByTimeAsync(15_000);
    await assertion;

    expect(writes).toHaveLength(15);
    for (const write of parsedWrites(writes)) {
      expect(write).toMatchObject({ v: 2, id: 1, op: "hello" });
    }
    expect(port.close).toHaveBeenCalledOnce();
  });

  it("fails closed on a response with an ID that was never issued", async () => {
    const { port } = makeMockPort("I (18) boot: startup\n", [helloResponse(99)]);
    installSerial(port);

    await expect(SerialSession.connect()).rejects.toThrow("Response id mismatch");
    expect(port.close).toHaveBeenCalledOnce();
  });

  it("fails closed on malformed JSON-looking startup output", async () => {
    const { port } = makeMockPort("", ["{not-json}\n"]);
    installSerial(port);

    await expect(SerialSession.connect()).rejects.toThrow("Device returned invalid JSON");
    expect(port.close).toHaveBeenCalledOnce();
  });

  it("keeps startup-line tolerance limited to the initial hello exchange", async () => {
    const { port } = makeMockPort("ESP-ROM: startup\n", [
      helloResponse(),
      "I (42) runtime log\n" + response(2),
    ]);
    installSerial(port);

    const { session } = await SerialSession.connect();

    await expect(session.requestCanonicalV2("time.status")).rejects.toThrow("Device returned invalid JSON");
    expect(session.isClosed()).toBe(true);
  });

  it("keeps established-session requests on the strict 5 second response deadline", async () => {
    vi.useFakeTimers();
    const { port, writes } = makeMockPort("", [
      helloResponse(),
      { value: response(2), delayMs: 6000 },
    ]);
    installSerial(port);

    const { session } = await SerialSession.connect();
    const assertion = expect(session.requestCanonicalV2("time.status")).rejects.toThrow("Device response timed out");
    await vi.advanceTimersByTimeAsync(5000);
    await assertion;

    expect(writes).toHaveLength(2);
    expect(session.isClosed()).toBe(true);
    expect(port.close).toHaveBeenCalledOnce();

    // The late response arrives after reader cancellation and must not escape or
    // become available to a future request on the closed transport.
    await vi.advanceTimersByTimeAsync(1000);
    await expect(session.requestCanonicalV2("time.status")).rejects.toThrow("Device is not connected");
  });

  it("never retries a state-changing operation after synchronization", async () => {
    vi.useFakeTimers();
    const { port, writes } = makeMockPort("", [helloResponse(), null]);
    installSerial(port);

    const { session } = await SerialSession.connect();
    const assertion = expect(session.requestCanonicalV2("vault.install", {})).rejects.toThrow(
      "Device response timed out",
    );
    await vi.advanceTimersByTimeAsync(5000);
    await assertion;
    await vi.advanceTimersByTimeAsync(10_000);

    expect(writes).toHaveLength(2);
    expect(parsedWrites(writes)[1]).toMatchObject({ v: 2, id: 2, op: "vault.install" });
    expect(session.isClosed()).toBe(true);
  });

  it("fails closed when startup noise exceeds the bounded line count", async () => {
    const startup = Array.from({ length: 65 }, (_, index) => `I (${index}) startup\n`).join("");
    const { port } = makeMockPort(startup, [helloResponse()]);
    installSerial(port);

    await expect(SerialSession.connect()).rejects.toThrow(
      "Device startup output exceeded synchronization limits",
    );
    expect(port.close).toHaveBeenCalledOnce();
  });
});
