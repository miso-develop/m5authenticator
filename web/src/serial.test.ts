import { afterEach, describe, expect, it, vi } from "vitest";

import { SerialSession } from "./serial";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

type MockResponse = string | { value: string; delayMs: number };

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
      // A timed-out transport closes/cancels the stream before a synthetic late response arrives.
    }
  }

  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      writes.push(decoder.decode(chunk));
      const next = responses.shift();
      if (next === undefined) return;
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
    close: vi.fn(async () => undefined),
  };

  return { port, writes };
}

function installSerial(port: ReturnType<typeof makeMockPort>["port"]): void {
  vi.stubGlobal("navigator", {
    serial: {
      requestPort: vi.fn(async () => port),
    },
  });
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
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
    const firstWrite = writes[0];
    if (firstWrite === undefined) throw new Error("Serial hello request was not written");
    expect(JSON.parse(firstWrite.trim())).toMatchObject({ v: 2, id: 1, op: "hello" });
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
    expect(writes).toHaveLength(1);
    expect(session.isClosed()).toBe(false);
    await session.close();
  });

  it("does not skip a JSON candidate with the wrong request id", async () => {
    const { port } = makeMockPort("I (18) boot: startup\n", [helloResponse(99)]);
    installSerial(port);

    await expect(SerialSession.connect()).rejects.toThrow("Response id mismatch");
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

describe("SerialSession operation-specific response deadlines", () => {
  it("keeps established read-only requests on the strict 5 second deadline", async () => {
    vi.useFakeTimers();
    const { port } = makeMockPort("", [
      helloResponse(),
      { value: response(2), delayMs: 6000 },
    ]);
    installSerial(port);
    const { session } = await SerialSession.connect();

    const assertion = expect(session.requestCanonicalV2("time.status")).rejects.toThrow(
      "Device response timed out during time.status",
    );
    await vi.advanceTimersByTimeAsync(5000);
    await assertion;

    expect(session.isClosed()).toBe(true);
    expect(port.close).toHaveBeenCalledOnce();
  });

  it("allows a delayed vault.install response without issuing a duplicate write", async () => {
    vi.useFakeTimers();
    const { port, writes } = makeMockPort("", [
      helloResponse(),
      { value: response(2), delayMs: 6000 },
    ]);
    installSerial(port);
    const { session } = await SerialSession.connect();

    const installing = session.requestCanonicalV2("vault.install", { synthetic: true });
    await vi.advanceTimersByTimeAsync(6000);
    await expect(installing).resolves.toEqual({});

    expect(writes).toHaveLength(2);
    const installWrite = writes[1];
    if (installWrite === undefined) throw new Error("vault.install request was not written");
    expect(JSON.parse(installWrite.trim())).toMatchObject({ v: 2, id: 2, op: "vault.install" });
    expect(session.isClosed()).toBe(false);
    await session.close();
  });

  it("still enforces the exact response id during the extended vault.install window", async () => {
    vi.useFakeTimers();
    const { port } = makeMockPort("", [
      helloResponse(),
      { value: response(99), delayMs: 6000 },
    ]);
    installSerial(port);
    const { session } = await SerialSession.connect();

    const assertion = expect(session.requestCanonicalV2("vault.install", { synthetic: true })).rejects.toThrow(
      "Response id mismatch",
    );
    await vi.advanceTimersByTimeAsync(6000);
    await assertion;

    expect(session.isClosed()).toBe(true);
  });

  it("allows session.complete to finish beyond five seconds without retrying it", async () => {
    vi.useFakeTimers();
    const { port, writes } = makeMockPort("", [
      helloResponse(),
      { value: response(2), delayMs: 6000 },
    ]);
    installSerial(port);
    const { session } = await SerialSession.connect();

    const completing = session.requestV2("session.complete", { attempt_id: "synthetic" });
    await vi.advanceTimersByTimeAsync(6000);
    await expect(completing).resolves.toEqual({});

    expect(writes).toHaveLength(2);
    const completeWrite = writes[1];
    if (completeWrite === undefined) throw new Error("session.complete request was not written");
    expect(JSON.parse(completeWrite.trim())).toMatchObject({ v: 2, id: 2, op: "session.complete" });
    await session.close();
  });
});
