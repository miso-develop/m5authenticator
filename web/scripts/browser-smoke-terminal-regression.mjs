import assert from "node:assert/strict";
import test from "node:test";

import {
  SmokeTerminalError,
  assertWindowsSmokePass,
  waitForTerminalState,
} from "./browser-smoke-terminal.mjs";

function fakeTime() {
  let current = 0;
  return {
    now: () => current,
    sleep: async (milliseconds) => {
      current += milliseconds;
    },
  };
}

test("running is nonterminal and polling continues until pass", async () => {
  const states = [
    { status: "running", stage: "qr-dense-two-account-v22-dense-decode" },
    { status: "running", stage: "argon2-kdf" },
    {
      status: "pass",
      stage: "complete",
      securityStatus: "pass",
      qrStatus: "pass",
      denseQrStatus: "pass",
      argon2Status: "pass",
    },
  ];
  let reads = 0;
  const time = fakeTime();

  const result = await waitForTerminalState({
    readState: async () => states[Math.min(reads++, states.length - 1)],
    timeoutMs: 1_000,
    pollIntervalMs: 100,
    now: time.now,
    sleep: time.sleep,
  });

  assert.equal(reads, 3);
  assert.equal(result.status, "pass");
  assert.equal(result.stage, "complete");
});

test("explicit fail is terminal and fails closed immediately", async () => {
  let reads = 0;
  const time = fakeTime();

  await assert.rejects(
    waitForTerminalState({
      readState: async () => {
        reads += 1;
        return { status: "fail", stage: "argon2-kdf" };
      },
      timeoutMs: 1_000,
      pollIntervalMs: 100,
      now: time.now,
      sleep: time.sleep,
    }),
    (error) => error instanceof SmokeTerminalError && error.code === "EXPLICIT_FAIL",
  );

  assert.equal(reads, 1);
});

test("intermediate running state times out instead of becoming success", async () => {
  const time = fakeTime();

  await assert.rejects(
    waitForTerminalState({
      readState: async () => ({ status: "running", stage: "argon2-kdf" }),
      timeoutMs: 300,
      pollIntervalMs: 100,
      now: time.now,
      sleep: time.sleep,
    }),
    (error) =>
      error instanceof SmokeTerminalError &&
      error.code === "TIMEOUT" &&
      error.message.includes("status=running") &&
      error.message.includes("stage=argon2-kdf"),
  );
});

test("unexpected nonterminal status fails closed", async () => {
  const time = fakeTime();

  await assert.rejects(
    waitForTerminalState({
      readState: async () => ({ status: "done", stage: "complete" }),
      timeoutMs: 1_000,
      pollIntervalMs: 100,
      now: time.now,
      sleep: time.sleep,
    }),
    (error) => error instanceof SmokeTerminalError && error.code === "INVALID_STATUS",
  );
});

test("Windows aggregate pass requires every existing smoke stage to pass", () => {
  assert.throws(
    () =>
      assertWindowsSmokePass({
        status: "pass",
        stage: "complete",
        securityStatus: "pass",
        qrStatus: "pass",
        denseQrStatus: "pass",
        argon2Status: "",
      }),
    (error) => error instanceof SmokeTerminalError && error.code === "INCOMPLETE_PASS",
  );

  assert.doesNotThrow(() =>
    assertWindowsSmokePass({
      status: "pass",
      stage: "complete",
      securityStatus: "pass",
      qrStatus: "pass",
      denseQrStatus: "pass",
      argon2Status: "pass",
    }),
  );
});
