import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawn, spawnSync } from "node:child_process";

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_POLL_INTERVAL_MS = 250;
const DEVTOOLS_FILE_POLL_MS = 100;
const CDP_REQUEST_TIMEOUT_MS = 5_000;
const SAFE_DIAGNOSTIC_VALUE = /^[A-Za-z0-9._:-]{0,160}$/;

const sleepReal = (milliseconds) => new Promise((resolveSleep) => setTimeout(resolveSleep, milliseconds));

function safeDiagnosticValue(value, fallback) {
  return typeof value === "string" && SAFE_DIAGNOSTIC_VALUE.test(value) ? value : fallback;
}

function normalizeState(value) {
  const state = value && typeof value === "object" ? value : {};
  return {
    status: safeDiagnosticValue(state.status, ""),
    stage: safeDiagnosticValue(state.stage, "unknown"),
    securityStatus: safeDiagnosticValue(state.securityStatus, ""),
    qrStatus: safeDiagnosticValue(state.qrStatus, ""),
    denseQrStatus: safeDiagnosticValue(state.denseQrStatus, ""),
    argon2Status: safeDiagnosticValue(state.argon2Status, ""),
  };
}

export class SmokeTerminalError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SmokeTerminalError";
    this.code = code;
  }
}

function timeoutError(timeoutMs, state) {
  return new SmokeTerminalError(
    "TIMEOUT",
    `Browser smoke timed out after ${timeoutMs}ms with status=${state.status || "unset"} stage=${state.stage || "unknown"}.`,
  );
}

export async function waitForTerminalState({
  readState,
  timeoutMs,
  pollIntervalMs = DEFAULT_POLL_INTERVAL_MS,
  now = Date.now,
  sleep = sleepReal,
}) {
  if (typeof readState !== "function") {
    throw new TypeError("readState must be a function");
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("timeoutMs must be a positive finite number");
  }
  if (!Number.isFinite(pollIntervalMs) || pollIntervalMs <= 0) {
    throw new TypeError("pollIntervalMs must be a positive finite number");
  }

  const startedAt = now();
  const deadline = startedAt + timeoutMs;
  let lastState = normalizeState({});

  while (true) {
    if (now() > deadline) {
      throw timeoutError(timeoutMs, lastState);
    }

    lastState = normalizeState(await readState());
    if (lastState.status === "pass") {
      return lastState;
    }
    if (lastState.status === "fail") {
      throw new SmokeTerminalError(
        "EXPLICIT_FAIL",
        `Browser smoke reported explicit fail at stage=${lastState.stage || "unknown"}.`,
      );
    }
    if (lastState.status !== "" && lastState.status !== "running") {
      throw new SmokeTerminalError(
        "INVALID_STATUS",
        `Browser smoke reported unexpected status=${lastState.status} at stage=${lastState.stage || "unknown"}.`,
      );
    }

    const remaining = deadline - now();
    if (remaining <= 0) {
      throw timeoutError(timeoutMs, lastState);
    }
    await sleep(Math.min(pollIntervalMs, remaining));
  }
}

export function assertWindowsSmokePass(stateValue) {
  const state = normalizeState(stateValue);
  const required = [
    ["status", state.status],
    ["stage", state.stage],
    ["securityStatus", state.securityStatus],
    ["qrStatus", state.qrStatus],
    ["denseQrStatus", state.denseQrStatus],
    ["argon2Status", state.argon2Status],
  ];
  const expected = {
    status: "pass",
    stage: "complete",
    securityStatus: "pass",
    qrStatus: "pass",
    denseQrStatus: "pass",
    argon2Status: "pass",
  };
  const mismatch = required.find(([name, value]) => value !== expected[name]);
  if (mismatch) {
    throw new SmokeTerminalError(
      "INCOMPLETE_PASS",
      `Browser smoke terminal pass is incomplete: ${mismatch[0]}=${mismatch[1] || "unset"}.`,
    );
  }
}

async function waitForDevToolsPort(profileDir, deadline) {
  const portFile = join(profileDir, "DevToolsActivePort");
  while (Date.now() <= deadline) {
    try {
      const contents = await readFile(portFile, "utf8");
      const firstLine = contents.split(/\r?\n/, 1)[0]?.trim();
      const port = Number(firstLine);
      if (Number.isInteger(port) && port > 0 && port <= 65_535) {
        return port;
      }
      throw new SmokeTerminalError("DEVTOOLS_PORT", "Chrome DevTools port file was invalid.");
    } catch (error) {
      if (error instanceof SmokeTerminalError) throw error;
      if (error && typeof error === "object" && error.code !== "ENOENT") {
        throw new SmokeTerminalError("DEVTOOLS_PORT", "Chrome DevTools port file could not be read.");
      }
    }
    await sleepReal(DEVTOOLS_FILE_POLL_MS);
  }
  throw new SmokeTerminalError("DEVTOOLS_TIMEOUT", "Chrome DevTools did not become ready before the smoke timeout.");
}

async function waitForPageTarget(port, smokeUrl, deadline) {
  const endpoint = `http://127.0.0.1:${port}/json/list`;
  while (Date.now() <= deadline) {
    try {
      const response = await fetch(endpoint, { cache: "no-store" });
      if (response.ok) {
        const targets = await response.json();
        if (Array.isArray(targets)) {
          const page = targets.find(
            (target) =>
              target &&
              target.type === "page" &&
              typeof target.url === "string" &&
              target.url.startsWith(smokeUrl) &&
              typeof target.webSocketDebuggerUrl === "string",
          );
          if (page) return page.webSocketDebuggerUrl;
        }
      }
    } catch {
      // Chrome may expose the port file before the target list is ready.
    }
    await sleepReal(DEVTOOLS_FILE_POLL_MS);
  }
  throw new SmokeTerminalError("DEVTOOLS_TIMEOUT", "Chrome smoke page did not become debuggable before the smoke timeout.");
}

class CdpClient {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    socket.addEventListener("message", (event) => this.handleMessage(event));
    socket.addEventListener("close", () => this.failPending("Chrome DevTools connection closed."));
    socket.addEventListener("error", () => this.failPending("Chrome DevTools connection failed."));
  }

  handleMessage(event) {
    let message;
    try {
      message = JSON.parse(typeof event.data === "string" ? event.data : String(event.data));
    } catch {
      return;
    }
    if (!message || typeof message.id !== "number") return;
    const pending = this.pending.get(message.id);
    if (!pending) return;
    this.pending.delete(message.id);
    clearTimeout(pending.timer);
    if (message.error) {
      pending.reject(new SmokeTerminalError("CDP_ERROR", "Chrome DevTools evaluation failed."));
      return;
    }
    pending.resolve(message.result);
  }

  failPending(message) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new SmokeTerminalError("CDP_CLOSED", message));
    }
    this.pending.clear();
  }

  async evaluate(expression) {
    const id = this.nextId++;
    const response = await new Promise((resolveRequest, rejectRequest) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        rejectRequest(new SmokeTerminalError("CDP_TIMEOUT", "Chrome DevTools state read timed out."));
      }, CDP_REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve: resolveRequest, reject: rejectRequest, timer });
      this.socket.send(
        JSON.stringify({
          id,
          method: "Runtime.evaluate",
          params: { expression, returnByValue: true, awaitPromise: false },
        }),
      );
    });

    if (response?.exceptionDetails) {
      throw new SmokeTerminalError("CDP_EVALUATE", "Chrome DevTools state evaluation raised an exception.");
    }
    return response?.result?.value;
  }

  close() {
    try {
      this.socket.close();
    } catch {
      // Best-effort harness cleanup only.
    }
  }
}

async function connectCdp(webSocketUrl, deadline) {
  const remaining = Math.max(1, Math.min(CDP_REQUEST_TIMEOUT_MS, deadline - Date.now()));
  return await new Promise((resolveSocket, rejectSocket) => {
    const socket = new WebSocket(webSocketUrl);
    const timer = setTimeout(() => {
      try {
        socket.close();
      } catch {
        // Best-effort cleanup.
      }
      rejectSocket(new SmokeTerminalError("CDP_TIMEOUT", "Chrome DevTools connection timed out."));
    }, remaining);
    socket.addEventListener(
      "open",
      () => {
        clearTimeout(timer);
        resolveSocket(new CdpClient(socket));
      },
      { once: true },
    );
    socket.addEventListener(
      "error",
      () => {
        clearTimeout(timer);
        rejectSocket(new SmokeTerminalError("CDP_ERROR", "Chrome DevTools connection failed."));
      },
      { once: true },
    );
  });
}

const SMOKE_STATE_EXPRESSION = `(() => {
  const dataset = document.body?.dataset ?? {};
  return {
    status: dataset.status ?? "",
    stage: dataset.stage ?? "",
    securityStatus: dataset.securityStatus ?? "",
    qrStatus: dataset.qrStatus ?? "",
    denseQrStatus: dataset.denseQrStatus ?? "",
    argon2Status: dataset.argon2Status ?? "",
  };
})()`;

function stopChrome(chrome) {
  if (!chrome?.pid || chrome.exitCode !== null) return;
  if (process.platform === "win32") {
    spawnSync("taskkill.exe", ["/PID", String(chrome.pid), "/T", "/F"], { stdio: "ignore" });
    return;
  }
  chrome.kill("SIGKILL");
}

export async function runWindowsChromeSmoke({ chromePath, smokeUrl, timeoutMs = DEFAULT_TIMEOUT_MS }) {
  if (!chromePath || !smokeUrl) {
    throw new SmokeTerminalError("ARGUMENT", "Chrome path and smoke URL are required.");
  }
  const profileDir = await mkdtemp(join(tmpdir(), "m5auth-chrome-smoke-"));
  const startedAt = Date.now();
  const deadline = startedAt + timeoutMs;
  let chrome;
  let cdp;

  try {
    chrome = spawn(
      chromePath,
      [
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--remote-debugging-port=0",
        `--user-data-dir=${profileDir}`,
        smokeUrl,
      ],
      { stdio: "ignore", windowsHide: true },
    );
    chrome.on("error", () => {
      // The polling path below observes the missing DevTools endpoint and fails closed.
    });

    const port = await waitForDevToolsPort(profileDir, deadline);
    const webSocketUrl = await waitForPageTarget(port, smokeUrl, deadline);
    cdp = await connectCdp(webSocketUrl, deadline);
    const elapsed = Date.now() - startedAt;
    const remaining = timeoutMs - elapsed;
    if (remaining <= 0) {
      throw timeoutError(timeoutMs, normalizeState({}));
    }

    const state = await waitForTerminalState({
      timeoutMs: remaining,
      pollIntervalMs: DEFAULT_POLL_INTERVAL_MS,
      readState: async () => {
        if (chrome.exitCode !== null) {
          throw new SmokeTerminalError("CHROME_EXIT", "Chrome exited before browser smoke reached a terminal state.");
        }
        return await cdp.evaluate(SMOKE_STATE_EXPRESSION);
      },
    });
    assertWindowsSmokePass(state);
    return state;
  } finally {
    cdp?.close();
    stopChrome(chrome);
    await rm(profileDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  }
}

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!argument?.startsWith("--")) continue;
    const name = argument.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new SmokeTerminalError("ARGUMENT", `Missing value for --${safeDiagnosticValue(name, "argument")}.`);
    }
    values.set(name, value);
    index += 1;
  }
  const timeoutValue = values.get("timeout-ms");
  const timeoutMs = timeoutValue === undefined ? DEFAULT_TIMEOUT_MS : Number(timeoutValue);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new SmokeTerminalError("ARGUMENT", "--timeout-ms must be a positive finite number.");
  }
  return {
    chromePath: values.get("chrome"),
    smokeUrl: values.get("url"),
    timeoutMs,
  };
}

async function main() {
  try {
    const options = parseArguments(process.argv.slice(2));
    await runWindowsChromeSmoke(options);
    console.log("[browser-smoke] terminal PASS reached with QR, dense QR, Argon2, and security stages complete.");
  } catch (error) {
    const message =
      error instanceof SmokeTerminalError
        ? error.message
        : "Windows Chrome browser smoke harness failed before a terminal state.";
    console.error(`[browser-smoke] ${message}`);
    process.exitCode = 1;
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === invokedPath) {
  await main();
}
