import { SerialSession } from "./serial";
import type { CanonicalWireOperation } from "./canonical-protocol-v2";
import type { SessionWireOperation } from "./security/session-protocol-v2";

const PANEL_ID = "issue86-production-trace";
const MAX_TRACE_LINES = 64;
const TRACED_CANONICAL_OPERATIONS = new Set<CanonicalWireOperation>(["hello", "vault.install"]);
const SAFE_SESSION_STATES = new Set(["awaiting_presence", "confirmed", "rejected", "expired", "cancelled"]);

interface SerialSessionDebugView {
  pending?: unknown;
  pendingBytes?: unknown;
  pendingRead?: unknown;
  inFlight?: unknown;
  closed?: unknown;
  staleInitialHelloResponseId?: unknown;
  staleInitialHelloResponsesRemaining?: unknown;
}

export function sanitizeSessionState(value: unknown): string {
  return typeof value === "string" && SAFE_SESSION_STATES.has(value) ? value : "<invalid-state>";
}

export function sanitizedTraceError(error: unknown): string {
  if (!(error instanceof Error)) return "unknown-error";
  switch (error.message) {
    case "Device response timed out":
      return "timeout";
    case "Device disconnected before responding":
      return "disconnected-before-response";
    case "Device response was too large":
      return "response-too-large";
    case "Device is not connected":
      return "transport-closed";
    case "Another device request is already in progress":
      return "concurrent-request-rejected";
    default:
      break;
  }
  const normalized = error.message.toLowerCase();
  if (normalized.includes("id mismatch")) return "protocol-id-mismatch";
  if (normalized.includes("invalid") || normalized.includes("unsupported protocol")) {
    return "protocol-validation-error";
  }
  if (normalized.includes("device rejected") || normalized.includes("session rejected") ||
      normalized.includes("session expired") || normalized.includes("session cancelled")) {
    return "device-session-rejection";
  }
  return "sanitized-error";
}

function booleanLabel(value: boolean): string {
  return value ? "yes" : "no";
}

function boundedNonNegativeInteger(value: unknown): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : -1;
}

function transportState(session: SerialSession): string {
  // Measurement-only branch: TypeScript `private` fields are read as non-secret
  // transport metadata. No request/response body, IDs, Device identity, or
  // credential/key material is accessed or rendered.
  const internal = session as unknown as SerialSessionDebugView;
  const pending = typeof internal.pending === "string" ? internal.pending : "";
  const pendingBytes = boundedNonNegativeInteger(internal.pendingBytes);
  const staleRemaining = boundedNonNegativeInteger(internal.staleInitialHelloResponsesRemaining);
  return [
    `closed=${booleanLabel(internal.closed === true)}`,
    `in_flight=${booleanLabel(internal.inFlight === true)}`,
    `pending_request=${internal.inFlight === true ? 1 : 0}`,
    `pending_read=${booleanLabel(internal.pendingRead !== undefined)}`,
    `pending_bytes=${pendingBytes}`,
    `pending_newline=${booleanLabel(pending.includes("\n"))}`,
    `stale_hello_remaining=${staleRemaining}`,
    `stale_hello_id_present=${booleanLabel(internal.staleInitialHelloResponseId !== undefined)}`,
  ].join(" ");
}

const traceLines: string[] = [
  "Issue #86 measurement-only Web trace",
  "Logs only operation names, elapsed milliseconds, sanitized session state/errors, and non-secret transport lifecycle state.",
];
let sequence = 0;
let panel: HTMLPreElement | null = null;

function ensurePanel(): HTMLPreElement | null {
  if (typeof document === "undefined") return null;
  if (panel?.isConnected) return panel;

  const section = document.createElement("section");
  section.id = PANEL_ID;
  section.setAttribute("aria-label", "Issue 86 measurement trace");
  section.style.maxWidth = "960px";
  section.style.margin = "24px auto";
  section.style.padding = "16px";
  section.style.border = "1px solid #737373";
  section.style.borderRadius = "12px";
  section.style.background = "#f5f5f5";

  const heading = document.createElement("h2");
  heading.textContent = "Issue #86 measurement trace — do not publish secrets";
  heading.style.marginTop = "0";
  const note = document.createElement("p");
  note.textContent = "Copy only this trace block into the Human Task. It never includes request parameters, request IDs, Device ID, credential data, ciphertext, passphrases, or key material.";
  const pre = document.createElement("pre");
  pre.style.whiteSpace = "pre-wrap";
  pre.style.overflowWrap = "anywhere";
  pre.textContent = traceLines.join("\n");

  section.append(heading, note, pre);
  document.body.append(section);
  panel = pre;
  return pre;
}

function appendTrace(message: string): void {
  sequence += 1;
  traceLines.push(`${String(sequence).padStart(2, "0")} ${message}`);
  if (traceLines.length > MAX_TRACE_LINES + 2) {
    traceLines.splice(2, traceLines.length - (MAX_TRACE_LINES + 2));
  }
  const pre = ensurePanel();
  if (pre) pre.textContent = traceLines.join("\n");
}

function elapsedMs(started: number): number {
  return Math.max(0, Math.round(performance.now() - started));
}

const originalRequestV2 = SerialSession.prototype.requestV2;
SerialSession.prototype.requestV2 = async function issue86TracedRequestV2(
  op: SessionWireOperation,
  params: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const started = performance.now();
  appendTrace(`→ ${op} ${transportState(this)}`);
  try {
    const result = await originalRequestV2.call(this, op, params);
    if (op === "session.status") {
      appendTrace(`← session.status state=${sanitizeSessionState(result.state)} ${elapsedMs(started)}ms ${transportState(this)}`);
    } else {
      appendTrace(`← ${op} ok ${elapsedMs(started)}ms ${transportState(this)}`);
    }
    return result;
  } catch (error) {
    appendTrace(`× ${op} ${sanitizedTraceError(error)} ${elapsedMs(started)}ms ${transportState(this)}`);
    throw error;
  }
};

const originalCanonical = SerialSession.prototype.requestCanonicalV2;
SerialSession.prototype.requestCanonicalV2 = async function issue86TracedCanonicalRequest(
  op: CanonicalWireOperation,
  params: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  if (!TRACED_CANONICAL_OPERATIONS.has(op)) return originalCanonical.call(this, op, params);
  const started = performance.now();
  appendTrace(`→ ${op} ${transportState(this)}`);
  try {
    const result = await originalCanonical.call(this, op, params);
    appendTrace(`← ${op} ok ${elapsedMs(started)}ms ${transportState(this)}`);
    return result;
  } catch (error) {
    appendTrace(`× ${op} ${sanitizedTraceError(error)} ${elapsedMs(started)}ms ${transportState(this)}`);
    throw error;
  }
};

const originalClose = SerialSession.prototype.close;
SerialSession.prototype.close = async function issue86TracedClose(): Promise<void> {
  appendTrace(`• transport.close before ${transportState(this)}`);
  await originalClose.call(this);
  appendTrace(`• transport.close after ${transportState(this)}`);
};

if (typeof window !== "undefined") {
  // Capture phase is intentional. Production main.ts registered its normal
  // pagehide cleanup earlier, so capture lets measurement classify page
  // lifecycle before that cleanup can call transport.close().
  window.addEventListener("pagehide", () => {
    appendTrace("• lifecycle.pagehide");
  }, { capture: true });
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => { ensurePanel(); }, { once: true });
  } else {
    ensurePanel();
  }
}
