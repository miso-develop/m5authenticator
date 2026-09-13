import { SerialSession } from "./serial";
import type { CanonicalWireOperation } from "./canonical-protocol-v2";
import type { SessionWireOperation } from "./security/session-protocol-v2";

const PANEL_ID = "issue86-production-trace";
const MAX_TRACE_LINES = 64;
const TRACED_CANONICAL_OPERATIONS = new Set<CanonicalWireOperation>(["hello", "vault.install"]);
const SAFE_SESSION_STATES = new Set(["awaiting_presence", "confirmed", "rejected", "expired", "cancelled"]);

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

const traceLines: string[] = [
  "Issue #86 measurement-only Web trace",
  "Logs only operation names, elapsed milliseconds, sanitized session state/errors, and transport close.",
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
  appendTrace(`→ ${op}`);
  try {
    const result = await originalRequestV2.call(this, op, params);
    if (op === "session.status") {
      appendTrace(`← session.status state=${sanitizeSessionState(result.state)} ${elapsedMs(started)}ms`);
    } else {
      appendTrace(`← ${op} ok ${elapsedMs(started)}ms`);
    }
    return result;
  } catch (error) {
    appendTrace(`× ${op} ${sanitizedTraceError(error)} ${elapsedMs(started)}ms`);
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
  appendTrace(`→ ${op}`);
  try {
    const result = await originalCanonical.call(this, op, params);
    appendTrace(`← ${op} ok ${elapsedMs(started)}ms`);
    return result;
  } catch (error) {
    appendTrace(`× ${op} ${sanitizedTraceError(error)} ${elapsedMs(started)}ms`);
    throw error;
  }
};

const originalClose = SerialSession.prototype.close;
SerialSession.prototype.close = async function issue86TracedClose(): Promise<void> {
  appendTrace("• transport.close");
  await originalClose.call(this);
};

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => { ensurePanel(); }, { once: true });
  } else {
    ensurePanel();
  }
}
