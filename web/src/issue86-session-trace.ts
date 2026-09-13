import { SerialSession } from "./serial";
import type { SessionWireOperation } from "./security/session-protocol-v2";

const PANEL_ID = "issue86-session-trace";
const MAX_TRACE_LINES = 40;

function safeErrorLabel(error: unknown): string {
  if (!(error instanceof Error)) return "unknown error";
  const message = error.message;
  const safeMessages = [
    "Device response timed out",
    "Device disconnected before responding",
    "Device response was too large",
    "Device returned invalid Protocol v2 JSON",
    "Device returned invalid Protocol v2 response",
    "Protocol v2 response id mismatch",
    "Unsupported Protocol v2 response version",
  ];
  if (safeMessages.includes(message)) return message;
  if (message.startsWith("Device rejected Protocol v2 session request:")) return message;
  return error.name || "Error";
}

function createTracePanel(): HTMLPreElement | null {
  if (typeof document === "undefined") return null;
  const existing = document.querySelector<HTMLPreElement>(`#${PANEL_ID} pre`);
  if (existing) return existing;

  const panel = document.createElement("aside");
  panel.id = PANEL_ID;
  panel.setAttribute("aria-live", "polite");
  panel.style.position = "fixed";
  panel.style.right = "12px";
  panel.style.bottom = "12px";
  panel.style.zIndex = "2147483647";
  panel.style.width = "min(560px, calc(100vw - 24px))";
  panel.style.maxHeight = "42vh";
  panel.style.overflow = "auto";
  panel.style.padding = "12px";
  panel.style.border = "1px solid #737373";
  panel.style.borderRadius = "10px";
  panel.style.background = "#111827";
  panel.style.color = "#f9fafb";
  panel.style.boxShadow = "0 12px 32px rgba(0, 0, 0, 0.35)";
  panel.style.font = "12px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
  panel.hidden = true;

  const title = document.createElement("strong");
  title.textContent = "Issue #86 session trace (non-secret)";
  const note = document.createElement("div");
  note.textContent = "Only operation names, status states, timings, and sanitized errors are shown.";
  note.style.margin = "4px 0 8px";
  note.style.color = "#d1d5db";
  const pre = document.createElement("pre");
  pre.style.margin = "0";
  pre.style.whiteSpace = "pre-wrap";
  pre.style.overflowWrap = "anywhere";

  panel.append(title, note, pre);
  document.body.append(panel);
  return pre;
}

const traceLines: string[] = [];
let sequence = 0;

function appendTrace(message: string): void {
  const pre = createTracePanel();
  if (!pre) return;
  sequence += 1;
  traceLines.push(`${String(sequence).padStart(2, "0")} ${message}`);
  if (traceLines.length > MAX_TRACE_LINES) traceLines.splice(0, traceLines.length - MAX_TRACE_LINES);
  pre.textContent = traceLines.join("\n");
  const panel = pre.closest<HTMLElement>(`#${PANEL_ID}`);
  if (panel) panel.hidden = false;
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
    const elapsed = Math.max(0, Math.round(performance.now() - started));
    if (op === "session.status") {
      const state = typeof result.state === "string" ? result.state : "<missing-state>";
      appendTrace(`← session.status state=${state} ${elapsed}ms`);
    } else {
      appendTrace(`← ${op} ok ${elapsed}ms`);
    }
    return result;
  } catch (error) {
    const elapsed = Math.max(0, Math.round(performance.now() - started));
    appendTrace(`× ${op} ${safeErrorLabel(error)} ${elapsed}ms`);
    throw error;
  }
};
