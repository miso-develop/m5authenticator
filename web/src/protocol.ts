export const PROTOCOL_VERSION = 1 as const;
export const STORAGE_SCHEMA_VERSION = 1 as const;
export const FIRMWARE_COMPATIBILITY = "0.1.x" as const;

export interface HelloData {
  device: string;
  firmware: string;
  protocol: number;
  storage_schema: number;
  build_commit: string;
}

interface ProtocolResponse {
  v: unknown;
  id: unknown;
  ok: unknown;
  data?: unknown;
  error?: unknown;
}

export function buildHelloRequest(id: number): string {
  if (!Number.isSafeInteger(id) || id < 0) {
    throw new Error("Invalid request id");
  }
  return JSON.stringify({ v: PROTOCOL_VERSION, id, op: "hello", params: {} }) + "\n";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseHelloResponse(raw: string, expectedId: number): HelloData {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Device returned invalid JSON");
  }

  if (!isRecord(parsed)) {
    throw new Error("Device returned invalid response");
  }

  const response = parsed as unknown as ProtocolResponse;
  if (response.v !== PROTOCOL_VERSION) {
    throw new Error("Unsupported protocol version");
  }
  if (response.id !== expectedId) {
    throw new Error("Response id mismatch");
  }
  if (response.ok !== true || !isRecord(response.data)) {
    throw new Error("Device rejected hello request");
  }

  const data = response.data;
  if (
    typeof data.device !== "string" ||
    typeof data.firmware !== "string" ||
    data.protocol !== PROTOCOL_VERSION ||
    typeof data.storage_schema !== "number" ||
    !Number.isSafeInteger(data.storage_schema) ||
    typeof data.build_commit !== "string"
  ) {
    throw new Error("Device returned incompatible metadata");
  }

  return {
    device: data.device,
    firmware: data.firmware,
    protocol: data.protocol,
    storage_schema: data.storage_schema,
    build_commit: data.build_commit,
  };
}
