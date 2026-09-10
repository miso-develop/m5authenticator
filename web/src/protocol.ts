export const PROTOCOL_VERSION = 1 as const;
export const STORAGE_SCHEMA_VERSION = 1 as const;
export const FIRMWARE_COMPATIBILITY = "0.1.x" as const;

export type TimeState = "not_synced" | "ready" | "stale";
export type TimeSource = "none" | "ntp" | "usb";

export interface TimeStatus {
  time_state: TimeState;
  time_source: TimeSource;
  last_sync: number | null;
  time_age_seconds: number | null;
  time_resync_due: boolean;
}

export interface HelloData extends TimeStatus {
  device: string;
  firmware: string;
  protocol: number;
  storage_schema: number;
  build_commit: string;
  security_profile: string;
  storage_ready: boolean;
  production_release_allowed: boolean;
  storage_status?: string;
}

export interface AccountMetadata {
  id: number;
  order: number;
  issuer: string;
  account: string;
  display_name: string;
}

export interface AccountsData {
  count: number;
  accounts: AccountMetadata[];
}

export interface WifiStatusData {
  configured: boolean;
  ssid: string;
}

interface ProtocolResponse {
  v: unknown;
  id: unknown;
  ok: unknown;
  data?: unknown;
  error?: unknown;
}

export class DeviceProtocolError extends Error {
  public readonly code: string;

  public constructor(code: string) {
    super(`Device rejected request: ${code}`);
    this.name = "DeviceProtocolError";
    this.code = code;
  }
}

export function buildRequest(id: number, op: string, params: Record<string, unknown> = {}): string {
  validateRequestId(id);
  if (!op || op.length > 64) throw new Error("Invalid operation");
  return JSON.stringify({ v: PROTOCOL_VERSION, id, op, params }) + "\n";
}

export function buildHelloRequest(id: number): string {
  return buildRequest(id, "hello");
}

export function parseResponseData(raw: string, expectedId: number): Record<string, unknown> {
  validateRequestId(expectedId);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Device returned invalid JSON");
  }
  if (!isRecord(parsed)) throw new Error("Device returned invalid response");

  const response = parsed as unknown as ProtocolResponse;
  if (response.v !== PROTOCOL_VERSION) throw new Error("Unsupported protocol version");
  if (response.id !== expectedId) throw new Error("Response id mismatch");
  if (response.ok === false) {
    const error = response.error;
    if (!isRecord(error) || typeof error.code !== "string" || error.code.length === 0) {
      throw new Error("Device returned invalid error response");
    }
    throw new DeviceProtocolError(error.code);
  }
  if (response.ok !== true || !isRecord(response.data)) throw new Error("Device returned invalid response");
  return response.data;
}

export function parseHelloResponse(raw: string, expectedId: number): HelloData {
  return parseHelloData(parseResponseData(raw, expectedId));
}

export function parseHelloData(data: Record<string, unknown>): HelloData {
  if (
    typeof data.device !== "string" ||
    typeof data.firmware !== "string" ||
    data.protocol !== PROTOCOL_VERSION ||
    typeof data.storage_schema !== "number" || !Number.isSafeInteger(data.storage_schema) ||
    typeof data.build_commit !== "string" ||
    typeof data.security_profile !== "string" ||
    typeof data.storage_ready !== "boolean" ||
    typeof data.production_release_allowed !== "boolean"
  ) {
    throw new Error("Device returned incompatible metadata");
  }

  const time = parseTimeStatus(data);
  const storageStatus = data.storage_status;
  if (storageStatus !== undefined && typeof storageStatus !== "string") {
    throw new Error("Device returned invalid storage status");
  }
  return {
    device: data.device,
    firmware: data.firmware,
    protocol: data.protocol,
    storage_schema: data.storage_schema,
    build_commit: data.build_commit,
    security_profile: data.security_profile,
    storage_ready: data.storage_ready,
    production_release_allowed: data.production_release_allowed,
    ...(typeof storageStatus === "string" ? { storage_status: storageStatus } : {}),
    ...time,
  };
}

export function parseTimeStatus(data: Record<string, unknown>): TimeStatus {
  if (
    !isTimeState(data.time_state) ||
    !isTimeSource(data.time_source) ||
    typeof data.time_resync_due !== "boolean" ||
    !isNullableSafeInteger(data.last_sync) ||
    !isNullableSafeInteger(data.time_age_seconds)
  ) {
    throw new Error("Device returned invalid time status");
  }
  return {
    time_state: data.time_state,
    time_source: data.time_source,
    last_sync: data.last_sync,
    time_age_seconds: data.time_age_seconds,
    time_resync_due: data.time_resync_due,
  };
}

export function parseAccountsData(data: Record<string, unknown>): AccountsData {
  if (typeof data.count !== "number" || !Number.isSafeInteger(data.count) || !Array.isArray(data.accounts)) {
    throw new Error("Device returned invalid account metadata");
  }
  const accounts = data.accounts.map((value) => {
    if (
      !isRecord(value) ||
      typeof value.id !== "number" || !Number.isSafeInteger(value.id) || value.id <= 0 ||
      typeof value.order !== "number" || !Number.isSafeInteger(value.order) || value.order < 0 ||
      typeof value.issuer !== "string" ||
      typeof value.account !== "string" ||
      typeof value.display_name !== "string"
    ) {
      throw new Error("Device returned invalid account metadata");
    }
    return {
      id: value.id,
      order: value.order,
      issuer: value.issuer,
      account: value.account,
      display_name: value.display_name,
    } satisfies AccountMetadata;
  });
  if (data.count !== accounts.length || accounts.length > 32) {
    throw new Error("Device returned inconsistent account metadata");
  }
  accounts.sort((left, right) => left.order - right.order);
  return { count: accounts.length, accounts };
}

export function parseWifiStatusData(data: Record<string, unknown>): WifiStatusData {
  if (typeof data.configured !== "boolean" || typeof data.ssid !== "string") {
    throw new Error("Device returned invalid Wi-Fi status");
  }
  return { configured: data.configured, ssid: data.ssid };
}

function validateRequestId(id: number): void {
  if (!Number.isSafeInteger(id) || id < 0) throw new Error("Invalid request id");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTimeState(value: unknown): value is TimeState {
  return value === "not_synced" || value === "ready" || value === "stale";
}

function isTimeSource(value: unknown): value is TimeSource {
  return value === "none" || value === "ntp" || value === "usb";
}

function isNullableSafeInteger(value: unknown): value is number | null {
  return value === null || (typeof value === "number" && Number.isSafeInteger(value) && value >= 0);
}
