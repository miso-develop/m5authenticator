import {
  decodeBase64UrlCanonical,
  encodeBase64UrlCanonical,
  SESSION_P256_PUBLIC_KEY_BYTES,
  SESSION_REGISTRATION_ID_BYTES,
  SESSION_VAULT_ID_BYTES,
} from "./security/session-protocol-v2";
import type { EncryptedVaultEnvelope } from "./security/vault-crypto";

export const CANONICAL_PROTOCOL_VERSION = 2 as const;
export const CANONICAL_STORAGE_SCHEMA_VERSION = 2 as const;
export const CANONICAL_VAULT_FORMAT_VERSION = 1 as const;

export type CanonicalWireOperation =
  | "hello"
  | "vault.install"
  | "vault.update"
  | "vault.rekey"
  | "time.status"
  | "time.sync"
  | "device.lock"
  | "factory_reset";

export type DeviceRuntimeState =
  | "unprovisioned"
  | "reprovision_required"
  | "locked"
  | "unlocked"
  | "error";

export interface CanonicalHelloData {
  device: string;
  deviceId: string;
  firmware: string;
  protocol: 2;
  storageSchema: 2;
  vaultFormat: 1;
  buildCommit: string;
  state: DeviceRuntimeState;
  storageReady: boolean;
  vaultPresent: boolean;
  vaultId: Uint8Array | null;
  generation: bigint;
  registrationPresent: boolean;
  registrationId: Uint8Array | null;
  registrationEpoch: number;
  brkPublicKey: Uint8Array | null;
}

export interface CanonicalTimeStatus {
  readiness: "not_synced" | "ready" | "stale";
  source: "none" | "ntp" | "usb";
  lastSyncUnixSeconds: bigint;
  ageSeconds: number;
  resyncDue: boolean;
}

export class CanonicalProtocolV2Error extends Error {
  public readonly code: string;

  public constructor(code: string) {
    super(`Device rejected Protocol v2 request: ${code}`);
    this.name = "CanonicalProtocolV2Error";
    this.code = code;
  }
}

export function buildCanonicalV2Request(
  id: number,
  op: CanonicalWireOperation,
  params: Record<string, unknown> = {},
): string {
  if (!Number.isSafeInteger(id) || id < 0) throw new Error("Invalid request id");
  return JSON.stringify({ v: CANONICAL_PROTOCOL_VERSION, id, op, params }) + "\n";
}

export function parseCanonicalV2Response(
  raw: string,
  expectedId: number,
): Record<string, unknown> {
  if (!Number.isSafeInteger(expectedId) || expectedId < 0) throw new Error("Invalid request id");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error("Device returned invalid JSON");
  }
  if (!isRecord(parsed)) throw new Error("Device returned invalid response");
  if (parsed.v !== CANONICAL_PROTOCOL_VERSION) throw new Error("Unsupported protocol version");
  if (parsed.id !== expectedId) throw new Error("Response id mismatch");
  if (parsed.ok === false) {
    if (!isRecord(parsed.error) || typeof parsed.error.code !== "string" || parsed.error.code.length === 0) {
      throw new Error("Device returned invalid error response");
    }
    throw new CanonicalProtocolV2Error(parsed.error.code);
  }
  if (parsed.ok !== true || !isRecord(parsed.data)) throw new Error("Device returned invalid response");
  return parsed.data;
}

export function parseCanonicalHelloData(data: Record<string, unknown>): CanonicalHelloData {
  if (
    typeof data.device !== "string" || data.device.length === 0 ||
    typeof data.device_id !== "string" || data.device_id.length === 0 || data.device_id.length > 128 ||
    typeof data.firmware !== "string" ||
    data.protocol !== CANONICAL_PROTOCOL_VERSION ||
    data.storage_schema !== CANONICAL_STORAGE_SCHEMA_VERSION ||
    data.vault_format !== CANONICAL_VAULT_FORMAT_VERSION ||
    typeof data.build_commit !== "string" ||
    !isRuntimeState(data.state) ||
    typeof data.storage_ready !== "boolean" ||
    typeof data.vault_present !== "boolean" ||
    typeof data.registration_present !== "boolean" ||
    typeof data.registration_epoch !== "number" ||
    !Number.isSafeInteger(data.registration_epoch) || data.registration_epoch < 0
  ) {
    throw new Error("Device returned incompatible canonical metadata");
  }

  const generation = parseU64Decimal(data.generation, "generation");
  let vaultId: Uint8Array | null = null;
  if (data.vault_present) {
    vaultId = decodeFixed(data.vault_id, SESSION_VAULT_ID_BYTES, "vault_id");
    if (generation === 0n) throw new Error("Provisioned Device generation must be positive");
  } else if (data.vault_id !== null || generation !== 0n) {
    throw new Error("Unprovisioned Device returned Vault metadata");
  }

  let registrationId: Uint8Array | null = null;
  let brkPublicKey: Uint8Array | null = null;
  if (data.registration_present) {
    registrationId = decodeFixed(data.registration_id, SESSION_REGISTRATION_ID_BYTES, "registration_id");
    brkPublicKey = decodeFixed(data.brk_public_key, SESSION_P256_PUBLIC_KEY_BYTES, "brk_public_key");
    if (data.registration_epoch < 1) throw new Error("Active registration epoch must be positive");
  } else if (
    data.registration_id !== null || data.brk_public_key !== null || data.registration_epoch !== 0
  ) {
    throw new Error("Unregistered Device returned registration metadata");
  }

  if (data.vault_present !== data.registration_present) {
    throw new Error("Device returned a partial Vault/registration security state");
  }

  return {
    device: data.device,
    deviceId: data.device_id,
    firmware: data.firmware,
    protocol: CANONICAL_PROTOCOL_VERSION,
    storageSchema: CANONICAL_STORAGE_SCHEMA_VERSION,
    vaultFormat: CANONICAL_VAULT_FORMAT_VERSION,
    buildCommit: data.build_commit,
    state: data.state,
    storageReady: data.storage_ready,
    vaultPresent: data.vault_present,
    vaultId,
    generation,
    registrationPresent: data.registration_present,
    registrationId,
    registrationEpoch: data.registration_epoch,
    brkPublicKey,
  };
}

export function parseCanonicalTimeStatus(data: Record<string, unknown>): CanonicalTimeStatus {
  if (
    !isReadiness(data.readiness) ||
    !isTimeSource(data.source) ||
    typeof data.age_seconds !== "number" || !Number.isSafeInteger(data.age_seconds) || data.age_seconds < 0 ||
    typeof data.resync_due !== "boolean"
  ) {
    throw new Error("Device returned invalid trusted-time status");
  }
  return {
    readiness: data.readiness,
    source: data.source,
    lastSyncUnixSeconds: parseU64Decimal(data.last_sync_unix_seconds, "last_sync_unix_seconds"),
    ageSeconds: data.age_seconds,
    resyncDue: data.resync_due,
  };
}

export function encryptedVaultParams(envelope: EncryptedVaultEnvelope): Record<string, unknown> {
  if (
    envelope.vaultFormatVersion !== CANONICAL_VAULT_FORMAT_VERSION ||
    envelope.storageSchemaVersion !== CANONICAL_STORAGE_SCHEMA_VERSION ||
    envelope.vaultId.length !== SESSION_VAULT_ID_BYTES ||
    envelope.nonce.length !== 12 || envelope.tag.length !== 16 ||
    envelope.ciphertext.length === 0 || envelope.ciphertextLength !== envelope.ciphertext.length ||
    envelope.generation < 1n || envelope.generation > 0xffff_ffff_ffff_ffffn
  ) {
    throw new Error("Invalid canonical encrypted Vault envelope");
  }
  return {
    vault_format_version: envelope.vaultFormatVersion,
    storage_schema_version: envelope.storageSchemaVersion,
    vault_id: encodeBase64UrlCanonical(envelope.vaultId),
    generation: envelope.generation.toString(10),
    nonce: encodeBase64UrlCanonical(envelope.nonce),
    ciphertext: encodeBase64UrlCanonical(envelope.ciphertext),
    tag: encodeBase64UrlCanonical(envelope.tag),
    ciphertext_length: envelope.ciphertextLength,
  };
}

function decodeFixed(value: unknown, length: number, field: string): Uint8Array {
  if (typeof value !== "string") throw new Error(`Device returned invalid ${field}`);
  const decoded = decodeBase64UrlCanonical(value, length, field);
  if (decoded.length !== length) throw new Error(`Device returned invalid ${field}`);
  return decoded;
}

function parseU64Decimal(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(value)) {
    throw new Error(`Device returned invalid ${field}`);
  }
  const parsed = BigInt(value);
  if (parsed > 0xffff_ffff_ffff_ffffn) throw new Error(`Device returned invalid ${field}`);
  return parsed;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isRuntimeState(value: unknown): value is DeviceRuntimeState {
  return value === "unprovisioned" || value === "reprovision_required" || value === "locked" ||
    value === "unlocked" || value === "error";
}

function isReadiness(value: unknown): value is CanonicalTimeStatus["readiness"] {
  return value === "not_synced" || value === "ready" || value === "stale";
}

function isTimeSource(value: unknown): value is CanonicalTimeStatus["source"] {
  return value === "none" || value === "ntp" || value === "usb";
}
