export const SESSION_PROTOCOL_VERSION = 2 as const;
export const SESSION_TRANSCRIPT_VERSION = 1 as const;
export const SESSION_VAULT_ID_BYTES = 16;
export const SESSION_REGISTRATION_ID_BYTES = 16;
export const SESSION_MAX_DEVICE_ID_BYTES = 64;
export const SESSION_ATTEMPT_ID_BYTES = 16;
export const SESSION_DEVICE_CHALLENGE_BYTES = 32;
export const SESSION_P256_PUBLIC_KEY_BYTES = 65;
export const SESSION_NONCE_BYTES = 12;
export const SESSION_TAG_BYTES = 16;
export const SESSION_VMK_BYTES = 32;
export const SESSION_SIGNATURE_BYTES = 64;
export const SESSION_ATTEMPT_TTL_MS = 30_000;
export const SESSION_MAX_WIRE_RESPONSE_CHARS = 4096;

const textEncoder = new TextEncoder();
const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const OPERATION_BYTE = {
  trusted_browser_unlock: 1,
  initial_provisioning: 2,
  recovery: 3,
  browser_replacement: 4,
  vmk_rekey: 5,
} as const;

export type SessionOperation = keyof typeof OPERATION_BYTE;
export type SessionWireOperation =
  | "session.begin"
  | "session.authorize"
  | "session.status"
  | "session.complete"
  | "session.cancel";

export interface SessionTranscriptInput {
  operation: SessionOperation;
  deviceId: string;
  vaultId: Uint8Array;
  expectedGeneration: bigint;
  registrationId: Uint8Array;
  registrationEpoch: number;
  attemptId: Uint8Array;
  challenge: Uint8Array;
  deviceEphemeralPublicKey: Uint8Array;
  webEphemeralPublicKey: Uint8Array;
  currentBrkPublicKey: Uint8Array;
  proposedBrkPublicKey: Uint8Array;
}

export interface SessionBeginData {
  attemptId: Uint8Array;
  challenge: Uint8Array;
  devicePublicKeyRaw: Uint8Array;
  expiresInMs: number;
}

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function assertBytes(value: Uint8Array, expectedLength: number, field: string): void {
  assert(value.length === expectedLength, `${field} must be ${expectedLength} bytes`);
}

function isZero(value: Uint8Array): boolean {
  let combined = 0;
  for (const byte of value) combined |= byte;
  return combined === 0;
}

function assertOptionalP256Identity(value: Uint8Array, field: string): void {
  assertBytes(value, SESSION_P256_PUBLIC_KEY_BYTES, field);
  assert(isZero(value) || value[0] === 0x04, `${field} must be zero or an uncompressed P-256 public key`);
}

function appendBytes(output: number[], value: Uint8Array): void {
  for (const byte of value) output.push(byte);
}

function appendU32(output: number[], value: number): void {
  output.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function appendU64(output: number[], value: bigint): void {
  for (let shift = 56n; shift >= 0n; shift -= 8n) {
    output.push(Number((value >> shift) & 0xffn));
  }
}

export function encodeSessionTranscript(input: SessionTranscriptInput): Uint8Array {
  const deviceId = textEncoder.encode(input.deviceId);
  assert(deviceId.length > 0 && deviceId.length <= SESSION_MAX_DEVICE_ID_BYTES, "Device ID has invalid length");
  assertBytes(input.vaultId, SESSION_VAULT_ID_BYTES, "vault_id");
  assert(input.expectedGeneration >= 0n && input.expectedGeneration <= 0xffffffffffffffffn, "expected generation is out of range");
  assertBytes(input.registrationId, SESSION_REGISTRATION_ID_BYTES, "registration id");
  assert(Number.isSafeInteger(input.registrationEpoch) && input.registrationEpoch >= 0 && input.registrationEpoch <= 0xffffffff,
    "registration epoch is out of range");
  assertBytes(input.attemptId, SESSION_ATTEMPT_ID_BYTES, "attempt id");
  assertBytes(input.challenge, SESSION_DEVICE_CHALLENGE_BYTES, "Device challenge");
  assertBytes(input.deviceEphemeralPublicKey, SESSION_P256_PUBLIC_KEY_BYTES, "Device ephemeral public key");
  assertBytes(input.webEphemeralPublicKey, SESSION_P256_PUBLIC_KEY_BYTES, "Web ephemeral public key");
  assert(input.deviceEphemeralPublicKey[0] === 0x04, "Device ephemeral public key must be uncompressed P-256");
  assert(input.webEphemeralPublicKey[0] === 0x04, "Web ephemeral public key must be uncompressed P-256");
  assertOptionalP256Identity(input.currentBrkPublicKey, "current BRK public key");
  assertOptionalP256Identity(input.proposedBrkPublicKey, "proposed BRK public key");

  switch (input.operation) {
    case "trusted_browser_unlock":
      assert(!isZero(input.currentBrkPublicKey) && input.registrationEpoch > 0,
        "Trusted Browser unlock requires an active registration");
      break;
    case "initial_provisioning":
      assert(isZero(input.currentBrkPublicKey) && !isZero(input.proposedBrkPublicKey) && input.registrationEpoch === 0,
        "Initial provisioning requires only a proposed BRK");
      break;
    case "recovery":
    case "browser_replacement":
      assert(!isZero(input.proposedBrkPublicKey), "Recovery/replacement requires a proposed BRK");
      break;
    case "vmk_rekey":
      assert(!isZero(input.currentBrkPublicKey) && input.registrationEpoch > 0,
        "VMK re-key requires an active registration");
      break;
  }

  const output: number[] = [0x4d, 0x35, 0x41, 0x53, SESSION_TRANSCRIPT_VERSION, SESSION_PROTOCOL_VERSION,
    OPERATION_BYTE[input.operation], deviceId.length];
  appendBytes(output, deviceId);
  appendBytes(output, input.vaultId);
  appendU64(output, input.expectedGeneration);
  appendBytes(output, input.registrationId);
  appendU32(output, input.registrationEpoch);
  appendBytes(output, input.attemptId);
  appendBytes(output, input.challenge);
  appendBytes(output, input.deviceEphemeralPublicKey);
  appendBytes(output, input.webEphemeralPublicKey);
  appendBytes(output, input.currentBrkPublicKey);
  appendBytes(output, input.proposedBrkPublicKey);
  return Uint8Array.from(output);
}

export function encodeBase64UrlCanonical(value: Uint8Array): string {
  let output = "";
  let index = 0;
  while (index + 3 <= value.length) {
    const a = value[index] ?? 0;
    const b = value[index + 1] ?? 0;
    const c = value[index + 2] ?? 0;
    const bits = (a << 16) | (b << 8) | c;
    output += BASE64URL_ALPHABET[(bits >>> 18) & 0x3f] ?? "";
    output += BASE64URL_ALPHABET[(bits >>> 12) & 0x3f] ?? "";
    output += BASE64URL_ALPHABET[(bits >>> 6) & 0x3f] ?? "";
    output += BASE64URL_ALPHABET[bits & 0x3f] ?? "";
    index += 3;
  }
  const remaining = value.length - index;
  if (remaining === 1) {
    const bits = (value[index] ?? 0) << 16;
    output += BASE64URL_ALPHABET[(bits >>> 18) & 0x3f] ?? "";
    output += BASE64URL_ALPHABET[(bits >>> 12) & 0x3f] ?? "";
  } else if (remaining === 2) {
    const bits = ((value[index] ?? 0) << 16) | ((value[index + 1] ?? 0) << 8);
    output += BASE64URL_ALPHABET[(bits >>> 18) & 0x3f] ?? "";
    output += BASE64URL_ALPHABET[(bits >>> 12) & 0x3f] ?? "";
    output += BASE64URL_ALPHABET[(bits >>> 6) & 0x3f] ?? "";
  }
  return output;
}

function decodeBase64UrlChar(value: string): number {
  const index = BASE64URL_ALPHABET.indexOf(value);
  return index;
}

export function decodeBase64UrlCanonical(value: string, expectedLength?: number): Uint8Array {
  assert(value.length % 4 !== 1, "Invalid base64url length");
  const output: number[] = [];
  let accumulator = 0;
  let bits = 0;
  for (const char of value) {
    const decoded = decodeBase64UrlChar(char);
    assert(decoded >= 0, "Invalid base64url character");
    accumulator = ((accumulator << 6) | decoded) >>> 0;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output.push((accumulator >>> bits) & 0xff);
    }
  }
  if (bits > 0) {
    assert((accumulator & ((1 << bits) - 1)) === 0, "Non-canonical base64url trailing bits");
  }
  const decoded = Uint8Array.from(output);
  assert(encodeBase64UrlCanonical(decoded) === value, "Non-canonical base64url encoding");
  if (expectedLength !== undefined) assertBytes(decoded, expectedLength, "decoded base64url field");
  return decoded;
}

function assertRequestId(id: number): void {
  assert(Number.isSafeInteger(id) && id >= 0, "Invalid request id");
}

function isSessionWireOperation(value: string): value is SessionWireOperation {
  return value === "session.begin" || value === "session.authorize" || value === "session.status" ||
    value === "session.complete" || value === "session.cancel";
}

export function buildSessionV2Request(id: number, op: SessionWireOperation, params: Record<string, unknown> = {}): string {
  assertRequestId(id);
  assert(isSessionWireOperation(op), "Invalid Protocol v2 session operation");
  return JSON.stringify({ v: SESSION_PROTOCOL_VERSION, id, op, params }) + "\n";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export class SessionProtocolV2Error extends Error {
  public readonly code: string;

  public constructor(code: string) {
    super(`Device rejected Protocol v2 session request: ${code}`);
    this.name = "SessionProtocolV2Error";
    this.code = code;
  }
}

export function parseSessionV2Response(raw: string, expectedId: number): Record<string, unknown> {
  assertRequestId(expectedId);
  assert(raw.length <= SESSION_MAX_WIRE_RESPONSE_CHARS, "Protocol v2 response is too large");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Device returned invalid Protocol v2 JSON");
  }
  assert(isRecord(parsed), "Device returned invalid Protocol v2 response");
  assert(parsed.v === SESSION_PROTOCOL_VERSION, "Unsupported Protocol v2 response version");
  assert(parsed.id === expectedId, "Protocol v2 response id mismatch");
  if (parsed.ok === false) {
    assert(isRecord(parsed.error) && typeof parsed.error.code === "string" && parsed.error.code.length > 0,
      "Device returned invalid Protocol v2 error response");
    throw new SessionProtocolV2Error(parsed.error.code);
  }
  assert(parsed.ok === true && isRecord(parsed.data), "Device returned invalid Protocol v2 response");
  return parsed.data;
}

export function parseSessionBeginData(data: Record<string, unknown>): SessionBeginData {
  assert(typeof data.attempt_id === "string" && typeof data.challenge === "string" &&
    typeof data.device_public_key === "string", "Device returned invalid session begin data");
  assert(typeof data.expires_in_ms === "number" && Number.isSafeInteger(data.expires_in_ms) &&
    data.expires_in_ms > 0 && data.expires_in_ms <= SESSION_ATTEMPT_TTL_MS,
    "Device returned invalid session expiry");
  return {
    attemptId: decodeBase64UrlCanonical(data.attempt_id, SESSION_ATTEMPT_ID_BYTES),
    challenge: decodeBase64UrlCanonical(data.challenge, SESSION_DEVICE_CHALLENGE_BYTES),
    devicePublicKeyRaw: decodeBase64UrlCanonical(data.device_public_key, SESSION_P256_PUBLIC_KEY_BYTES),
    expiresInMs: data.expires_in_ms,
  };
}
