import {
  AES_GCM_KEY_BYTES,
  AES_GCM_NONCE_BYTES,
  AES_GCM_TAG_BYTES,
  RECOVERY_PACKAGE_VERSION,
  VMK_WRAP_VERSION,
  decryptVault,
  type EncryptedVaultEnvelope,
  type PassphraseWrappedVmk,
  unwrapVmkWithPassphrase,
  wrapVmkWithPassphrase,
} from "./vault-crypto";
import { VAULT_FORMAT_VERSION, VAULT_ID_BYTES, VAULT_TARGET_STORAGE_SCHEMA_VERSION } from "./vault-format";

const BROWSER_STATE_VERSION = 1;
const BUK_WRAP_VERSION = 1;
const REGISTRATION_ID_BYTES = 16;
const BRK_PUBLIC_RAW_BYTES = 65;
const RECOVERY_PACKAGE_MAX_CHARS = 2_000_000;
const DB_NAME = "m5authenticator-v1";
const DB_VERSION = 1;
const STORE_NAME = "canonical-vaults";
const textEncoder = new TextEncoder();

export const RECOVERY_PASSPHRASE_CHANGE_NOTICE =
  "Changing the Passphrase does not cryptographically revoke Recovery Packages that were already exported. Export a replacement package and delete old copies that you control.";

export type TrustedBrowserStatus = "active" | "replacement-pending";

export interface BrowserWrappedVmk {
  version: number;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

export interface TrustedBrowserRegistration {
  registrationId: Uint8Array;
  epoch: number;
  status: TrustedBrowserStatus;
  buk: CryptoKey;
  brkPrivateKey: CryptoKey;
  brkPublicKeyRaw: Uint8Array;
  wrappedVmk: BrowserWrappedVmk;
}

export interface BrowserDeviceMetadata {
  deviceId: string;
}

export interface BrowserCanonicalState {
  stateVersion: number;
  vault: EncryptedVaultEnvelope;
  recoveryWrappedVmk: PassphraseWrappedVmk;
  trustedBrowser: TrustedBrowserRegistration;
  deviceMetadata: BrowserDeviceMetadata | null;
}

interface PersistedBrowserCanonicalState extends BrowserCanonicalState {
  key: string;
}

interface RecoveryPackageJson {
  packageVersion: number;
  vault: {
    vaultFormatVersion: number;
    storageSchemaVersion: number;
    vaultId: string;
    generation: string;
    nonce: string;
    ciphertext: string;
    tag: string;
    ciphertextLength: number;
  };
  wrappedVmk: {
    packageVersion: number;
    wrapVersion: number;
    vaultFormatVersion: number;
    vaultId: string;
    kdf: {
      algorithm: "argon2id";
      version: number;
      memoryKiB: number;
      iterations: number;
      parallelism: number;
      salt: string;
      outputBytes: number;
    };
    nonce: string;
    ciphertext: string;
    tag: string;
  };
  previousRegistration: {
    registrationId: string;
    epoch: number;
  };
  deviceMetadata: BrowserDeviceMetadata | null;
}

export class GenerationConflictError extends Error {
  constructor(message = "Canonical Vault generation conflict; recovery or explicit conflict resolution is required") {
    super(message);
    this.name = "GenerationConflictError";
  }
}

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function assertLength(value: Uint8Array, expected: number, field: string): void {
  assert(value.length === expected, `${field} must be ${expected} bytes`);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) diff |= (left[index] ?? 0) ^ (right[index] ?? 0);
  return diff === 0;
}

function cloneVault(value: EncryptedVaultEnvelope): EncryptedVaultEnvelope {
  return {
    vaultFormatVersion: value.vaultFormatVersion,
    storageSchemaVersion: value.storageSchemaVersion,
    vaultId: value.vaultId.slice(),
    generation: value.generation,
    nonce: value.nonce.slice(),
    ciphertext: value.ciphertext.slice(),
    tag: value.tag.slice(),
    ciphertextLength: value.ciphertextLength,
  };
}

function cloneWrappedVmk(value: PassphraseWrappedVmk): PassphraseWrappedVmk {
  return {
    packageVersion: value.packageVersion,
    wrapVersion: value.wrapVersion,
    vaultFormatVersion: value.vaultFormatVersion,
    vaultId: value.vaultId.slice(),
    kdf: { ...value.kdf, salt: value.kdf.salt.slice() },
    nonce: value.nonce.slice(),
    ciphertext: value.ciphertext.slice(),
    tag: value.tag.slice(),
  };
}

function cloneBrowserWrappedVmk(value: BrowserWrappedVmk): BrowserWrappedVmk {
  return {
    version: value.version,
    nonce: value.nonce.slice(),
    ciphertext: value.ciphertext.slice(),
    tag: value.tag.slice(),
  };
}

function validateStateFraming(state: BrowserCanonicalState): void {
  assert(state.stateVersion === BROWSER_STATE_VERSION, `unsupported browser state version: ${state.stateVersion}`);
  assert(state.vault.vaultFormatVersion === VAULT_FORMAT_VERSION, "unsupported Vault format version");
  assert(state.vault.storageSchemaVersion === VAULT_TARGET_STORAGE_SCHEMA_VERSION, "unsupported target storage schema");
  assertLength(state.vault.vaultId, VAULT_ID_BYTES, "vaultId");
  assertLength(state.vault.nonce, AES_GCM_NONCE_BYTES, "Vault nonce");
  assertLength(state.vault.tag, AES_GCM_TAG_BYTES, "Vault tag");
  assert(state.vault.ciphertextLength === state.vault.ciphertext.length, "Vault ciphertext framing mismatch");

  const wrapped = state.recoveryWrappedVmk;
  assert(wrapped.packageVersion === RECOVERY_PACKAGE_VERSION, "unsupported Recovery Package version");
  assert(wrapped.wrapVersion === VMK_WRAP_VERSION, "unsupported VMK wrap version");
  assert(wrapped.vaultFormatVersion === VAULT_FORMAT_VERSION, "unsupported wrapped VMK Vault format");
  assertLength(wrapped.vaultId, VAULT_ID_BYTES, "wrapped VMK vaultId");
  assert(sameBytes(state.vault.vaultId, wrapped.vaultId), "Vault and wrapped VMK vault_id mismatch");
  assertLength(wrapped.nonce, AES_GCM_NONCE_BYTES, "wrapped VMK nonce");
  assertLength(wrapped.tag, AES_GCM_TAG_BYTES, "wrapped VMK tag");
  assert(wrapped.ciphertext.length === AES_GCM_KEY_BYTES, "wrapped VMK ciphertext must be 32 bytes");

  const registration = state.trustedBrowser;
  assertLength(registration.registrationId, REGISTRATION_ID_BYTES, "registrationId");
  assert(Number.isSafeInteger(registration.epoch) && registration.epoch >= 1, "registration epoch must be a positive safe integer");
  assert(registration.status === "active" || registration.status === "replacement-pending", "unsupported Trusted Browser status");
  assert(registration.buk.type === "secret", "BUK must be a secret CryptoKey");
  assert(registration.buk.extractable === false, "BUK must be non-extractable");
  assert(registration.buk.algorithm.name === "AES-GCM", "BUK must use AES-GCM");
  assert(registration.buk.usages.includes("encrypt") && registration.buk.usages.includes("decrypt"), "BUK usages are invalid");
  assert(registration.brkPrivateKey.type === "private", "BRK private key is invalid");
  assert(registration.brkPrivateKey.extractable === false, "BRK private key must be non-extractable");
  const brkAlgorithm = registration.brkPrivateKey.algorithm as EcKeyAlgorithm;
  assert(brkAlgorithm.name === "ECDSA" && brkAlgorithm.namedCurve === "P-256", "BRK must use ECDSA P-256");
  assert(registration.brkPrivateKey.usages.includes("sign"), "BRK private key must permit signing");
  assertLength(registration.brkPublicKeyRaw, BRK_PUBLIC_RAW_BYTES, "BRK public key");
  assert(registration.wrappedVmk.version === BUK_WRAP_VERSION, "unsupported BUK VMK wrap version");
  assertLength(registration.wrappedVmk.nonce, AES_GCM_NONCE_BYTES, "BUK VMK wrap nonce");
  assertLength(registration.wrappedVmk.tag, AES_GCM_TAG_BYTES, "BUK VMK wrap tag");
  assert(registration.wrappedVmk.ciphertext.length === AES_GCM_KEY_BYTES, "BUK wrapped VMK ciphertext must be 32 bytes");
  if (state.deviceMetadata !== null) assert(state.deviceMetadata.deviceId.length > 0, "deviceId must not be empty");
}

export function sanitizeBrowserCanonicalState(state: BrowserCanonicalState): BrowserCanonicalState {
  validateStateFraming(state);
  return {
    stateVersion: BROWSER_STATE_VERSION,
    vault: cloneVault(state.vault),
    recoveryWrappedVmk: cloneWrappedVmk(state.recoveryWrappedVmk),
    trustedBrowser: {
      registrationId: state.trustedBrowser.registrationId.slice(),
      epoch: state.trustedBrowser.epoch,
      status: state.trustedBrowser.status,
      buk: state.trustedBrowser.buk,
      brkPrivateKey: state.trustedBrowser.brkPrivateKey,
      brkPublicKeyRaw: state.trustedBrowser.brkPublicKeyRaw.slice(),
      wrappedVmk: cloneBrowserWrappedVmk(state.trustedBrowser.wrappedVmk),
    },
    deviceMetadata: state.deviceMetadata === null ? null : { deviceId: state.deviceMetadata.deviceId },
  };
}

function randomBytes(length: number): Uint8Array {
  const value = new Uint8Array(length);
  crypto.getRandomValues(value);
  return value;
}

function copyBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer;
}

function splitCiphertextAndTag(combined: ArrayBuffer): { ciphertext: Uint8Array; tag: Uint8Array } {
  const bytes = new Uint8Array(combined);
  assert(bytes.length >= AES_GCM_TAG_BYTES, "AES-GCM result is shorter than the tag");
  return {
    ciphertext: bytes.slice(0, bytes.length - AES_GCM_TAG_BYTES),
    tag: bytes.slice(bytes.length - AES_GCM_TAG_BYTES),
  };
}

function joinCiphertextAndTag(ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  assertLength(tag, AES_GCM_TAG_BYTES, "AES-GCM tag");
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);
  return combined;
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function buildBukWrapAad(vaultId: Uint8Array, registrationId: Uint8Array, epoch: number): Uint8Array {
  assertLength(vaultId, VAULT_ID_BYTES, "vaultId");
  assertLength(registrationId, REGISTRATION_ID_BYTES, "registrationId");
  assert(Number.isSafeInteger(epoch) && epoch >= 1, "registration epoch must be positive");
  return textEncoder.encode(`M5AUTH-BUK-WRAP1\u0000${toHex(vaultId)}:${toHex(registrationId)}:${epoch}`);
}

async function generateTrustedBrowserKeys(): Promise<{
  registrationId: Uint8Array;
  buk: CryptoKey;
  brkPrivateKey: CryptoKey;
  brkPublicKeyRaw: Uint8Array;
}> {
  const buk = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const generated = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  assert("privateKey" in generated && "publicKey" in generated, "ECDSA key generation did not return a key pair");
  const pair = generated as CryptoKeyPair;
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  assertLength(publicRaw, BRK_PUBLIC_RAW_BYTES, "BRK public key");
  assert(buk.extractable === false, "BUK generation unexpectedly produced an extractable key");
  assert(pair.privateKey.extractable === false, "BRK generation unexpectedly produced an extractable private key");
  return {
    registrationId: randomBytes(REGISTRATION_ID_BYTES),
    buk,
    brkPrivateKey: pair.privateKey,
    brkPublicKeyRaw: publicRaw,
  };
}

async function wrapVmkWithBuk(
  vmk: Uint8Array,
  buk: CryptoKey,
  vaultId: Uint8Array,
  registrationId: Uint8Array,
  epoch: number,
): Promise<BrowserWrappedVmk> {
  assertLength(vmk, AES_GCM_KEY_BYTES, "VMK");
  const nonce = randomBytes(AES_GCM_NONCE_BYTES);
  const aad = buildBukWrapAad(vaultId, registrationId, epoch);
  const combined = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: copyBuffer(nonce), additionalData: copyBuffer(aad), tagLength: 128 },
    buk,
    copyBuffer(vmk),
  );
  return { version: BUK_WRAP_VERSION, nonce, ...splitCiphertextAndTag(combined) };
}

export async function unwrapVmkForTrustedBrowser(state: BrowserCanonicalState): Promise<Uint8Array> {
  validateStateFraming(state);
  const wrapped = state.trustedBrowser.wrappedVmk;
  const aad = buildBukWrapAad(
    state.vault.vaultId,
    state.trustedBrowser.registrationId,
    state.trustedBrowser.epoch,
  );
  const combined = joinCiphertextAndTag(wrapped.ciphertext, wrapped.tag);
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: copyBuffer(wrapped.nonce), additionalData: copyBuffer(aad), tagLength: 128 },
      state.trustedBrowser.buk,
      copyBuffer(combined),
    );
    const vmk = new Uint8Array(plaintext);
    assertLength(vmk, AES_GCM_KEY_BYTES, "unwrapped VMK");
    return vmk;
  } finally {
    combined.fill(0);
  }
}

export interface CreateBrowserCanonicalStateInput {
  vault: EncryptedVaultEnvelope;
  recoveryWrappedVmk: PassphraseWrappedVmk;
  vmk: Uint8Array;
  registrationEpoch?: number;
  status?: TrustedBrowserStatus;
  deviceMetadata?: BrowserDeviceMetadata | null;
}

export async function createBrowserCanonicalState(
  input: CreateBrowserCanonicalStateInput,
): Promise<BrowserCanonicalState> {
  assertLength(input.vmk, AES_GCM_KEY_BYTES, "VMK");
  assert(sameBytes(input.vault.vaultId, input.recoveryWrappedVmk.vaultId), "Vault and recovery wrapper vault_id mismatch");
  const epoch = input.registrationEpoch ?? 1;
  const keys = await generateTrustedBrowserKeys();
  const wrappedVmk = await wrapVmkWithBuk(input.vmk, keys.buk, input.vault.vaultId, keys.registrationId, epoch);
  return sanitizeBrowserCanonicalState({
    stateVersion: BROWSER_STATE_VERSION,
    vault: input.vault,
    recoveryWrappedVmk: input.recoveryWrappedVmk,
    trustedBrowser: {
      registrationId: keys.registrationId,
      epoch,
      status: input.status ?? "active",
      buk: keys.buk,
      brkPrivateKey: keys.brkPrivateKey,
      brkPublicKeyRaw: keys.brkPublicKeyRaw,
      wrappedVmk,
    },
    deviceMetadata: input.deviceMetadata ?? null,
  });
}

export function assertCanonicalGeneration(
  state: BrowserCanonicalState,
  observed: { vaultId: Uint8Array; generation: bigint },
): void {
  if (!sameBytes(state.vault.vaultId, observed.vaultId) || state.vault.generation !== observed.generation) {
    throw new GenerationConflictError();
  }
}

function toBase64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value: unknown, field: string): Uint8Array {
  assert(typeof value === "string" && /^[A-Za-z0-9_-]*$/.test(value), `${field} is not valid base64url`);
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Error(`${field} is not valid base64url`);
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function asObject(value: unknown, field: string): Record<string, unknown> {
  assert(typeof value === "object" && value !== null && !Array.isArray(value), `${field} must be an object`);
  return value as Record<string, unknown>;
}

function asInteger(value: unknown, field: string, minimum = 0): number {
  assert(typeof value === "number" && Number.isSafeInteger(value) && value >= minimum, `${field} must be a safe integer`);
  return value;
}

function asString(value: unknown, field: string): string {
  assert(typeof value === "string", `${field} must be a string`);
  return value;
}

function parseGeneration(value: unknown): bigint {
  const encoded = asString(value, "vault.generation");
  assert(/^(0|[1-9][0-9]{0,19})$/.test(encoded), "vault.generation is invalid");
  const generation = BigInt(encoded);
  assert(generation <= 0xffff_ffff_ffff_ffffn, "vault.generation exceeds u64");
  return generation;
}

export function exportRecoveryPackage(state: BrowserCanonicalState): string {
  const safe = sanitizeBrowserCanonicalState(state);
  const packageJson: RecoveryPackageJson = {
    packageVersion: RECOVERY_PACKAGE_VERSION,
    vault: {
      vaultFormatVersion: safe.vault.vaultFormatVersion,
      storageSchemaVersion: safe.vault.storageSchemaVersion,
      vaultId: toBase64Url(safe.vault.vaultId),
      generation: safe.vault.generation.toString(10),
      nonce: toBase64Url(safe.vault.nonce),
      ciphertext: toBase64Url(safe.vault.ciphertext),
      tag: toBase64Url(safe.vault.tag),
      ciphertextLength: safe.vault.ciphertextLength,
    },
    wrappedVmk: {
      packageVersion: safe.recoveryWrappedVmk.packageVersion,
      wrapVersion: safe.recoveryWrappedVmk.wrapVersion,
      vaultFormatVersion: safe.recoveryWrappedVmk.vaultFormatVersion,
      vaultId: toBase64Url(safe.recoveryWrappedVmk.vaultId),
      kdf: {
        algorithm: "argon2id",
        version: safe.recoveryWrappedVmk.kdf.version,
        memoryKiB: safe.recoveryWrappedVmk.kdf.memoryKiB,
        iterations: safe.recoveryWrappedVmk.kdf.iterations,
        parallelism: safe.recoveryWrappedVmk.kdf.parallelism,
        salt: toBase64Url(safe.recoveryWrappedVmk.kdf.salt),
        outputBytes: safe.recoveryWrappedVmk.kdf.outputBytes,
      },
      nonce: toBase64Url(safe.recoveryWrappedVmk.nonce),
      ciphertext: toBase64Url(safe.recoveryWrappedVmk.ciphertext),
      tag: toBase64Url(safe.recoveryWrappedVmk.tag),
    },
    previousRegistration: {
      registrationId: toBase64Url(safe.trustedBrowser.registrationId),
      epoch: safe.trustedBrowser.epoch,
    },
    deviceMetadata: safe.deviceMetadata,
  };
  return JSON.stringify(packageJson, null, 2);
}

export function parseRecoveryPackage(serialized: string): {
  vault: EncryptedVaultEnvelope;
  wrappedVmk: PassphraseWrappedVmk;
  previousRegistration: { registrationId: Uint8Array; epoch: number };
  deviceMetadata: BrowserDeviceMetadata | null;
} {
  assert(serialized.length > 0 && serialized.length <= RECOVERY_PACKAGE_MAX_CHARS, "Recovery Package size is invalid");
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized) as unknown;
  } catch {
    throw new Error("Recovery Package is not valid JSON");
  }
  const root = asObject(parsed, "Recovery Package");
  assert(asInteger(root.packageVersion, "packageVersion", 1) === RECOVERY_PACKAGE_VERSION, "unsupported Recovery Package version");

  const vaultJson = asObject(root.vault, "vault");
  const vault: EncryptedVaultEnvelope = {
    vaultFormatVersion: asInteger(vaultJson.vaultFormatVersion, "vault.vaultFormatVersion", 1),
    storageSchemaVersion: asInteger(vaultJson.storageSchemaVersion, "vault.storageSchemaVersion", 1),
    vaultId: fromBase64Url(vaultJson.vaultId, "vault.vaultId"),
    generation: parseGeneration(vaultJson.generation),
    nonce: fromBase64Url(vaultJson.nonce, "vault.nonce"),
    ciphertext: fromBase64Url(vaultJson.ciphertext, "vault.ciphertext"),
    tag: fromBase64Url(vaultJson.tag, "vault.tag"),
    ciphertextLength: asInteger(vaultJson.ciphertextLength, "vault.ciphertextLength"),
  };

  const wrappedJson = asObject(root.wrappedVmk, "wrappedVmk");
  const kdfJson = asObject(wrappedJson.kdf, "wrappedVmk.kdf");
  const algorithm = asString(kdfJson.algorithm, "wrappedVmk.kdf.algorithm");
  assert(algorithm === "argon2id", "unsupported Recovery Package KDF");
  const wrappedVmk: PassphraseWrappedVmk = {
    packageVersion: asInteger(wrappedJson.packageVersion, "wrappedVmk.packageVersion", 1),
    wrapVersion: asInteger(wrappedJson.wrapVersion, "wrappedVmk.wrapVersion", 1),
    vaultFormatVersion: asInteger(wrappedJson.vaultFormatVersion, "wrappedVmk.vaultFormatVersion", 1),
    vaultId: fromBase64Url(wrappedJson.vaultId, "wrappedVmk.vaultId"),
    kdf: {
      algorithm: "argon2id",
      version: asInteger(kdfJson.version, "wrappedVmk.kdf.version", 1),
      memoryKiB: asInteger(kdfJson.memoryKiB, "wrappedVmk.kdf.memoryKiB", 1),
      iterations: asInteger(kdfJson.iterations, "wrappedVmk.kdf.iterations", 1),
      parallelism: asInteger(kdfJson.parallelism, "wrappedVmk.kdf.parallelism", 1),
      salt: fromBase64Url(kdfJson.salt, "wrappedVmk.kdf.salt"),
      outputBytes: asInteger(kdfJson.outputBytes, "wrappedVmk.kdf.outputBytes", 1),
    },
    nonce: fromBase64Url(wrappedJson.nonce, "wrappedVmk.nonce"),
    ciphertext: fromBase64Url(wrappedJson.ciphertext, "wrappedVmk.ciphertext"),
    tag: fromBase64Url(wrappedJson.tag, "wrappedVmk.tag"),
  };

  const previousJson = asObject(root.previousRegistration, "previousRegistration");
  const previousRegistration = {
    registrationId: fromBase64Url(previousJson.registrationId, "previousRegistration.registrationId"),
    epoch: asInteger(previousJson.epoch, "previousRegistration.epoch", 1),
  };
  assertLength(previousRegistration.registrationId, REGISTRATION_ID_BYTES, "previous registrationId");

  let deviceMetadata: BrowserDeviceMetadata | null = null;
  if (root.deviceMetadata !== null && root.deviceMetadata !== undefined) {
    const deviceJson = asObject(root.deviceMetadata, "deviceMetadata");
    const deviceId = asString(deviceJson.deviceId, "deviceMetadata.deviceId");
    assert(deviceId.length > 0 && deviceId.length <= 256, "deviceMetadata.deviceId length is invalid");
    deviceMetadata = { deviceId };
  }

  const placeholderKey = {} as CryptoKey;
  const placeholderState = {
    stateVersion: BROWSER_STATE_VERSION,
    vault,
    recoveryWrappedVmk: wrappedVmk,
    trustedBrowser: {
      registrationId: previousRegistration.registrationId,
      epoch: previousRegistration.epoch,
      status: "replacement-pending" as const,
      buk: placeholderKey,
      brkPrivateKey: placeholderKey,
      brkPublicKeyRaw: new Uint8Array(BRK_PUBLIC_RAW_BYTES),
      wrappedVmk: {
        version: BUK_WRAP_VERSION,
        nonce: new Uint8Array(AES_GCM_NONCE_BYTES),
        ciphertext: new Uint8Array(AES_GCM_KEY_BYTES),
        tag: new Uint8Array(AES_GCM_TAG_BYTES),
      },
    },
    deviceMetadata,
  };
  assert(vault.vaultFormatVersion === VAULT_FORMAT_VERSION, "unsupported Vault format version");
  assert(vault.storageSchemaVersion === VAULT_TARGET_STORAGE_SCHEMA_VERSION, "unsupported storage schema version");
  assertLength(vault.vaultId, VAULT_ID_BYTES, "vaultId");
  assertLength(vault.nonce, AES_GCM_NONCE_BYTES, "Vault nonce");
  assertLength(vault.tag, AES_GCM_TAG_BYTES, "Vault tag");
  assert(vault.ciphertextLength === vault.ciphertext.length, "Vault ciphertext framing mismatch");
  assert(sameBytes(vault.vaultId, wrappedVmk.vaultId), "Vault and wrapped VMK vault_id mismatch");
  void placeholderState;
  return { vault, wrappedVmk, previousRegistration, deviceMetadata };
}

export async function importRecoveryPackage(serialized: string, passphrase: string): Promise<BrowserCanonicalState> {
  const parsed = parseRecoveryPackage(serialized);
  const vmk = await unwrapVmkWithPassphrase(parsed.wrappedVmk, passphrase);
  let plaintext: Uint8Array | null = null;
  try {
    plaintext = await decryptVault(parsed.vault, vmk);
    const nextEpoch = parsed.previousRegistration.epoch + 1;
    assert(Number.isSafeInteger(nextEpoch), "registration epoch overflow");
    return await createBrowserCanonicalState({
      vault: parsed.vault,
      recoveryWrappedVmk: parsed.wrappedVmk,
      vmk,
      registrationEpoch: nextEpoch,
      status: "replacement-pending",
      deviceMetadata: parsed.deviceMetadata,
    });
  } finally {
    plaintext?.fill(0);
    vmk.fill(0);
  }
}

export async function changeRecoveryPassphrase(
  state: BrowserCanonicalState,
  currentPassphrase: string,
  newPassphrase: string,
): Promise<BrowserCanonicalState> {
  const safe = sanitizeBrowserCanonicalState(state);
  const vmk = await unwrapVmkWithPassphrase(safe.recoveryWrappedVmk, currentPassphrase);
  let plaintext: Uint8Array | null = null;
  try {
    plaintext = await decryptVault(safe.vault, vmk);
    const replacement = await wrapVmkWithPassphrase(vmk, safe.vault.vaultId, newPassphrase);
    return sanitizeBrowserCanonicalState({ ...safe, recoveryWrappedVmk: replacement });
  } finally {
    plaintext?.fill(0);
    vmk.fill(0);
  }
}

function vaultKey(vaultId: Uint8Array): string {
  assertLength(vaultId, VAULT_ID_BYTES, "vaultId");
  return toHex(vaultId);
}

function openDatabase(): Promise<IDBDatabase> {
  assert(typeof indexedDB !== "undefined", "IndexedDB is unavailable in this browser");
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) db.createObjectStore(STORE_NAME, { keyPath: "key" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Failed to open browser Vault database"));
    request.onblocked = () => reject(new Error("Browser Vault database upgrade is blocked by another tab"));
  });
}

export class IndexedDbBrowserVaultStore {
  async get(vaultId: Uint8Array): Promise<BrowserCanonicalState | null> {
    const db = await openDatabase();
    try {
      const transaction = db.transaction(STORE_NAME, "readonly");
      const request = transaction.objectStore(STORE_NAME).get(vaultKey(vaultId));
      const record = await new Promise<PersistedBrowserCanonicalState | undefined>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result as PersistedBrowserCanonicalState | undefined);
        request.onerror = () => reject(request.error ?? new Error("Failed to read browser Vault state"));
      });
      return record ? sanitizeBrowserCanonicalState(record) : null;
    } finally {
      db.close();
    }
  }

  async list(): Promise<BrowserCanonicalState[]> {
    const db = await openDatabase();
    try {
      const transaction = db.transaction(STORE_NAME, "readonly");
      const request = transaction.objectStore(STORE_NAME).getAll();
      const records = await new Promise<PersistedBrowserCanonicalState[]>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result as PersistedBrowserCanonicalState[]);
        request.onerror = () => reject(request.error ?? new Error("Failed to list browser Vault state"));
      });
      return records.map((record) => sanitizeBrowserCanonicalState(record));
    } finally {
      db.close();
    }
  }

  async put(state: BrowserCanonicalState, expectedGeneration?: bigint): Promise<void> {
    const safe = sanitizeBrowserCanonicalState(state);
    const key = vaultKey(safe.vault.vaultId);
    const record: PersistedBrowserCanonicalState = { key, ...safe };
    const db = await openDatabase();
    try {
      await new Promise<void>((resolve, reject) => {
        const transaction = db.transaction(STORE_NAME, "readwrite");
        const store = transaction.objectStore(STORE_NAME);
        let failure: Error | null = null;
        const currentRequest = store.get(key);
        currentRequest.onerror = () => {
          failure = currentRequest.error ?? new Error("Failed to read current browser Vault generation");
          transaction.abort();
        };
        currentRequest.onsuccess = () => {
          const current = currentRequest.result as PersistedBrowserCanonicalState | undefined;
          if (expectedGeneration !== undefined) {
            if (!current || current.vault.generation !== expectedGeneration) {
              failure = new GenerationConflictError();
              transaction.abort();
              return;
            }
          } else if (current) {
            failure = new GenerationConflictError("Canonical browser Vault already exists; explicit replacement is required");
            transaction.abort();
            return;
          }
          store.put(record);
        };
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => reject(failure ?? transaction.error ?? new Error("Browser Vault transaction aborted"));
        transaction.onerror = () => {
          if (!failure && transaction.error) failure = transaction.error;
        };
      });
    } finally {
      db.close();
    }
  }

  async delete(vaultId: Uint8Array, expectedGeneration?: bigint): Promise<void> {
    const key = vaultKey(vaultId);
    const db = await openDatabase();
    try {
      await new Promise<void>((resolve, reject) => {
        const transaction = db.transaction(STORE_NAME, "readwrite");
        const store = transaction.objectStore(STORE_NAME);
        let failure: Error | null = null;
        const currentRequest = store.get(key);
        currentRequest.onerror = () => {
          failure = currentRequest.error ?? new Error("Failed to read browser Vault state before delete");
          transaction.abort();
        };
        currentRequest.onsuccess = () => {
          const current = currentRequest.result as PersistedBrowserCanonicalState | undefined;
          if (expectedGeneration !== undefined && (!current || current.vault.generation !== expectedGeneration)) {
            failure = new GenerationConflictError();
            transaction.abort();
            return;
          }
          store.delete(key);
        };
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => reject(failure ?? transaction.error ?? new Error("Browser Vault delete transaction aborted"));
      });
    } finally {
      db.close();
    }
  }
}

export function displayVaultId(vaultId: Uint8Array): string {
  return toHex(vaultId);
}
