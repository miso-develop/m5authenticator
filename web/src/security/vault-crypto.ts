import { argon2id } from "hash-wasm";
import {
  VAULT_FORMAT_VERSION,
  VAULT_ID_BYTES,
  VAULT_TARGET_STORAGE_SCHEMA_VERSION,
  buildVaultAad,
  buildVmkWrapAad,
} from "./vault-format";

export const AES_GCM_KEY_BYTES = 32;
export const AES_GCM_NONCE_BYTES = 12;
export const AES_GCM_TAG_BYTES = 16;
export const ARGON2ID_VERSION = 19;
export const ARGON2ID_MEMORY_KIB = 32_768;
export const ARGON2ID_ITERATIONS = 3;
export const ARGON2ID_PARALLELISM = 1;
export const ARGON2ID_SALT_BYTES = 32;
export const ARGON2ID_OUTPUT_BYTES = 32;
export const VMK_WRAP_VERSION = 1;

const textEncoder = new TextEncoder();

export interface EncryptedVaultEnvelope {
  vaultFormatVersion: number;
  storageSchemaVersion: number;
  vaultId: Uint8Array;
  generation: bigint;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
  ciphertextLength: number;
}

export interface Argon2idKdfMetadata {
  algorithm: "argon2id";
  version: number;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  salt: Uint8Array;
  outputBytes: number;
}

export interface PassphraseWrappedVmk {
  wrapVersion: number;
  vaultFormatVersion: number;
  vaultId: Uint8Array;
  kdf: Argon2idKdfMetadata;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

export interface RandomSource {
  fill(target: Uint8Array): void;
}

const browserRandomSource: RandomSource = {
  fill(target) {
    crypto.getRandomValues(target);
  },
};

function copyBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer;
}

function assertLength(value: Uint8Array, expected: number, field: string): void {
  if (value.length !== expected) {
    throw new Error(`${field} must be ${expected} bytes`);
  }
}

function randomBytes(length: number, source: RandomSource): Uint8Array {
  const value = new Uint8Array(length);
  source.fill(value);
  return value;
}

function splitCiphertextAndTag(combined: ArrayBuffer): { ciphertext: Uint8Array; tag: Uint8Array } {
  const bytes = new Uint8Array(combined);
  if (bytes.length < AES_GCM_TAG_BYTES) {
    throw new Error("AES-GCM result is shorter than the authentication tag");
  }
  return {
    ciphertext: bytes.slice(0, bytes.length - AES_GCM_TAG_BYTES),
    tag: bytes.slice(bytes.length - AES_GCM_TAG_BYTES),
  };
}

function joinCiphertextAndTag(ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  assertLength(tag, AES_GCM_TAG_BYTES, "AES-GCM tag");
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);
  return combined;
}

async function importAesKey(rawKey: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  assertLength(rawKey, AES_GCM_KEY_BYTES, "AES-256 key");
  return crypto.subtle.importKey("raw", copyBuffer(rawKey), { name: "AES-GCM" }, false, [usage]);
}

async function aesGcmEncrypt(
  rawKey: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
  assertLength(nonce, AES_GCM_NONCE_BYTES, "AES-GCM nonce");
  const key = await importAesKey(rawKey, "encrypt");
  const combined = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: copyBuffer(nonce),
      additionalData: copyBuffer(aad),
      tagLength: 128,
    },
    key,
    copyBuffer(plaintext),
  );
  return splitCiphertextAndTag(combined);
}

async function aesGcmDecrypt(
  rawKey: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  assertLength(nonce, AES_GCM_NONCE_BYTES, "AES-GCM nonce");
  const key = await importAesKey(rawKey, "decrypt");
  const combined = joinCiphertextAndTag(ciphertext, tag);
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: copyBuffer(nonce),
        additionalData: copyBuffer(aad),
        tagLength: 128,
      },
      key,
      copyBuffer(combined),
    );
    return new Uint8Array(plaintext);
  } finally {
    combined.fill(0);
  }
}

function validateVaultEnvelope(envelope: EncryptedVaultEnvelope): void {
  if (envelope.vaultFormatVersion !== VAULT_FORMAT_VERSION) {
    throw new Error(`unsupported vault format version: ${envelope.vaultFormatVersion}`);
  }
  if (envelope.storageSchemaVersion !== VAULT_TARGET_STORAGE_SCHEMA_VERSION) {
    throw new Error(`unsupported storage schema version: ${envelope.storageSchemaVersion}`);
  }
  assertLength(envelope.vaultId, VAULT_ID_BYTES, "vaultId");
  assertLength(envelope.nonce, AES_GCM_NONCE_BYTES, "vault nonce");
  assertLength(envelope.tag, AES_GCM_TAG_BYTES, "vault tag");
  if (envelope.ciphertextLength !== envelope.ciphertext.length) {
    throw new Error("vault ciphertext length framing mismatch");
  }
}

export async function encryptVault(
  plaintext: Uint8Array,
  vmk: Uint8Array,
  vaultId: Uint8Array,
  generation: bigint,
  source: RandomSource = browserRandomSource,
): Promise<EncryptedVaultEnvelope> {
  assertLength(vmk, AES_GCM_KEY_BYTES, "VMK");
  assertLength(vaultId, VAULT_ID_BYTES, "vaultId");
  const nonce = randomBytes(AES_GCM_NONCE_BYTES, source);
  const aad = buildVaultAad({ vaultId, generation });
  const encrypted = await aesGcmEncrypt(vmk, nonce, plaintext, aad);
  return {
    vaultFormatVersion: VAULT_FORMAT_VERSION,
    storageSchemaVersion: VAULT_TARGET_STORAGE_SCHEMA_VERSION,
    vaultId: vaultId.slice(),
    generation,
    nonce,
    ciphertext: encrypted.ciphertext,
    tag: encrypted.tag,
    ciphertextLength: encrypted.ciphertext.length,
  };
}

export async function decryptVault(
  envelope: EncryptedVaultEnvelope,
  vmk: Uint8Array,
): Promise<Uint8Array> {
  validateVaultEnvelope(envelope);
  assertLength(vmk, AES_GCM_KEY_BYTES, "VMK");
  const aad = buildVaultAad({
    vaultId: envelope.vaultId,
    generation: envelope.generation,
    storageSchemaVersion: envelope.storageSchemaVersion,
    vaultFormatVersion: envelope.vaultFormatVersion,
  });
  return aesGcmDecrypt(vmk, envelope.nonce, envelope.ciphertext, envelope.tag, aad);
}

export function normalizeAndValidatePassphrase(passphrase: string): Uint8Array {
  const normalized = passphrase.normalize("NFC");
  const codePoints = Array.from(normalized).length;
  if (codePoints < 15 || codePoints > 128) {
    throw new Error("Passphrase must contain 15 to 128 Unicode code points after NFC normalization");
  }
  const encoded = textEncoder.encode(normalized);
  if (encoded.length > 512) {
    encoded.fill(0);
    throw new Error("Passphrase exceeds the 512-byte UTF-8 limit after NFC normalization");
  }
  return encoded;
}

export function createArgon2idMetadata(
  source: RandomSource = browserRandomSource,
): Argon2idKdfMetadata {
  return {
    algorithm: "argon2id",
    version: ARGON2ID_VERSION,
    memoryKiB: ARGON2ID_MEMORY_KIB,
    iterations: ARGON2ID_ITERATIONS,
    parallelism: ARGON2ID_PARALLELISM,
    salt: randomBytes(ARGON2ID_SALT_BYTES, source),
    outputBytes: ARGON2ID_OUTPUT_BYTES,
  };
}

function validateKdfMetadata(metadata: Argon2idKdfMetadata): void {
  if (metadata.algorithm !== "argon2id") {
    throw new Error(`unsupported KDF algorithm: ${String(metadata.algorithm)}`);
  }
  if (metadata.version !== ARGON2ID_VERSION) {
    throw new Error(`unsupported Argon2id version: ${metadata.version}`);
  }
  if (
    metadata.memoryKiB !== ARGON2ID_MEMORY_KIB ||
    metadata.iterations !== ARGON2ID_ITERATIONS ||
    metadata.parallelism !== ARGON2ID_PARALLELISM ||
    metadata.outputBytes !== ARGON2ID_OUTPUT_BYTES
  ) {
    throw new Error("unsupported Argon2id parameter set");
  }
  assertLength(metadata.salt, ARGON2ID_SALT_BYTES, "Argon2id salt");
}

export async function derivePassphraseKek(
  passphrase: string,
  metadata: Argon2idKdfMetadata,
): Promise<Uint8Array> {
  validateKdfMetadata(metadata);
  const encoded = normalizeAndValidatePassphrase(passphrase);
  try {
    const result = await argon2id({
      password: encoded,
      salt: metadata.salt,
      parallelism: metadata.parallelism,
      iterations: metadata.iterations,
      memorySize: metadata.memoryKiB,
      hashLength: metadata.outputBytes,
      outputType: "binary",
    });
    return result.slice();
  } finally {
    encoded.fill(0);
  }
}

function validateWrappedVmk(value: PassphraseWrappedVmk): void {
  if (value.wrapVersion !== VMK_WRAP_VERSION) {
    throw new Error(`unsupported VMK wrap version: ${value.wrapVersion}`);
  }
  if (value.vaultFormatVersion !== VAULT_FORMAT_VERSION) {
    throw new Error(`unsupported vault format version: ${value.vaultFormatVersion}`);
  }
  assertLength(value.vaultId, VAULT_ID_BYTES, "vaultId");
  assertLength(value.nonce, AES_GCM_NONCE_BYTES, "VMK wrap nonce");
  assertLength(value.tag, AES_GCM_TAG_BYTES, "VMK wrap tag");
  if (value.ciphertext.length !== AES_GCM_KEY_BYTES) {
    throw new Error("wrapped VMK ciphertext must be 32 bytes");
  }
  validateKdfMetadata(value.kdf);
}

export async function wrapVmkWithPassphrase(
  vmk: Uint8Array,
  vaultId: Uint8Array,
  passphrase: string,
  kdf: Argon2idKdfMetadata = createArgon2idMetadata(),
  source: RandomSource = browserRandomSource,
): Promise<PassphraseWrappedVmk> {
  assertLength(vmk, AES_GCM_KEY_BYTES, "VMK");
  assertLength(vaultId, VAULT_ID_BYTES, "vaultId");
  validateKdfMetadata(kdf);
  const nonce = randomBytes(AES_GCM_NONCE_BYTES, source);
  const kek = await derivePassphraseKek(passphrase, kdf);
  try {
    const aad = buildVmkWrapAad({ vaultId });
    const encrypted = await aesGcmEncrypt(kek, nonce, vmk, aad);
    return {
      wrapVersion: VMK_WRAP_VERSION,
      vaultFormatVersion: VAULT_FORMAT_VERSION,
      vaultId: vaultId.slice(),
      kdf: {
        ...kdf,
        salt: kdf.salt.slice(),
      },
      nonce,
      ciphertext: encrypted.ciphertext,
      tag: encrypted.tag,
    };
  } finally {
    kek.fill(0);
  }
}

export async function unwrapVmkWithPassphrase(
  wrapped: PassphraseWrappedVmk,
  passphrase: string,
): Promise<Uint8Array> {
  validateWrappedVmk(wrapped);
  const kek = await derivePassphraseKek(passphrase, wrapped.kdf);
  try {
    const aad = buildVmkWrapAad({
      vaultId: wrapped.vaultId,
      wrapVersion: wrapped.wrapVersion,
      vaultFormatVersion: wrapped.vaultFormatVersion,
    });
    const vmk = await aesGcmDecrypt(kek, wrapped.nonce, wrapped.ciphertext, wrapped.tag, aad);
    assertLength(vmk, AES_GCM_KEY_BYTES, "unwrapped VMK");
    return vmk;
  } finally {
    kek.fill(0);
  }
}
