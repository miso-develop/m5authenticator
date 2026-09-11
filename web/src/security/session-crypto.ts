import { AES_GCM_KEY_BYTES, AES_GCM_NONCE_BYTES, AES_GCM_TAG_BYTES } from "./vault-crypto";

export const SESSION_ATTEMPT_ID_BYTES = 16;
export const SESSION_DEVICE_CHALLENGE_BYTES = 32;
export const SESSION_P256_PUBLIC_KEY_BYTES = 65;

const MAX_HKDF_CONTEXT_BYTES = 4096;
const MAX_TRANSCRIPT_BYTES = 16_384;

export interface DeviceSessionBinding {
  attemptId: Uint8Array;
  challenge: Uint8Array;
  devicePublicKeyRaw: Uint8Array;
}

export interface WebEphemeralKeyPair {
  privateKey: CryptoKey;
  publicKeyRaw: Uint8Array;
}

export interface SessionAeadKeyInput {
  privateKey: CryptoKey;
  peerPublicKeyRaw: Uint8Array;
  hkdfSalt: Uint8Array;
  hkdfInfo: Uint8Array;
}

export interface SealedSessionVmk {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function assertExactLength(value: Uint8Array, expected: number, field: string): void {
  assert(value.length === expected, `${field} must be ${expected} bytes`);
}

function assertBoundedNonEmpty(value: Uint8Array, maximum: number, field: string): void {
  assert(value.length > 0, `${field} must not be empty`);
  assert(value.length <= maximum, `${field} exceeds ${maximum} bytes`);
}

function copyBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer;
}

function validateRawP256PublicKey(value: Uint8Array, field: string): void {
  assertExactLength(value, SESSION_P256_PUBLIC_KEY_BYTES, field);
  assert(value[0] === 0x04, `${field} must be an uncompressed P-256 public key`);
}

function validateEcdhPrivateKey(key: CryptoKey): void {
  assert(key.type === "private", "ECDH key must be private");
  assert(key.algorithm.name === "ECDH", "private key must use ECDH");
  const algorithm = key.algorithm as EcKeyAlgorithm;
  assert(algorithm.namedCurve === "P-256", "ECDH private key must use P-256");
  assert(key.usages.includes("deriveBits"), "ECDH private key must permit deriveBits");
}

function validateSessionAeadKey(key: CryptoKey): void {
  assert(key.type === "secret", "session key must be a secret key");
  assert(key.extractable === false, "session key must be non-extractable");
  assert(key.algorithm.name === "AES-GCM", "session key must use AES-GCM");
  const algorithm = key.algorithm as AesKeyAlgorithm;
  assert(algorithm.length === 256, "session key must be AES-256-GCM");
  assert(key.usages.includes("encrypt"), "session key must permit encryption");
}

export function validateDeviceSessionBinding(input: DeviceSessionBinding): DeviceSessionBinding {
  assertExactLength(input.attemptId, SESSION_ATTEMPT_ID_BYTES, "attempt id");
  assertExactLength(input.challenge, SESSION_DEVICE_CHALLENGE_BYTES, "Device challenge");
  validateRawP256PublicKey(input.devicePublicKeyRaw, "Device public key");
  return {
    attemptId: input.attemptId.slice(),
    challenge: input.challenge.slice(),
    devicePublicKeyRaw: input.devicePublicKeyRaw.slice(),
  };
}

export async function generateWebEphemeralKeyPair(): Promise<WebEphemeralKeyPair> {
  const generated = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  assert("privateKey" in generated && "publicKey" in generated, "ECDH key generation did not return a key pair");
  const pair = generated as CryptoKeyPair;
  validateEcdhPrivateKey(pair.privateKey);
  assert(pair.privateKey.extractable === false, "Web ECDH private key must be non-extractable");
  const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  validateRawP256PublicKey(publicKeyRaw, "Web public key");
  return { privateKey: pair.privateKey, publicKeyRaw };
}

async function importPeerP256PublicKey(raw: Uint8Array): Promise<CryptoKey> {
  validateRawP256PublicKey(raw, "peer public key");
  try {
    return await crypto.subtle.importKey(
      "raw",
      copyBuffer(raw),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
  } catch {
    throw new Error("peer public key is not a valid P-256 point");
  }
}

export async function deriveSessionAeadKey(input: SessionAeadKeyInput): Promise<CryptoKey> {
  validateEcdhPrivateKey(input.privateKey);
  validateRawP256PublicKey(input.peerPublicKeyRaw, "peer public key");
  assertBoundedNonEmpty(input.hkdfSalt, MAX_HKDF_CONTEXT_BYTES, "HKDF salt");
  assertBoundedNonEmpty(input.hkdfInfo, MAX_HKDF_CONTEXT_BYTES, "HKDF info");

  const peerPublicKey = await importPeerP256PublicKey(input.peerPublicKeyRaw);
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPublicKey },
    input.privateKey,
    256,
  ));
  assertExactLength(sharedSecret, AES_GCM_KEY_BYTES, "ECDH shared secret");

  try {
    const hkdfKey = await crypto.subtle.importKey("raw", copyBuffer(sharedSecret), "HKDF", false, ["deriveKey"]);
    const sessionKey = await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: copyBuffer(input.hkdfSalt),
        info: copyBuffer(input.hkdfInfo),
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    validateSessionAeadKey(sessionKey);
    return sessionKey;
  } finally {
    sharedSecret.fill(0);
  }
}

function splitCiphertextAndTag(combined: ArrayBuffer): { ciphertext: Uint8Array; tag: Uint8Array } {
  const bytes = new Uint8Array(combined);
  assert(bytes.length >= AES_GCM_TAG_BYTES, "AES-GCM output is shorter than its tag");
  return {
    ciphertext: bytes.slice(0, bytes.length - AES_GCM_TAG_BYTES),
    tag: bytes.slice(bytes.length - AES_GCM_TAG_BYTES),
  };
}

export async function sealVmkForSession(input: {
  sessionKey: CryptoKey;
  vmk: Uint8Array;
  aad: Uint8Array;
}): Promise<SealedSessionVmk> {
  validateSessionAeadKey(input.sessionKey);
  assert(input.sessionKey.usages.includes("encrypt"), "session key cannot seal VMK material");
  assertExactLength(input.vmk, AES_GCM_KEY_BYTES, "VMK");
  assertBoundedNonEmpty(input.aad, MAX_TRANSCRIPT_BYTES, "session transcript AAD");

  const nonce = new Uint8Array(AES_GCM_NONCE_BYTES);
  crypto.getRandomValues(nonce);
  const combined = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: copyBuffer(nonce),
      additionalData: copyBuffer(input.aad),
      tagLength: 128,
    },
    input.sessionKey,
    copyBuffer(input.vmk),
  );
  const sealed = splitCiphertextAndTag(combined);
  assert(sealed.ciphertext.length === AES_GCM_KEY_BYTES, "sealed VMK ciphertext must be 32 bytes");
  assertExactLength(sealed.tag, AES_GCM_TAG_BYTES, "session authentication tag");
  return { nonce, ...sealed };
}

export async function signTrustedBrowserTranscript(
  brkPrivateKey: CryptoKey,
  transcript: Uint8Array,
): Promise<Uint8Array> {
  assert(brkPrivateKey.type === "private", "BRK must be a private key");
  assert(brkPrivateKey.extractable === false, "BRK private key must be non-extractable");
  assert(brkPrivateKey.algorithm.name === "ECDSA", "BRK private key must use ECDSA");
  const algorithm = brkPrivateKey.algorithm as EcKeyAlgorithm;
  assert(algorithm.namedCurve === "P-256", "BRK private key must use P-256");
  assert(brkPrivateKey.usages.includes("sign"), "BRK private key must permit signing");
  assertBoundedNonEmpty(transcript, MAX_TRANSCRIPT_BYTES, "session transcript");

  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    brkPrivateKey,
    copyBuffer(transcript),
  ));
  assert(signature.length === 64, "ECDSA P-256 signature must be 64-byte IEEE P1363 form");
  return signature;
}
