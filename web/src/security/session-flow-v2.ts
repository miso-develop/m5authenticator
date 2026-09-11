import type { SessionV2Transport } from "../serial";
import {
  deriveSessionAeadKey,
  generateWebEphemeralKeyPair,
  sealVmkForSession,
  signTrustedBrowserTranscript,
  validateDeviceSessionBinding,
} from "./session-crypto";
import {
  SESSION_ATTEMPT_TTL_MS,
  SESSION_P256_PUBLIC_KEY_BYTES,
  SESSION_REGISTRATION_ID_BYTES,
  SESSION_VAULT_ID_BYTES,
  decodeBase64UrlCanonical,
  encodeBase64UrlCanonical,
  encodeSessionTranscript,
  parseSessionBeginData,
  type SessionOperation,
} from "./session-protocol-v2";

export interface SessionV2DeliveryInput {
  transport: SessionV2Transport;
  operation: SessionOperation;
  deviceId: string;
  vaultId: Uint8Array;
  expectedGeneration: bigint;
  registrationId: Uint8Array;
  registrationEpoch: number;
  currentBrkPublicKey: Uint8Array;
  proposedBrkPublicKey: Uint8Array;
  brkPrivateKey?: CryptoKey;
  vmk: Uint8Array;
  pollIntervalMs?: number;
  wait?: (milliseconds: number) => Promise<void>;
}

export interface SessionV2DeliveryResult {
  attemptId: Uint8Array;
}

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function zeroPublicKey(): Uint8Array {
  return new Uint8Array(SESSION_P256_PUBLIC_KEY_BYTES);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function isZero(value: Uint8Array): boolean {
  let combined = 0;
  for (const byte of value) combined |= byte;
  return combined === 0;
}

function hkdfSalt(attemptId: Uint8Array, challenge: Uint8Array): Uint8Array {
  const value = new Uint8Array(attemptId.length + challenge.length);
  value.set(attemptId);
  value.set(challenge, attemptId.length);
  return value;
}

function defaultWait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function requireOperationAuthentication(input: SessionV2DeliveryInput): void {
  const requiresCurrentBrowser = input.operation === "trusted_browser_unlock" || input.operation === "vmk_rekey";
  if (requiresCurrentBrowser) {
    assert(input.brkPrivateKey !== undefined, `${input.operation} requires active BRK authentication`);
    assert(!isZero(input.currentBrkPublicKey), `${input.operation} requires the current BRK identity`);
  }
  if (input.operation === "initial_provisioning" || input.operation === "recovery" || input.operation === "browser_replacement") {
    assert(!isZero(input.proposedBrkPublicKey), `${input.operation} requires a proposed BRK identity`);
  }
}

export async function deliverVmkOverSessionV2(input: SessionV2DeliveryInput): Promise<SessionV2DeliveryResult> {
  assert(input.vaultId.length === SESSION_VAULT_ID_BYTES, "vault_id must be 16 bytes");
  assert(input.registrationId.length === SESSION_REGISTRATION_ID_BYTES, "registration id must be 16 bytes");
  assert(input.currentBrkPublicKey.length === SESSION_P256_PUBLIC_KEY_BYTES, "current BRK public key must be 65 bytes");
  assert(input.proposedBrkPublicKey.length === SESSION_P256_PUBLIC_KEY_BYTES, "proposed BRK public key must be 65 bytes");
  assert(input.vmk.length === 32, "VMK must be 32 bytes");
  requireOperationAuthentication(input);

  const wait = input.wait ?? defaultWait;
  const pollIntervalMs = input.pollIntervalMs ?? 250;
  assert(Number.isSafeInteger(pollIntervalMs) && pollIntervalMs >= 1 && pollIntervalMs <= 1000, "Invalid session poll interval");

  const vmk = input.vmk.slice();
  let attemptId: Uint8Array | null = null;
  let challenge: Uint8Array | null = null;
  let transcript: Uint8Array | null = null;
  let salt: Uint8Array | null = null;
  let signature: Uint8Array | null = null;
  let sealedNonce: Uint8Array | null = null;
  let sealedCiphertext: Uint8Array | null = null;
  let sealedTag: Uint8Array | null = null;
  let completed = false;

  try {
    const begin = parseSessionBeginData(await input.transport.requestV2("session.begin", {
      operation: input.operation,
      device_id: input.deviceId,
      vault_id: encodeBase64UrlCanonical(input.vaultId),
      expected_generation: input.expectedGeneration.toString(10),
      registration_id: encodeBase64UrlCanonical(input.registrationId),
      registration_epoch: input.registrationEpoch,
      current_brk_public_key: encodeBase64UrlCanonical(input.currentBrkPublicKey),
      proposed_brk_public_key: encodeBase64UrlCanonical(input.proposedBrkPublicKey),
    }));
    const binding = validateDeviceSessionBinding({
      attemptId: begin.attemptId,
      challenge: begin.challenge,
      devicePublicKeyRaw: begin.devicePublicKeyRaw,
    });
    attemptId = binding.attemptId;
    challenge = binding.challenge;

    const ephemeral = await generateWebEphemeralKeyPair();
    transcript = encodeSessionTranscript({
      operation: input.operation,
      deviceId: input.deviceId,
      vaultId: input.vaultId,
      expectedGeneration: input.expectedGeneration,
      registrationId: input.registrationId,
      registrationEpoch: input.registrationEpoch,
      attemptId,
      challenge,
      deviceEphemeralPublicKey: binding.devicePublicKeyRaw,
      webEphemeralPublicKey: ephemeral.publicKeyRaw,
      currentBrkPublicKey: input.currentBrkPublicKey,
      proposedBrkPublicKey: input.proposedBrkPublicKey,
    });
    salt = hkdfSalt(attemptId, challenge);

    const sessionKey = await deriveSessionAeadKey({
      privateKey: ephemeral.privateKey,
      peerPublicKeyRaw: binding.devicePublicKeyRaw,
      hkdfSalt: salt,
      hkdfInfo: transcript,
    });

    if (input.brkPrivateKey !== undefined) {
      signature = await signTrustedBrowserTranscript(input.brkPrivateKey, transcript);
    }

    await input.transport.requestV2("session.authorize", {
      attempt_id: encodeBase64UrlCanonical(attemptId),
      web_public_key: encodeBase64UrlCanonical(ephemeral.publicKeyRaw),
      ...(signature === null ? {} : { brk_signature: encodeBase64UrlCanonical(signature) }),
    });

    const deadline = Date.now() + Math.min(begin.expiresInMs, SESSION_ATTEMPT_TTL_MS);
    while (true) {
      const status = await input.transport.requestV2("session.status", {
        attempt_id: encodeBase64UrlCanonical(attemptId),
      });
      assert(typeof status.state === "string", "Device returned invalid session state");
      if (status.state === "confirmed") break;
      if (status.state === "rejected" || status.state === "expired" || status.state === "cancelled") {
        throw new Error(`Device session ${status.state}`);
      }
      assert(status.state === "awaiting_presence", "Device returned unsupported session state");
      if (Date.now() >= deadline) throw new Error("Device user-presence confirmation timed out");
      await wait(Math.min(pollIntervalMs, Math.max(1, deadline - Date.now())));
    }

    const sealed = await sealVmkForSession({ sessionKey, vmk, aad: transcript });
    sealedNonce = sealed.nonce;
    sealedCiphertext = sealed.ciphertext;
    sealedTag = sealed.tag;
    await input.transport.requestV2("session.complete", {
      attempt_id: encodeBase64UrlCanonical(attemptId),
      nonce: encodeBase64UrlCanonical(sealed.nonce),
      ciphertext: encodeBase64UrlCanonical(sealed.ciphertext),
      tag: encodeBase64UrlCanonical(sealed.tag),
    });
    completed = true;
    return { attemptId: attemptId.slice() };
  } finally {
    if (!completed && attemptId !== null) {
      try {
        await input.transport.requestV2("session.cancel", {
          attempt_id: encodeBase64UrlCanonical(attemptId),
        });
      } catch {
        // Preserve the original failure. No key material is logged or echoed.
      }
    }
    vmk.fill(0);
    attemptId?.fill(0);
    challenge?.fill(0);
    transcript?.fill(0);
    salt?.fill(0);
    signature?.fill(0);
    sealedNonce?.fill(0);
    sealedCiphertext?.fill(0);
    sealedTag?.fill(0);
  }
}

// Helper for #55 when comparing non-secret Device status against the Browser
// state before selecting quick-unlock versus replacement/recovery.
export function registrationMatches(
  left: { registrationId: Uint8Array; epoch: number; brkPublicKey: Uint8Array },
  right: { registrationId: Uint8Array; epoch: number; brkPublicKey: Uint8Array },
): boolean {
  return left.epoch === right.epoch && sameBytes(left.registrationId, right.registrationId) &&
    sameBytes(left.brkPublicKey, right.brkPublicKey);
}

export function absentBrkIdentity(): Uint8Array {
  return zeroPublicKey();
}
