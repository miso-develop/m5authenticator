import { describe, expect, it } from "vitest";
import type { SessionV2Transport } from "../serial";
import { deliverVmkOverSessionV2 } from "./session-flow-v2";
import {
  decodeBase64UrlCanonical,
  encodeBase64UrlCanonical,
  encodeSessionTranscript,
  type SessionWireOperation,
} from "./session-protocol-v2";

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function join(left: Uint8Array, right: Uint8Array): Uint8Array {
  const combined = new Uint8Array(left.length + right.length);
  combined.set(left);
  combined.set(right, left.length);
  return combined;
}

function copyBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer;
}

describe("Protocol v2 staged VMK delivery", () => {
  it("binds BRK authentication, fresh ECDH, transcript HKDF/AAD, and VMK AEAD end to end", async () => {
    const attemptId = bytes(16, 0x20);
    const challenge = bytes(32, 0x30);
    const vaultId = bytes(16, 0x00);
    const registrationId = bytes(16, 0x10);
    const vmk = bytes(32, 0xa0);

    const deviceGenerated = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    ) as CryptoKeyPair;
    const devicePublic = new Uint8Array(await crypto.subtle.exportKey("raw", deviceGenerated.publicKey));

    const brkGenerated = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    ) as CryptoKeyPair;
    const brkPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", brkGenerated.publicKey));

    let capturedWebPublic: Uint8Array | null = null;
    let expectedTranscript: Uint8Array | null = null;
    let statusCalls = 0;
    let vmkAccepted = false;

    const transport: SessionV2Transport = {
      async requestV2(op: SessionWireOperation, params: Record<string, unknown> = {}) {
        if (op === "session.begin") {
          return {
            attempt_id: encodeBase64UrlCanonical(attemptId),
            challenge: encodeBase64UrlCanonical(challenge),
            device_public_key: encodeBase64UrlCanonical(devicePublic),
            expires_in_ms: 30_000,
          };
        }
        if (op === "session.authorize") {
          expect(typeof params.web_public_key).toBe("string");
          expect(typeof params.brk_signature).toBe("string");
          capturedWebPublic = decodeBase64UrlCanonical(params.web_public_key as string, 65);
          expectedTranscript = encodeSessionTranscript({
            operation: "trusted_browser_unlock",
            deviceId: "stick3-test",
            vaultId,
            expectedGeneration: 0x0102030405060708n,
            registrationId,
            registrationEpoch: 7,
            attemptId,
            challenge,
            deviceEphemeralPublicKey: devicePublic,
            webEphemeralPublicKey: capturedWebPublic,
            currentBrkPublicKey: brkPublicRaw,
            proposedBrkPublicKey: new Uint8Array(65),
          });
          const signature = decodeBase64UrlCanonical(params.brk_signature as string, 64);
          expect(await crypto.subtle.verify(
            { name: "ECDSA", hash: "SHA-256" },
            brkGenerated.publicKey,
            copyBuffer(signature),
            copyBuffer(expectedTranscript),
          )).toBe(true);
          return {};
        }
        if (op === "session.status") {
          statusCalls += 1;
          return { state: statusCalls === 1 ? "awaiting_presence" : "confirmed" };
        }
        if (op === "session.complete") {
          expect(capturedWebPublic).not.toBeNull();
          expect(expectedTranscript).not.toBeNull();
          const webPublicKey = await crypto.subtle.importKey(
            "raw",
            copyBuffer(capturedWebPublic as Uint8Array),
            { name: "ECDH", namedCurve: "P-256" },
            false,
            [],
          );
          const shared = new Uint8Array(await crypto.subtle.deriveBits(
            { name: "ECDH", public: webPublicKey },
            deviceGenerated.privateKey,
            256,
          ));
          const hkdfKey = await crypto.subtle.importKey("raw", copyBuffer(shared), "HKDF", false, ["deriveKey"]);
          const salt = join(attemptId, challenge);
          const deviceSessionKey = await crypto.subtle.deriveKey(
            {
              name: "HKDF",
              hash: "SHA-256",
              salt: copyBuffer(salt),
              info: copyBuffer(expectedTranscript as Uint8Array),
            },
            hkdfKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"],
          );
          const nonce = decodeBase64UrlCanonical(params.nonce as string, 12);
          const ciphertext = decodeBase64UrlCanonical(params.ciphertext as string, 32);
          const tag = decodeBase64UrlCanonical(params.tag as string, 16);
          const plaintext = new Uint8Array(await crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: copyBuffer(nonce),
              additionalData: copyBuffer(expectedTranscript as Uint8Array),
              tagLength: 128,
            },
            deviceSessionKey,
            copyBuffer(join(ciphertext, tag)),
          ));
          expect(plaintext).toEqual(vmk);
          vmkAccepted = true;
          plaintext.fill(0);
          shared.fill(0);
          salt.fill(0);
          return { accepted: true };
        }
        throw new Error(`unexpected operation: ${op}`);
      },
      async close() {},
    };

    const result = await deliverVmkOverSessionV2({
      transport,
      operation: "trusted_browser_unlock",
      deviceId: "stick3-test",
      vaultId,
      expectedGeneration: 0x0102030405060708n,
      registrationId,
      registrationEpoch: 7,
      currentBrkPublicKey: brkPublicRaw,
      proposedBrkPublicKey: new Uint8Array(65),
      brkPrivateKey: brkGenerated.privateKey,
      vmk,
      pollIntervalMs: 1,
      wait: async () => {},
    });

    expect(result.attemptId).toEqual(attemptId);
    expect(vmkAccepted).toBe(true);
    expect(vmk).toEqual(bytes(32, 0xa0));
  });

  it("cancels the exact attempt when presence is rejected", async () => {
    const deviceGenerated = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    ) as CryptoKeyPair;
    const devicePublic = new Uint8Array(await crypto.subtle.exportKey("raw", deviceGenerated.publicKey));
    const proposedBrk = new Uint8Array(65);
    proposedBrk[0] = 0x04;
    proposedBrk.fill(0x22, 1);
    const attemptId = bytes(16, 1);
    let cancelledAttempt = "";

    const transport: SessionV2Transport = {
      async requestV2(op, params = {}) {
        if (op === "session.begin") return {
          attempt_id: encodeBase64UrlCanonical(attemptId),
          challenge: encodeBase64UrlCanonical(bytes(32, 2)),
          device_public_key: encodeBase64UrlCanonical(devicePublic),
          expires_in_ms: 30_000,
        };
        if (op === "session.authorize") return {};
        if (op === "session.status") return { state: "rejected" };
        if (op === "session.cancel") {
          cancelledAttempt = params.attempt_id as string;
          return {};
        }
        throw new Error(`unexpected operation: ${op}`);
      },
      async close() {},
    };

    await expect(deliverVmkOverSessionV2({
      transport,
      operation: "initial_provisioning",
      deviceId: "stick3-test",
      vaultId: bytes(16, 3),
      expectedGeneration: 0n,
      registrationId: bytes(16, 4),
      registrationEpoch: 0,
      currentBrkPublicKey: new Uint8Array(65),
      proposedBrkPublicKey: proposedBrk,
      vmk: bytes(32, 5),
      wait: async () => {},
    })).rejects.toThrow(/rejected/i);

    expect(cancelledAttempt).toBe(encodeBase64UrlCanonical(attemptId));
  });

  it("rejects quick unlock without a BRK before emitting any wire request", async () => {
    let requests = 0;
    const transport: SessionV2Transport = {
      async requestV2() {
        requests += 1;
        return {};
      },
      async close() {},
    };
    const currentBrk = new Uint8Array(65);
    currentBrk[0] = 0x04;

    await expect(deliverVmkOverSessionV2({
      transport,
      operation: "trusted_browser_unlock",
      deviceId: "stick3-test",
      vaultId: bytes(16, 1),
      expectedGeneration: 1n,
      registrationId: bytes(16, 2),
      registrationEpoch: 1,
      currentBrkPublicKey: currentBrk,
      proposedBrkPublicKey: new Uint8Array(65),
      vmk: bytes(32, 3),
    })).rejects.toThrow(/BRK authentication/i);
    expect(requests).toBe(0);
  });
});
