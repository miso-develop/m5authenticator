import { describe, expect, it } from "vitest";
import {
  SESSION_PROTOCOL_VERSION,
  buildSessionV2Request,
  decodeBase64UrlCanonical,
  encodeBase64UrlCanonical,
  encodeSessionTranscript,
  parseSessionBeginData,
  parseSessionV2Response,
} from "./session-protocol-v2";

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function publicKey(start: number): Uint8Array {
  const value = new Uint8Array(65);
  value[0] = 0x04;
  for (let index = 1; index < value.length; index += 1) value[index] = (start + index - 1) & 0xff;
  return value;
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const expectedTranscriptHex =
  "4d3541530102010b737469636b332d74657374000102030405060708090a0b0c0d0e0f0102" +
  "030405060708101112131415161718191a1b1c1d1e1f01020304202122232425262728292a" +
  "2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f" +
  "040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324" +
  "25262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40044142434445464748" +
  "494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d" +
  "6e6f707172737475767778797a7b7c7d7e7f80048182838485868788898a8b8c8d8e8f9091" +
  "92939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6" +
  "b7b8b9babbbcbdbebfc0000000000000000000000000000000000000000000000000000000" +
  "00000000000000000000000000000000000000000000000000000000000000000000000000" +
  "00";

describe("Protocol v2 session integration contract", () => {
  it("matches the native fixed-order transcript vector exactly", () => {
    const transcript = encodeSessionTranscript({
      operation: "trusted_browser_unlock",
      deviceId: "stick3-test",
      vaultId: bytes(16, 0x00),
      expectedGeneration: 0x0102030405060708n,
      registrationId: bytes(16, 0x10),
      registrationEpoch: 0x01020304,
      attemptId: bytes(16, 0x20),
      challenge: bytes(32, 0x30),
      deviceEphemeralPublicKey: publicKey(0x01),
      webEphemeralPublicKey: publicKey(0x41),
      currentBrkPublicKey: publicKey(0x81),
      proposedBrkPublicKey: new Uint8Array(65),
    });

    expect(transcript).toHaveLength(371);
    expect(toHex(transcript)).toBe(expectedTranscriptHex);
    const encoded = encodeBase64UrlCanonical(transcript);
    expect(decodeBase64UrlCanonical(encoded)).toEqual(transcript);
  });

  it("enforces operation-specific BRK binding", () => {
    const base = {
      deviceId: "stick3-test",
      vaultId: bytes(16, 1),
      expectedGeneration: 0n,
      registrationId: new Uint8Array(16),
      registrationEpoch: 0,
      attemptId: bytes(16, 2),
      challenge: bytes(32, 3),
      deviceEphemeralPublicKey: publicKey(4),
      webEphemeralPublicKey: publicKey(68),
      currentBrkPublicKey: new Uint8Array(65),
      proposedBrkPublicKey: publicKey(132),
    } as const;

    expect(() => encodeSessionTranscript({ ...base, operation: "initial_provisioning" })).not.toThrow();
    expect(() => encodeSessionTranscript({
      ...base,
      operation: "initial_provisioning",
      proposedBrkPublicKey: new Uint8Array(65),
    })).toThrow(/proposed BRK/i);
    expect(() => encodeSessionTranscript({
      ...base,
      operation: "trusted_browser_unlock",
    })).toThrow(/active registration/i);
  });

  it("uses canonical unpadded base64url and rejects alternate encodings", () => {
    const sample = bytes(17, 7);
    const encoded = encodeBase64UrlCanonical(sample);
    expect(encoded).not.toContain("=");
    expect(decodeBase64UrlCanonical(encoded, 17)).toEqual(sample);
    expect(() => decodeBase64UrlCanonical(encoded + "=")).toThrow(/character|canonical/i);
    expect(() => decodeBase64UrlCanonical("A")).toThrow(/length/i);
  });

  it("builds and parses request-id-correlated staged Protocol v2 NDJSON", () => {
    const request = buildSessionV2Request(17, "session.status", { attempt_id: "AA" });
    expect(request.endsWith("\n")).toBe(true);
    expect(JSON.parse(request)).toEqual({
      v: SESSION_PROTOCOL_VERSION,
      id: 17,
      op: "session.status",
      params: { attempt_id: "AA" },
    });

    expect(parseSessionV2Response(JSON.stringify({ v: 2, id: 17, ok: true, data: { state: "confirmed" } }), 17))
      .toEqual({ state: "confirmed" });
    expect(() => parseSessionV2Response(JSON.stringify({ v: 2, id: 18, ok: true, data: {} }), 17))
      .toThrow(/id mismatch/i);
    expect(() => parseSessionV2Response(JSON.stringify({ v: 1, id: 17, ok: true, data: {} }), 17))
      .toThrow(/version/i);
  });

  it("parses bounded Device attempt material", () => {
    const attemptId = bytes(16, 1);
    const challenge = bytes(32, 17);
    const key = publicKey(49);
    const parsed = parseSessionBeginData({
      attempt_id: encodeBase64UrlCanonical(attemptId),
      challenge: encodeBase64UrlCanonical(challenge),
      device_public_key: encodeBase64UrlCanonical(key),
      expires_in_ms: 30_000,
    });
    expect(parsed.attemptId).toEqual(attemptId);
    expect(parsed.challenge).toEqual(challenge);
    expect(parsed.devicePublicKeyRaw).toEqual(key);
    expect(() => parseSessionBeginData({
      attempt_id: encodeBase64UrlCanonical(bytes(15, 1)),
      challenge: encodeBase64UrlCanonical(challenge),
      device_public_key: encodeBase64UrlCanonical(key),
      expires_in_ms: 30_000,
    })).toThrow(/16 bytes/i);
  });
});
