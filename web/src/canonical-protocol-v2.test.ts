import { describe, expect, it } from "vitest";
import {
  buildCanonicalV2Request,
  encryptedVaultParams,
  parseCanonicalHelloData,
  parseCanonicalTimeStatus,
  parseCanonicalV2Response,
} from "./canonical-protocol-v2";
import { encodeBase64UrlCanonical } from "./security/session-protocol-v2";

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function helloData() {
  return {
    device: "M5StickS3",
    device_id: "00112233445566778899aabbccddeeff",
    firmware: "0.1.0",
    protocol: 2,
    storage_schema: 2,
    vault_format: 1,
    build_commit: "synthetic",
    state: "locked",
    storage_ready: true,
    vault_present: true,
    vault_id: encodeBase64UrlCanonical(bytes(16, 0x10)),
    generation: "7",
    registration_present: true,
    registration_id: encodeBase64UrlCanonical(bytes(16, 0x30)),
    registration_epoch: 4,
    brk_public_key: encodeBase64UrlCanonical(Uint8Array.from([0x04, ...bytes(64, 0x50)])),
  };
}

describe("canonical Protocol v2 management", () => {
  it("parses the exact 2/2/1 hello binding", () => {
    const parsed = parseCanonicalHelloData(helloData());
    expect(parsed.protocol).toBe(2);
    expect(parsed.storageSchema).toBe(2);
    expect(parsed.vaultFormat).toBe(1);
    expect(parsed.generation).toBe(7n);
    expect(parsed.registrationEpoch).toBe(4);
    expect(parsed.vaultId).toEqual(bytes(16, 0x10));
  });

  it("rejects partial Vault / registration state", () => {
    expect(() => parseCanonicalHelloData({ ...helloData(), registration_present: false, registration_id: null, registration_epoch: 0, brk_public_key: null }))
      .toThrow(/partial Vault\/registration/);
  });

  it("uses correlated v2 request IDs and remote rejection errors", () => {
    expect(buildCanonicalV2Request(9, "device.lock")).toBe('{"v":2,"id":9,"op":"device.lock","params":{}}\n');
    expect(parseCanonicalV2Response('{"v":2,"id":9,"ok":true,"data":{}}', 9)).toEqual({});
    expect(() => parseCanonicalV2Response('{"v":2,"id":9,"ok":false,"error":{"code":"invalid_state"}}', 9))
      .toThrow(/invalid_state/);
  });

  it("parses trusted-time framing and serializes encrypted Vault metadata", () => {
    expect(parseCanonicalTimeStatus({
      readiness: "ready",
      source: "usb",
      last_sync_unix_seconds: "1789156800",
      age_seconds: 3,
      resync_due: false,
    })).toEqual({
      readiness: "ready",
      source: "usb",
      lastSyncUnixSeconds: 1789156800n,
      ageSeconds: 3,
      resyncDue: false,
    });

    const vaultId = bytes(16, 0x10);
    const params = encryptedVaultParams({
      vaultFormatVersion: 1,
      storageSchemaVersion: 2,
      vaultId,
      generation: 8n,
      nonce: bytes(12, 0x20),
      ciphertext: bytes(32, 0x40),
      tag: bytes(16, 0x60),
      ciphertextLength: 32,
    });
    expect(params.generation).toBe("8");
    expect(params.vault_id).toBe(encodeBase64UrlCanonical(vaultId));
    expect(params.ciphertext_length).toBe(32);
  });
});
