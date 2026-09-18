import { describe, expect, it } from "vitest";
import {
  buildCanonicalV2Request,
  canonicalFactoryResetAttemptParams,
  deviceSupportsVaultFormat,
  encryptedVaultParams,
  parseCanonicalFactoryResetBegin,
  parseCanonicalFactoryResetStatus,
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
    recovery_reset_required: false,
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
  it("parses shipped Format-1 hello without inventing Format-2 write capability", () => {
    const parsed = parseCanonicalHelloData(helloData());
    expect(parsed.protocol).toBe(2);
    expect(parsed.storageSchema).toBe(2);
    expect(parsed.vaultFormat).toBe(1);
    expect(parsed.supportedVaultFormats).toEqual([]);
    expect(deviceSupportsVaultFormat(parsed, 2)).toBe(false);
    expect(parsed.generation).toBe(7n);
    expect(parsed.registrationEpoch).toBe(4);
    expect(parsed.recoveryResetRequired).toBe(false);
    expect(parsed.factoryResetPresenceRequired).toBe(false);
    expect(parsed.vaultId).toEqual(bytes(16, 0x10));
  });

  it("accepts additive [1,2] capability metadata independently from the persisted format", () => {
    const parsed = parseCanonicalHelloData({ ...helloData(), supported_vault_formats: [1, 2] });
    expect(parsed.vaultFormat).toBe(1);
    expect(parsed.supportedVaultFormats).toEqual([1, 2]);
    expect(deviceSupportsVaultFormat(parsed, 2)).toBe(true);

    const migrated = parseCanonicalHelloData({
      ...helloData(),
      vault_format: 2,
      supported_vault_formats: [1, 2],
    });
    expect(migrated.vaultFormat).toBe(2);
  });

  it("parses and fails closed on the healthy Factory Reset capability", () => {
    expect(parseCanonicalHelloData({
      ...helloData(),
      factory_reset_presence_required: true,
    }).factoryResetPresenceRequired).toBe(true);
    expect(parseCanonicalHelloData({
      ...helloData(),
      factory_reset_presence_required: false,
    }).factoryResetPresenceRequired).toBe(false);
    expect(() => parseCanonicalHelloData({
      ...helloData(),
      factory_reset_presence_required: "true",
    })).toThrow(/incompatible canonical metadata/);
  });

  it("rejects malformed capability metadata and unknown persisted formats", () => {
    expect(() => parseCanonicalHelloData({ ...helloData(), supported_vault_formats: [1, 2, 2] }))
      .toThrow(/supported_vault_formats/);
    expect(() => parseCanonicalHelloData({ ...helloData(), supported_vault_formats: "1,2" }))
      .toThrow(/supported_vault_formats/);
    expect(() => parseCanonicalHelloData({ ...helloData(), vault_format: 3 }))
      .toThrow(/incompatible canonical metadata/);
  });

  it("rejects partial Vault / registration state unless Device exposes bounded recovery reset", () => {
    const partial = {
      ...helloData(),
      registration_present: false,
      registration_id: null,
      registration_epoch: 0,
      brk_public_key: null,
    };
    expect(() => parseCanonicalHelloData(partial)).toThrow(/partial Vault\/registration/);

    const recovery = parseCanonicalHelloData({ ...partial, recovery_reset_required: true });
    expect(recovery.recoveryResetRequired).toBe(true);
    expect(recovery.vaultPresent).toBe(true);
    expect(recovery.registrationPresent).toBe(false);
  });

  it("uses correlated v2 request IDs and remote rejection errors", () => {
    expect(buildCanonicalV2Request(9, "device.lock")).toBe('{"v":2,"id":9,"op":"device.lock","params":{}}\n');
    expect(buildCanonicalV2Request(10, "factory_reset.begin")).toContain('"factory_reset.begin"');
    expect(buildCanonicalV2Request(11, "factory_reset.status")).toContain('"factory_reset.status"');
    expect(buildCanonicalV2Request(12, "factory_reset.cancel")).toContain('"factory_reset.cancel"');
    expect(buildCanonicalV2Request(13, "factory_reset.commit")).toContain('"factory_reset.commit"');
    expect(buildCanonicalV2Request(14, "factory_reset.recovery_begin")).toContain('"factory_reset.recovery_begin"');
    expect(parseCanonicalV2Response('{"v":2,"id":9,"ok":true,"data":{}}', 9)).toEqual({});
    expect(() => parseCanonicalV2Response('{"v":2,"id":9,"ok":false,"error":{"code":"invalid_state"}}', 9))
      .toThrow(/invalid_state/);
  });

  it("parses bounded Factory Reset attempts using the canonical attempt encoding", () => {
    const attemptId = bytes(16, 0x70);
    expect(parseCanonicalFactoryResetBegin({
      attempt_id: encodeBase64UrlCanonical(attemptId),
      expires_in_ms: 30_000,
    })).toEqual({ attemptId, expiresInMs: 30_000 });
    expect(parseCanonicalFactoryResetStatus({ state: "awaiting_confirmation" })).toBe("awaiting_confirmation");
    expect(parseCanonicalFactoryResetStatus({ state: "confirmed" })).toBe("confirmed");
    expect(canonicalFactoryResetAttemptParams(attemptId)).toEqual({
      attempt_id: encodeBase64UrlCanonical(attemptId),
    });
    expect(() => parseCanonicalFactoryResetBegin({
      attempt_id: encodeBase64UrlCanonical(attemptId),
      expires_in_ms: 30_001,
    })).toThrow(/invalid Factory Reset begin state/);
    expect(() => parseCanonicalFactoryResetStatus({ state: "expired" })).toThrow(/invalid Factory Reset status/);
  });

  it("parses the stable trusted-time source-authenticity combinations", () => {
    const cases = [
      ["none", "none"],
      ["ntp", "unauthenticated_network"],
      ["usb", "local_host_asserted"],
    ] as const;

    for (const [source, source_authenticity] of cases) {
      expect(parseCanonicalTimeStatus({
        readiness: source === "none" ? "not_synced" : "ready",
        source,
        source_authenticity,
        last_sync_unix_seconds: source === "none" ? "0" : "1789156800",
        age_seconds: 3,
        resync_due: false,
      }).sourceAuthenticity).toBe(source_authenticity);
    }
  });

  it("keeps missing or future trusted-time authenticity metadata compatible without inventing trust", () => {
    expect(parseCanonicalTimeStatus({
      readiness: "ready",
      source: "ntp",
      last_sync_unix_seconds: "1789156800",
      age_seconds: 3,
      resync_due: false,
    }).sourceAuthenticity).toBe("unknown");

    expect(parseCanonicalTimeStatus({
      readiness: "ready",
      source: "ntp",
      source_authenticity: "future_network_attestation",
      last_sync_unix_seconds: "1789156800",
      age_seconds: 3,
      resync_due: false,
    }).sourceAuthenticity).toBe("unknown");
  });

  it("rejects malformed or contradictory trusted-time authenticity metadata", () => {
    expect(() => parseCanonicalTimeStatus({
      readiness: "ready",
      source: "ntp",
      source_authenticity: "local_host_asserted",
      last_sync_unix_seconds: "1789156800",
      age_seconds: 3,
      resync_due: false,
    })).toThrow(/invalid trusted-time status/);

    expect(() => parseCanonicalTimeStatus({
      readiness: "ready",
      source: "ntp",
      source_authenticity: 7,
      last_sync_unix_seconds: "1789156800",
      age_seconds: 3,
      resync_due: false,
    })).toThrow(/source authenticity/);
  });

  it("parses trusted-time framing and serializes both supported encrypted Vault formats", () => {
    expect(parseCanonicalTimeStatus({
      readiness: "ready",
      source: "usb",
      source_authenticity: "local_host_asserted",
      last_sync_unix_seconds: "1789156800",
      age_seconds: 3,
      resync_due: false,
    })).toEqual({
      readiness: "ready",
      source: "usb",
      sourceAuthenticity: "local_host_asserted",
      lastSyncUnixSeconds: 1789156800n,
      ageSeconds: 3,
      resyncDue: false,
    });

    const vaultId = bytes(16, 0x10);
    for (const vaultFormatVersion of [1, 2] as const) {
      const params = encryptedVaultParams({
        vaultFormatVersion,
        storageSchemaVersion: 2,
        vaultId,
        generation: 8n,
        nonce: bytes(12, 0x20),
        ciphertext: bytes(32, 0x40),
        tag: bytes(16, 0x60),
        ciphertextLength: 32,
      });
      expect(params.vault_format_version).toBe(vaultFormatVersion);
      expect(params.generation).toBe("8");
      expect(params.vault_id).toBe(encodeBase64UrlCanonical(vaultId));
      expect(params.ciphertext_length).toBe(32);
    }
  });
});
