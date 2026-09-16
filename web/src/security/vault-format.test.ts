import { describe, expect, it } from "vitest";
import {
  CREDENTIAL_ID_BYTES,
  LEGACY_VAULT_FORMAT_VERSION,
  VAULT_FORMAT_VERSION,
  VAULT_ID_BYTES,
  VAULT_TARGET_STORAGE_SCHEMA_VERSION,
  buildVaultAad,
  buildVmkWrapAad,
  decodeVaultPlaintext,
  encodeVaultPlaintext,
  type VaultPlaintext,
} from "./vault-format";

function sequence(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function syntheticText(label: string): string {
  return `synthetic-${label}-only`;
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sampleVault(autoLockDays: number | null = null): VaultPlaintext {
  return {
    credentials: [
      {
        credentialId: sequence(CREDENTIAL_ID_BYTES, 0x20),
        secret: sequence(20, 0x40),
        issuer: syntheticText("issuer"),
        account: syntheticText("account"),
        displayName: syntheticText("display"),
        algorithm: "SHA1",
        digits: 6,
        periodSeconds: 30,
        manualOrder: 0,
      },
    ],
    wifi: {
      ssid: syntheticText("ssid"),
      password: syntheticText("network-pass"),
    },
    autoLockDays,
  };
}

describe("Vault Format 1 / 2", () => {
  it("keeps Format 1 byte-compatible and maps the missing automatic LOCK setting to disabled", () => {
    const original = sampleVault();
    const encoded = encodeVaultPlaintext(original, LEGACY_VAULT_FORMAT_VERSION);
    expect(new TextDecoder().decode(encoded.slice(0, 15))).toBe("M5AUTH-VLT-PT1\0");
    const decoded = decodeVaultPlaintext(encoded, LEGACY_VAULT_FORMAT_VERSION);

    expect(decoded.credentials).toHaveLength(1);
    expect(decoded.credentials[0]?.issuer).toBe(original.credentials[0]?.issuer);
    expect(decoded.credentials[0]?.secret).toEqual(original.credentials[0]?.secret);
    expect(decoded.wifi?.ssid).toBe(original.wifi?.ssid);
    expect(decoded.autoLockDays).toBeNull();
    expect(() => encodeVaultPlaintext(sampleVault(1), LEGACY_VAULT_FORMAT_VERSION)).toThrow(/Format 1/);
  });

  it.each([null, 1, 31] as const)("round-trips Format 2 autoLockDays=%s", (autoLockDays) => {
    const original = sampleVault(autoLockDays);
    const encoded = encodeVaultPlaintext(original, VAULT_FORMAT_VERSION);
    expect(new TextDecoder().decode(encoded.slice(0, 15))).toBe("M5AUTH-VLT-PT2\0");
    const decoded = decodeVaultPlaintext(encoded, VAULT_FORMAT_VERSION);
    expect(decoded.autoLockDays).toBe(autoLockDays);
    expect(decoded.credentials[0]?.account).toBe(original.credentials[0]?.account);
  });

  it("rejects invalid Format 2 automatic LOCK values instead of coercing them", () => {
    expect(() => encodeVaultPlaintext(sampleVault(0), VAULT_FORMAT_VERSION)).toThrow(/auto_lock_days/);
    expect(() => encodeVaultPlaintext(sampleVault(32), VAULT_FORMAT_VERSION)).toThrow(/auto_lock_days/);
    expect(() => encodeVaultPlaintext(sampleVault(1.5), VAULT_FORMAT_VERSION)).toThrow(/auto_lock_days/);

    const encoded = encodeVaultPlaintext(sampleVault(1), VAULT_FORMAT_VERSION);
    const badPresence = encoded.slice();
    badPresence[badPresence.length - 2] = 2;
    expect(() => decodeVaultPlaintext(badPresence, VAULT_FORMAT_VERSION)).toThrow(/auto_lock_present/);
  });

  it("uses separate authenticated AAD domains for Format 1 and Format 2", () => {
    const vaultId = sequence(VAULT_ID_BYTES, 0x00);
    const aad1 = buildVaultAad({ vaultId, generation: 7n, vaultFormatVersion: LEGACY_VAULT_FORMAT_VERSION });
    const aad2 = buildVaultAad({ vaultId, generation: 7n, vaultFormatVersion: VAULT_FORMAT_VERSION });

    expect(hex(aad1)).toBe(
      "4d35415554482d564c542d4141443100" +
        "0001" +
        "0002" +
        "000102030405060708090a0b0c0d0e0f" +
        "0000000000000007",
    );
    expect(hex(aad2).startsWith("4d35415554482d564c542d4141443200")).toBe(true);
    expect(aad2).not.toEqual(aad1);
  });

  it("builds the unchanged Version-1 VMK wrapping AAD", () => {
    const aad = buildVmkWrapAad({ vaultId: sequence(VAULT_ID_BYTES, 0x10) });
    expect(hex(aad)).toBe(
      "4d35415554482d564d4b2d575241503100" +
        "0001" +
        "0001" +
        "101112131415161718191a1b1c1d1e1f",
    );
  });

  it("fails closed for unknown format or storage schema versions", () => {
    const vaultId = sequence(VAULT_ID_BYTES, 0x00);
    expect(() => buildVaultAad({ vaultId, generation: 1n, vaultFormatVersion: VAULT_FORMAT_VERSION + 1 }))
      .toThrow(/unsupported vault format version/);
    expect(() => buildVaultAad({
      vaultId,
      generation: 1n,
      storageSchemaVersion: VAULT_TARGET_STORAGE_SCHEMA_VERSION + 1,
    })).toThrow(/unsupported storage schema version/);
  });

  it("requires exact end-of-input for both formats", () => {
    for (const version of [LEGACY_VAULT_FORMAT_VERSION, VAULT_FORMAT_VERSION] as const) {
      const encoded = encodeVaultPlaintext(sampleVault(), version);
      const trailing = new Uint8Array(encoded.length + 1);
      trailing.set(encoded);
      expect(() => decodeVaultPlaintext(trailing, version)).toThrow(/trailing/);
    }
  });
});
