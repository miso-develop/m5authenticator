import { describe, expect, it } from "vitest";
import {
  CREDENTIAL_ID_BYTES,
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

function sampleVault(): VaultPlaintext {
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
  };
}

describe("V1 vault format", () => {
  it("round-trips encrypted-boundary account and Wi-Fi fields", () => {
    const original = sampleVault();
    const decoded = decodeVaultPlaintext(encodeVaultPlaintext(original));

    expect(decoded.credentials).toHaveLength(1);
    expect(decoded.credentials[0]?.issuer).toBe(original.credentials[0]?.issuer);
    expect(decoded.credentials[0]?.account).toBe(original.credentials[0]?.account);
    expect(decoded.credentials[0]?.displayName).toBe(original.credentials[0]?.displayName);
    expect(decoded.credentials[0]?.secret).toEqual(original.credentials[0]?.secret);
    expect(decoded.wifi?.ssid).toBe(original.wifi?.ssid);
    expect(decoded.wifi?.password).toBe(original.wifi?.password);
  });

  it("builds fixed-order vault AAD without a Device identifier", () => {
    const aad = buildVaultAad({
      vaultId: sequence(VAULT_ID_BYTES, 0x00),
      generation: 7n,
    });

    expect(hex(aad)).toBe(
      "4d35415554482d564c542d4141443100" +
        "0001" +
        "0002" +
        "000102030405060708090a0b0c0d0e0f" +
        "0000000000000007",
    );
  });

  it("builds fixed-order VMK wrapping AAD", () => {
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
    expect(() =>
      buildVaultAad({ vaultId, generation: 1n, vaultFormatVersion: VAULT_FORMAT_VERSION + 1 }),
    ).toThrow(/unsupported vault format version/);
    expect(() =>
      buildVaultAad({
        vaultId,
        generation: 1n,
        storageSchemaVersion: VAULT_TARGET_STORAGE_SCHEMA_VERSION + 1,
      }),
    ).toThrow(/unsupported storage schema version/);
  });

  it("rejects trailing bytes and unsupported plaintext versions", () => {
    const encoded = encodeVaultPlaintext(sampleVault());
    const trailing = new Uint8Array(encoded.length + 1);
    trailing.set(encoded);
    expect(() => decodeVaultPlaintext(trailing)).toThrow(/trailing/);

    const unknown = encoded.slice();
    const versionOffset = new TextEncoder().encode("M5AUTH-VLT-PT1\0").length;
    unknown[versionOffset + 1] = 2;
    expect(() => decodeVaultPlaintext(unknown)).toThrow(/unsupported vault format version/);
  });
});
