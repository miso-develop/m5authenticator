import { describe, expect, it } from "vitest";
import { parseStandardTotpUri } from "./otpauth";

const SYNTHETIC_SECRET = "MFRGGZDFMZTWQ2LK"; // Base32 for the public synthetic bytes "abcdefghij".

function uri(overrides = ""): string {
  return `otpauth://totp/Example:alice%40example.invalid?secret=${SYNTHETIC_SECRET}&issuer=Example${overrides}`;
}

describe("parseStandardTotpUri", () => {
  it("normalizes a standard TOTP URI to the V1 profile", () => {
    const account = parseStandardTotpUri(uri("&algorithm=SHA1&digits=6&period=30"));

    expect(account).toMatchObject({
      issuer: "Example",
      account: "alice@example.invalid",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    });
    expect([...account.secret]).toEqual([...new TextEncoder().encode("abcdefghij")]);
  });

  it("uses V1 defaults when algorithm, digits, and period are omitted", () => {
    expect(parseStandardTotpUri(uri())).toMatchObject({ algorithm: "SHA1", digits: 6, period: 30 });
  });

  it.each([
    ["&algorithm=SHA256", "algorithm"],
    ["&digits=8", "6-digit"],
    ["&period=60", "30-second"],
  ])("rejects unsupported V1 parameters without exposing the source", (suffix: string, expectedMessage: string) => {
    const source = uri(suffix);
    expect(() => parseStandardTotpUri(source)).toThrow(expectedMessage);
    try {
      parseStandardTotpUri(source);
    } catch (error) {
      expect(String(error)).not.toContain(SYNTHETIC_SECRET);
      expect(String(error)).not.toContain(source);
    }
  });

  it("rejects HOTP and inconsistent issuer metadata", () => {
    expect(() => parseStandardTotpUri(uri().replace("otpauth://totp/", "otpauth://hotp/"))).toThrow(
      "Only standard TOTP",
    );
    expect(() => parseStandardTotpUri(uri().replace("issuer=Example", "issuer=Other"))).toThrow(
      "issuer metadata is inconsistent",
    );
  });
});
