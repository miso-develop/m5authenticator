import { describe, expect, it } from "vitest";
import { decodeBase32Secret, encodeBase32Secret } from "./base32";

describe("Base32 provisioning encoding", () => {
  it("round-trips an explicitly synthetic byte sequence without padding", () => {
    const source = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const encoded = encodeBase32Secret(source);
    expect(encoded).toMatch(/^[A-Z2-7]+$/);
    expect(decodeBase32Secret(encoded)).toEqual(source);
  });
});
