import { describe, expect, it } from "vitest";
import { ImportSession } from "./session";

const SYNTHETIC_URI =
  "otpauth://totp/Example:alice%40example.invalid?secret=MFRGGZDFMZTWQ2LK&issuer=Example";

describe("ImportSession", () => {
  it("exposes only non-secret confirmation metadata", () => {
    const session = new ImportSession();
    const update = session.importDecodedText(SYNTHETIC_URI);

    expect(update.accounts).toEqual([
      {
        issuer: "Example",
        account: "alice@example.invalid",
        algorithm: "SHA1",
        digits: 6,
        period: 30,
      },
    ]);
    expect(JSON.stringify(update)).not.toContain("MFRGGZDFMZTWQ2LK");
    expect(JSON.stringify(update)).not.toContain("abcdefghij");
  });

  it("clears pending confirmation state when the session ends", () => {
    const session = new ImportSession();
    session.importDecodedText(SYNTHETIC_URI);
    session.clear();
    expect(session.preview()).toEqual([]);
  });

  it("does not hide a pending Google migration batch behind a standard import", () => {
    const session = new ImportSession();
    const pending = migrationUriForSession();
    const update = session.importDecodedText(pending);
    expect(update.batch).toEqual({ received: 1, total: 2 });
    expect(() => session.importDecodedText(SYNTHETIC_URI)).toThrow("active Google Authenticator migration batch");
    session.clear();
  });
});

function migrationUriForSession(): string {
  const secret = Uint8Array.from([1, 2, 3]);
  const name = new TextEncoder().encode("batch@example.invalid");
  const issuer = new TextEncoder().encode("Example");
  const otp = concat(
    fieldBytes(1, secret),
    fieldBytes(2, name),
    fieldBytes(3, issuer),
    fieldVarint(4, 1),
    fieldVarint(5, 1),
    fieldVarint(6, 2),
  );
  const payload = concat(
    fieldBytes(1, otp),
    fieldVarint(2, 1),
    fieldVarint(3, 2),
    fieldVarint(4, 0),
    fieldVarint(5, 44),
  );
  let binary = "";
  for (const byte of payload) binary += String.fromCharCode(byte);
  return `otpauth-migration://offline?data=${encodeURIComponent(btoa(binary))}`;
}

function fieldBytes(field: number, value: Uint8Array): Uint8Array {
  return concat(varint((field << 3) | 2), varint(value.length), value);
}

function fieldVarint(field: number, value: number): Uint8Array {
  return concat(varint(field << 3), varint(value));
}

function varint(value: number): Uint8Array {
  const bytes: number[] = [];
  let remaining = value >>> 0;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining) byte |= 0x80;
    bytes.push(byte);
  } while (remaining);
  return Uint8Array.from(bytes);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
