import { describe, expect, it } from "vitest";
import { MigrationBatchAssembler, parseGoogleMigrationUri } from "./google-migration";

interface SyntheticOtp {
  secret: number[];
  name: string;
  issuer: string;
  algorithm?: number;
  digits?: number;
  type?: number;
}

function migrationUri(
  accounts: SyntheticOtp[],
  options: { batchSize?: number; batchIndex?: number; batchId?: number } = {},
): string {
  const payload = concat(
    ...accounts.map((account) => fieldBytes(1, otpParameters(account))),
    fieldVarint(2, 1),
    fieldVarint(3, options.batchSize ?? 1),
    fieldVarint(4, options.batchIndex ?? 0),
    fieldVarint(5, options.batchId ?? 12345),
  );
  let binary = "";
  for (const byte of payload) binary += String.fromCharCode(byte);
  return `otpauth-migration://offline?data=${encodeURIComponent(btoa(binary))}`;
}

function otpParameters(account: SyntheticOtp): Uint8Array {
  return concat(
    fieldBytes(1, Uint8Array.from(account.secret)),
    fieldString(2, account.name),
    fieldString(3, account.issuer),
    fieldVarint(4, account.algorithm ?? 1),
    fieldVarint(5, account.digits ?? 1),
    fieldVarint(6, account.type ?? 2),
  );
}

function fieldString(field: number, value: string): Uint8Array {
  return fieldBytes(field, new TextEncoder().encode(value));
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

const firstAccount: SyntheticOtp = {
  secret: [1, 2, 3, 4, 5],
  name: "alice@example.invalid",
  issuer: "Example",
};

describe("Google Authenticator migration import", () => {
  it("decodes a synthetic V1-compatible migration payload", () => {
    const part = parseGoogleMigrationUri(migrationUri([firstAccount]));
    expect(part).toMatchObject({ version: 1, batchSize: 1, batchIndex: 0, batchId: 12345 });
    expect(part.accounts[0]).toMatchObject({
      issuer: "Example",
      account: "alice@example.invalid",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    });
    expect([...part.accounts[0]!.secret]).toEqual([1, 2, 3, 4, 5]);
  });

  it("assembles multi-QR batches by batch index even when scanned out of order", () => {
    const assembler = new MigrationBatchAssembler();
    const second = parseGoogleMigrationUri(
      migrationUri([{ ...firstAccount, name: "second@example.invalid", secret: [8, 9] }], {
        batchSize: 2,
        batchIndex: 1,
        batchId: 77,
      }),
    );
    const first = parseGoogleMigrationUri(
      migrationUri([{ ...firstAccount, name: "first@example.invalid", secret: [6, 7] }], {
        batchSize: 2,
        batchIndex: 0,
        batchId: 77,
      }),
    );

    expect(assembler.add(second)).toEqual({ complete: false, received: 1, total: 2 });
    const completed = assembler.add(first);
    expect(completed.complete).toBe(true);
    expect(completed.accounts?.map((account) => account.account)).toEqual([
      "first@example.invalid",
      "second@example.invalid",
    ]);
  });

  it.each([
    [{ algorithm: 2 }, "unsupported by V1"],
    [{ digits: 2 }, "unsupported by V1"],
    [{ type: 1 }, "unsupported by V1"],
  ])("rejects migration accounts outside the V1 profile", (override: Partial<SyntheticOtp>, expected: string) => {
    const source = migrationUri([{ ...firstAccount, ...override }]);
    expect(() => parseGoogleMigrationUri(source)).toThrow(expected);
    try {
      parseGoogleMigrationUri(source);
    } catch (error) {
      expect(String(error)).not.toContain(source);
    }
  });

  it("rejects impossible batch sizes before retaining account secrets", () => {
    const source = migrationUri([firstAccount], { batchSize: 33, batchIndex: 0, batchId: 91 });
    expect(() => parseGoogleMigrationUri(source)).toThrow("metadata is unsupported");
  });

  it("rejects mixed batch metadata and clears secrets held by the partial batch", () => {
    const assembler = new MigrationBatchAssembler();
    const first = parseGoogleMigrationUri(migrationUri([firstAccount], { batchSize: 2, batchIndex: 0, batchId: 1 }));
    const heldSecret = first.accounts[0]!.secret;
    assembler.add(first);

    const other = parseGoogleMigrationUri(migrationUri([firstAccount], { batchSize: 2, batchIndex: 1, batchId: 2 }));
    expect(() => assembler.add(other)).toThrow("does not belong");
    expect([...heldSecret]).toEqual([0, 0, 0, 0, 0]);
  });
});
