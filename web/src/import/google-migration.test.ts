import { describe, expect, it } from "vitest";
import { MigrationBatchAssembler, parseGoogleMigrationUri } from "./google-migration";

const MIGRATION_SCHEME = "otp" + "auth-" + "migration://";

interface SyntheticOtp {
  secret: number[];
  name: string;
  issuer: string;
  algorithm?: number;
  digits?: number;
  type?: number;
  uniqueId?: string;
}

function migrationUri(
  accounts: SyntheticOtp[],
  options: { version?: number; batchSize?: number; batchIndex?: number; batchId?: number } = {},
): string {
  const payload = concat(
    ...accounts.map((account) => fieldBytes(1, otpParameters(account))),
    fieldVarint(2, options.version ?? 2),
    fieldVarint(3, options.batchSize ?? 1),
    fieldVarint(4, options.batchIndex ?? 0),
    fieldVarint(5, options.batchId ?? 12345),
  );
  let binary = "";
  for (const byte of payload) binary += String.fromCharCode(byte);
  return `${MIGRATION_SCHEME}offline?data=${encodeURIComponent(btoa(binary))}`;
}

function otpParameters(account: SyntheticOtp): Uint8Array {
  return concat(
    fieldBytes(1, Uint8Array.from(account.secret)),
    fieldString(2, account.name),
    fieldString(3, account.issuer),
    fieldVarint(4, account.algorithm ?? 1),
    fieldVarint(5, account.digits ?? 1),
    fieldVarint(6, account.type ?? 2),
    ...(account.uniqueId === undefined ? [] : [fieldString(8, account.uniqueId)]),
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

function syntheticAccounts(count: number, offset = 0): SyntheticOtp[] {
  return Array.from({ length: count }, (_, index) => ({
    secret: [((offset + index) % 200) + 1, 0x51],
    name: `synthetic-${offset + index}@example.invalid`,
    issuer: "Synthetic",
  }));
}

const firstAccount: SyntheticOtp = {
  secret: [1, 2, 3, 4, 5],
  name: "alice@example.invalid",
  issuer: "Example",
};

describe("Google Authenticator migration import", () => {
  it("decodes a current-compatible version 2 single-QR payload and ignores additive account fields", () => {
    const part = parseGoogleMigrationUri(migrationUri([{ ...firstAccount, uniqueId: "synthetic-entry-id" }], {
      version: 2,
      batchSize: 1,
      batchIndex: 0,
      batchId: 0,
    }));
    expect(part).toMatchObject({ version: 2, batchSize: 1, batchIndex: 0, batchId: 0 });
    expect(part.accounts[0]).toMatchObject({
      issuer: "Example",
      account: "alice@example.invalid",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    });
    expect([...part.accounts[0]!.secret]).toEqual([1, 2, 3, 4, 5]);
  });

  it("retains legacy version 1 migration compatibility", () => {
    const part = parseGoogleMigrationUri(migrationUri([firstAccount], { version: 1 }));
    expect(part.version).toBe(1);
    expect(part.accounts).toHaveLength(1);
  });

  it("assembles current-compatible version 2 multi-QR batches by index when scanned out of order", () => {
    const assembler = new MigrationBatchAssembler();
    const second = parseGoogleMigrationUri(
      migrationUri([{ ...firstAccount, name: "second@example.invalid", secret: [8, 9] }], {
        version: 2,
        batchSize: 2,
        batchIndex: 1,
        batchId: 77,
      }),
    );
    const first = parseGoogleMigrationUri(
      migrationUri([{ ...firstAccount, name: "first@example.invalid", secret: [6, 7] }], {
        version: 2,
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

  it("treats batch size as QR-part metadata rather than as the V1 account count", () => {
    const part = parseGoogleMigrationUri(migrationUri([firstAccount], {
      version: 2,
      batchSize: 33,
      batchIndex: 0,
      batchId: 123,
    }));
    expect(part.batchSize).toBe(33);

    const assembler = new MigrationBatchAssembler();
    expect(assembler.add(part)).toEqual({ complete: false, received: 1, total: 33 });
    assembler.clear();
  });

  it("rejects unknown migration versions with secret-free numeric diagnostics", () => {
    const source = migrationUri([firstAccount], { version: 3, batchSize: 1, batchIndex: 0 });
    let message = "";
    try {
      parseGoogleMigrationUri(source);
    } catch (error) {
      message = String(error);
    }
    expect(message).toContain("Unsupported Google Authenticator migration metadata");
    expect(message).toContain("version=3, batchSize=1, batchIndex=0");
    expect(message).not.toContain(source);
    expect(message).not.toContain("alice@example.invalid");
  });

  it.each([
    [{ batchSize: 0, batchIndex: 0 }, "batchSize=0, batchIndex=0"],
    [{ batchSize: 101, batchIndex: 0 }, "batchSize=101, batchIndex=0"],
    [{ batchSize: 2, batchIndex: 2 }, "batchSize=2, batchIndex=2"],
  ])("rejects malformed batch metadata without echoing the source", (metadata, expected) => {
    const source = migrationUri([firstAccount], { version: 2, ...metadata });
    let message = "";
    try {
      parseGoogleMigrationUri(source);
    } catch (error) {
      message = String(error);
    }
    expect(message).toContain("Invalid Google Authenticator migration metadata");
    expect(message).toContain(expected);
    expect(message).not.toContain(source);
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

  it("enforces the 32-account limit independently from QR batch size and clears rejected secrets", () => {
    const assembler = new MigrationBatchAssembler();
    const first = parseGoogleMigrationUri(migrationUri(syntheticAccounts(16), {
      batchSize: 2,
      batchIndex: 0,
      batchId: 444,
    }));
    const second = parseGoogleMigrationUri(migrationUri(syntheticAccounts(17, 16), {
      batchSize: 2,
      batchIndex: 1,
      batchId: 444,
    }));
    const heldSecrets = first.accounts.map((account) => account.secret);
    const rejectedSecrets = second.accounts.map((account) => account.secret);

    expect(assembler.add(first)).toEqual({ complete: false, received: 1, total: 2 });
    expect(() => assembler.add(second)).toThrow("exceeds the V1 account limit");
    for (const secret of [...heldSecrets, ...rejectedSecrets]) {
      expect([...secret].every((byte) => byte === 0)).toBe(true);
    }
    expect(assembler.hasPending()).toBe(false);
  });

  it("rejects mixed batch metadata and clears both held and rejected part secrets", () => {
    const assembler = new MigrationBatchAssembler();
    const first = parseGoogleMigrationUri(migrationUri([firstAccount], { batchSize: 2, batchIndex: 0, batchId: 1 }));
    const heldSecret = first.accounts[0]!.secret;
    assembler.add(first);

    const other = parseGoogleMigrationUri(migrationUri([firstAccount], { batchSize: 2, batchIndex: 1, batchId: 2 }));
    const rejectedSecret = other.accounts[0]!.secret;
    expect(() => assembler.add(other)).toThrow("does not belong");
    expect([...heldSecret]).toEqual([0, 0, 0, 0, 0]);
    expect([...rejectedSecret]).toEqual([0, 0, 0, 0, 0]);
    expect(assembler.hasPending()).toBe(false);
  });
});
