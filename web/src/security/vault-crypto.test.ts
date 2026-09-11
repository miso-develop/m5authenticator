import { describe, expect, it } from "vitest";
import {
  ARGON2ID_ITERATIONS,
  ARGON2ID_MEMORY_KIB,
  ARGON2ID_OUTPUT_BYTES,
  ARGON2ID_PARALLELISM,
  ARGON2ID_SALT_BYTES,
  ARGON2ID_VERSION,
  RECOVERY_PACKAGE_VERSION,
  VMK_WRAP_VERSION,
  decryptVault,
  derivePassphraseKek,
  encryptVault,
  normalizeAndValidatePassphrase,
  unwrapVmkWithPassphrase,
  wrapVmkWithPassphrase,
  type Argon2idKdfMetadata,
  type RandomSource,
} from "./vault-crypto";
import { VAULT_ID_BYTES } from "./vault-format";

const PASSPHRASE = "synthetic-passphrase-only-51";

function sequence(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

class FixedRandomSource implements RandomSource {
  constructor(private readonly chunks: Uint8Array[]) {}

  fill(target: Uint8Array): void {
    const next = this.chunks.shift();
    if (next === undefined || next.length !== target.length) {
      throw new Error("synthetic random source length mismatch");
    }
    target.set(next);
  }
}

class IncrementingRandomSource implements RandomSource {
  private start = 0x10;

  fill(target: Uint8Array): void {
    for (let index = 0; index < target.length; index += 1) {
      target[index] = (this.start + index) & 0xff;
    }
    this.start = (this.start + 0x40) & 0xff;
  }
}

function kdfFixture(): Argon2idKdfMetadata {
  return {
    algorithm: "argon2id",
    version: ARGON2ID_VERSION,
    memoryKiB: ARGON2ID_MEMORY_KIB,
    iterations: ARGON2ID_ITERATIONS,
    parallelism: ARGON2ID_PARALLELISM,
    salt: sequence(ARGON2ID_SALT_BYTES, 0x20),
    outputBytes: ARGON2ID_OUTPUT_BYTES,
  };
}

describe("V1 Web vault crypto", () => {
  it("matches the synthetic AES-256-GCM Vault known-answer vector", async () => {
    const keyBytes = sequence(32, 0x00);
    const vaultId = sequence(VAULT_ID_BYTES, 0x00);
    const plaintext = new TextEncoder().encode("synthetic-vault-payload-only");
    const envelope = await encryptVault(
      plaintext,
      keyBytes,
      vaultId,
      7n,
      new FixedRandomSource([sequence(12, 0xa0)]),
    );

    expect(hex(envelope.nonce)).toBe("a0a1a2a3a4a5a6a7a8a9aaab");
    expect(hex(envelope.ciphertext)).toBe(
      "956112592dae76d60148f1b27216b4f300cd207cfdd62641f3604aff",
    );
    expect(hex(envelope.tag)).toBe("fe8172af15306428c847087428f8395c");
    await expect(decryptVault(envelope, keyBytes)).resolves.toEqual(plaintext);
  });

  it("fails closed when Vault AAD or authentication tag changes", async () => {
    const keyBytes = sequence(32, 0x00);
    const envelope = await encryptVault(
      new TextEncoder().encode("synthetic-vault-payload-only"),
      keyBytes,
      sequence(VAULT_ID_BYTES, 0x00),
      7n,
      new FixedRandomSource([sequence(12, 0xa0)]),
    );

    await expect(decryptVault({ ...envelope, generation: 8n }, keyBytes)).rejects.toThrow();
    const changedTag = envelope.tag.slice();
    changedTag[0] = (changedTag[0] ?? 0) ^ 0x01;
    await expect(decryptVault({ ...envelope, tag: changedTag }, keyBytes)).rejects.toThrow();
  });

  it("matches the Argon2id v19 synthetic known-answer vector", async () => {
    const derived = await derivePassphraseKek(PASSPHRASE, kdfFixture());
    expect(hex(derived)).toBe(
      "fe495a7c9e2244d921169b177ad086861db297c9684f6a838bebc53765a65b97",
    );
    derived.fill(0);
  });

  it("matches the synthetic Passphrase-wrapped VMK known-answer vector", async () => {
    const keyBytes = sequence(32, 0x00);
    const vaultId = sequence(VAULT_ID_BYTES, 0x00);
    const wrapped = await wrapVmkWithPassphrase(
      keyBytes,
      vaultId,
      PASSPHRASE,
      kdfFixture(),
      new FixedRandomSource([sequence(12, 0xb0)]),
    );

    expect(wrapped.packageVersion).toBe(RECOVERY_PACKAGE_VERSION);
    expect(wrapped.wrapVersion).toBe(VMK_WRAP_VERSION);
    expect(hex(wrapped.nonce)).toBe("b0b1b2b3b4b5b6b7b8b9babb");
    expect(hex(wrapped.ciphertext)).toBe(
      "539fe562291b3e6503ec2f35c42cc8fd8b7e6ece98eed59410e780eabbd75fd5",
    );
    expect(hex(wrapped.tag)).toBe("04f7af67328726ba0bc6bc1c48a74f69");
    await expect(unwrapVmkWithPassphrase(wrapped, PASSPHRASE)).resolves.toEqual(keyBytes);
    await expect(
      unwrapVmkWithPassphrase(wrapped, "synthetic-different-passphrase-51"),
    ).rejects.toThrow();
  });

  it("fails closed for unsupported Recovery/KDF/wrap parameters before use", async () => {
    const keyBytes = sequence(32, 0x00);
    const vaultId = sequence(VAULT_ID_BYTES, 0x00);
    const wrapped = await wrapVmkWithPassphrase(
      keyBytes,
      vaultId,
      PASSPHRASE,
      kdfFixture(),
      new FixedRandomSource([sequence(12, 0xb0)]),
    );

    await expect(
      unwrapVmkWithPassphrase({ ...wrapped, packageVersion: RECOVERY_PACKAGE_VERSION + 1 }, PASSPHRASE),
    ).rejects.toThrow(/Recovery Package version/);
    await expect(
      unwrapVmkWithPassphrase({ ...wrapped, wrapVersion: VMK_WRAP_VERSION + 1 }, PASSPHRASE),
    ).rejects.toThrow(/VMK wrap version/);
    await expect(
      derivePassphraseKek(PASSPHRASE, { ...kdfFixture(), version: ARGON2ID_VERSION + 1 }),
    ).rejects.toThrow(/Argon2id version/);
  });

  it("requests a fresh nonce for every Vault encryption instead of deriving it from generation", async () => {
    const source = new IncrementingRandomSource();
    const keyBytes = sequence(32, 0x00);
    const vaultId = sequence(VAULT_ID_BYTES, 0x00);
    const plaintext = new TextEncoder().encode("synthetic-vault-payload-only");

    const first = await encryptVault(plaintext, keyBytes, vaultId, 9n, source);
    const second = await encryptVault(plaintext, keyBytes, vaultId, 9n, source);

    expect(first.nonce).not.toEqual(second.nonce);
    expect(first.ciphertext).not.toEqual(second.ciphertext);
  });

  it("NFC-normalizes Passphrase input before KDF processing", () => {
    const composed = normalizeAndValidatePassphrase("synthetic-caf\u00e9-passphrase");
    const decomposed = normalizeAndValidatePassphrase("synthetic-cafe\u0301-passphrase");
    expect(composed).toEqual(decomposed);
    composed.fill(0);
    decomposed.fill(0);
  });
});
