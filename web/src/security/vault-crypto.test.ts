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
  encryptLegacyVault,
  encryptVault,
  encryptVaultForFormat,
  normalizeAndValidatePassphrase,
  unwrapVmkWithPassphrase,
  wrapVmkWithPassphrase,
  wrapVmkWithPassphraseForFormat,
  type Argon2idKdfMetadata,
  type RandomSource,
} from "./vault-crypto";
import { LEGACY_VAULT_FORMAT_VERSION, VAULT_FORMAT_VERSION, VAULT_ID_BYTES } from "./vault-format";

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

describe("Web vault crypto", () => {
  it("preserves the shipped Format-1 AES-256-GCM known-answer vector", async () => {
    const keyBytes = sequence(32, 0x00);
    const vaultId = sequence(VAULT_ID_BYTES, 0x00);
    const plaintext = new TextEncoder().encode("synthetic-vault-payload-only");
    const envelope = await encryptLegacyVault(
      plaintext,
      keyBytes,
      vaultId,
      7n,
      new FixedRandomSource([sequence(12, 0xa0)]),
    );

    expect(envelope.vaultFormatVersion).toBe(LEGACY_VAULT_FORMAT_VERSION);
    expect(hex(envelope.nonce)).toBe("a0a1a2a3a4a5a6a7a8a9aaab");
    expect(hex(envelope.ciphertext)).toBe("956112592dae76d60148f1b27216b4f300cd207cfdd62641f3604aff");
    expect(hex(envelope.tag)).toBe("fe8172af15306428c847087428f8395c");
    await expect(decryptVault(envelope, keyBytes)).resolves.toEqual(plaintext);
  });

  it("uses the distinct Format-2 authenticated domain and never cross-decrypts formats", async () => {
    const keyBytes = sequence(32, 0x00);
    const vaultId = sequence(VAULT_ID_BYTES, 0x00);
    const plaintext = new TextEncoder().encode("synthetic-vault-payload-only");
    const sourceBytes = sequence(12, 0xa0);
    const legacy = await encryptVaultForFormat(
      plaintext,
      keyBytes,
      vaultId,
      7n,
      LEGACY_VAULT_FORMAT_VERSION,
      new FixedRandomSource([sourceBytes]),
    );
    const current = await encryptVaultForFormat(
      plaintext,
      keyBytes,
      vaultId,
      7n,
      VAULT_FORMAT_VERSION,
      new FixedRandomSource([sourceBytes]),
    );
    expect(current.vaultFormatVersion).toBe(VAULT_FORMAT_VERSION);
    // AES-GCM keystream encryption is independent of AAD, so identical
    // key/nonce/plaintext yields identical ciphertext while the authenticated
    // tag changes with the Format-2 AAD domain.
    expect(current.ciphertext).toEqual(legacy.ciphertext);
    expect(current.tag).not.toEqual(legacy.tag);
    await expect(decryptVault(current, keyBytes)).resolves.toEqual(plaintext);
    await expect(decryptVault({ ...current, vaultFormatVersion: LEGACY_VAULT_FORMAT_VERSION }, keyBytes)).rejects.toThrow();
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
    expect(hex(derived)).toBe("fe495a7c9e2244d921169b177ad086861db297c9684f6a838bebc53765a65b97");
    derived.fill(0);
  });

  it("keeps VMK wrap crypto at Version 1 while carrying the associated Vault format metadata", async () => {
    const keyBytes = sequence(32, 0x00);
    const vaultId = sequence(VAULT_ID_BYTES, 0x00);
    const wrapped1 = await wrapVmkWithPassphraseForFormat(
      keyBytes,
      vaultId,
      PASSPHRASE,
      LEGACY_VAULT_FORMAT_VERSION,
      kdfFixture(),
      new FixedRandomSource([sequence(12, 0xb0)]),
    );
    const wrapped2 = await wrapVmkWithPassphraseForFormat(
      keyBytes,
      vaultId,
      PASSPHRASE,
      VAULT_FORMAT_VERSION,
      kdfFixture(),
      new FixedRandomSource([sequence(12, 0xb0)]),
    );

    expect(wrapped1.packageVersion).toBe(RECOVERY_PACKAGE_VERSION);
    expect(wrapped1.wrapVersion).toBe(VMK_WRAP_VERSION);
    expect(wrapped1.vaultFormatVersion).toBe(1);
    expect(wrapped2.vaultFormatVersion).toBe(2);
    expect(wrapped2.ciphertext).toEqual(wrapped1.ciphertext);
    expect(wrapped2.tag).toEqual(wrapped1.tag);
    await expect(unwrapVmkWithPassphrase(wrapped2, PASSPHRASE)).resolves.toEqual(keyBytes);
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

    await expect(unwrapVmkWithPassphrase({ ...wrapped, packageVersion: RECOVERY_PACKAGE_VERSION + 1 }, PASSPHRASE))
      .rejects.toThrow(/Recovery Package version/);
    await expect(unwrapVmkWithPassphrase({ ...wrapped, wrapVersion: VMK_WRAP_VERSION + 1 }, PASSPHRASE))
      .rejects.toThrow(/VMK wrap version/);
    await expect(derivePassphraseKek(PASSPHRASE, { ...kdfFixture(), version: ARGON2ID_VERSION + 1 }))
      .rejects.toThrow(/Argon2id version/);
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
