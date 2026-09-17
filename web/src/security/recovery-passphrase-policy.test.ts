import { describe, expect, it } from "vitest";
import {
  RECOVERY_PASSPHRASE_DENYLIST_V1,
  RECOVERY_PASSPHRASE_DENYLIST_VERSION,
  RECOVERY_PASSPHRASE_POLICY_VERSION,
  WEAK_RECOVERY_PASSPHRASE_ERROR,
  isObviouslyWeakRecoveryPassphrase,
} from "./recovery-passphrase-policy";
import {
  AES_GCM_TAG_BYTES,
  ARGON2ID_ITERATIONS,
  ARGON2ID_MEMORY_KIB,
  ARGON2ID_OUTPUT_BYTES,
  ARGON2ID_PARALLELISM,
  ARGON2ID_SALT_BYTES,
  ARGON2ID_VERSION,
  RECOVERY_PACKAGE_VERSION,
  VMK_WRAP_VERSION,
  derivePassphraseKek,
  normalizeAndValidateNewRecoveryPassphrase,
  normalizeAndValidatePassphrase,
  unwrapVmkWithPassphrase,
  wrapVmkWithPassphraseForFormat,
  type Argon2idKdfMetadata,
  type PassphraseWrappedVmk,
  type RandomSource,
} from "./vault-crypto";
import { VAULT_FORMAT_VERSION, VAULT_ID_BYTES, buildVmkWrapAad } from "./vault-format";

function sequence(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
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

class RejectRandomUse implements RandomSource {
  fill(): void {
    throw new Error("random source must not be reached for a rejected Passphrase");
  }
}

async function createSyntheticPrePolicyWeakWrapper(
  passphrase: string,
  vmk: Uint8Array,
  vaultId: Uint8Array,
): Promise<PassphraseWrappedVmk> {
  const kdf = kdfFixture();
  const nonce = sequence(12, 0x70);
  const kek = await derivePassphraseKek(passphrase, kdf);
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      kek.slice().buffer,
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );
    const aad = buildVmkWrapAad({
      vaultId,
      packageVersion: RECOVERY_PACKAGE_VERSION,
      wrapVersion: VMK_WRAP_VERSION,
    });
    const combined = new Uint8Array(await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce.slice().buffer,
        additionalData: aad.slice().buffer,
        tagLength: 128,
      },
      key,
      vmk.slice().buffer,
    ));
    return {
      packageVersion: RECOVERY_PACKAGE_VERSION,
      wrapVersion: VMK_WRAP_VERSION,
      vaultFormatVersion: VAULT_FORMAT_VERSION,
      vaultId: vaultId.slice(),
      kdf: { ...kdf, salt: kdf.salt.slice() },
      nonce,
      ciphertext: combined.slice(0, combined.length - AES_GCM_TAG_BYTES),
      tag: combined.slice(combined.length - AES_GCM_TAG_BYTES),
    };
  } finally {
    kek.fill(0);
  }
}

const REJECTED = [
  "aaaaaaaaaaaaaaa",
  "界界界界界界界界界界界界界界界",
  "passwordpassword",
  "abcdabcdabcdabcd",
  "1234123412341234",
  "abababababababab",
  "012345678901234",
  "987654321098765",
  "abcdefghijklmnop",
  "qwertyuiopqwerty",
  "poiuytrewqpoiuyt",
  "abc-def_ghi.jklmnop",
  "correcthorsebatterystaple",
  "thisisapassword",
  " password1234567890 ",
  "LETMEIN123456789",
] as const;

const ACCEPTED = [
  "onlylowercasewordsthatstayvalid",
  "all digits 731905284617390",
  "no-uppercase-or-symbol-requirement",
  "これは十分に長く一意な回復用パスフレーズです",
  "pässphrase-with-varied-unicode-文字列",
] as const;

describe("weak-passphrase-policy-v1", () => {
  it("keeps the policy and bundled denylist explicitly versioned", () => {
    expect(RECOVERY_PASSPHRASE_POLICY_VERSION).toBe("weak-passphrase-policy-v1");
    expect(RECOVERY_PASSPHRASE_DENYLIST_VERSION).toBe("recovery-passphrase-denylist-v1");
    expect(RECOVERY_PASSPHRASE_DENYLIST_V1).toContain("correcthorsebatterystaple");
    expect(RECOVERY_PASSPHRASE_DENYLIST_V1).toContain("thisisapassword");
    expect(RECOVERY_PASSPHRASE_DENYLIST_V1).toContain("password1234567890");
    expect(RECOVERY_PASSPHRASE_DENYLIST_V1).toContain("letmein123456789");
  });

  it.each(REJECTED)("rejects deterministic weak vector %j", (passphrase) => {
    const normalized = passphrase.normalize("NFC");
    expect(isObviouslyWeakRecoveryPassphrase(normalized)).toBe(true);
    expect(() => normalizeAndValidateNewRecoveryPassphrase(passphrase)).toThrow(WEAK_RECOVERY_PASSPHRASE_ERROR);
  });

  it.each(ACCEPTED)("accepts valid long Passphrase %j without composition rules", (passphrase) => {
    const encoded = normalizeAndValidateNewRecoveryPassphrase(passphrase);
    expect(encoded.length).toBeGreaterThan(0);
    encoded.fill(0);
  });

  it("applies weak matching after NFC normalization without changing KDF bytes", () => {
    const composed = normalizeAndValidateNewRecoveryPassphrase("synthetic-caf\u00e9-passphrase");
    const decomposed = normalizeAndValidateNewRecoveryPassphrase("synthetic-cafe\u0301-passphrase");
    expect(composed).toEqual(decomposed);
    composed.fill(0);
    decomposed.fill(0);
  });

  it("rejects a weak new wrap before nonce generation while preserving bounds-only legacy KDF input", async () => {
    const weak = "aaaaaaaaaaaaaaa";
    const legacyInput = normalizeAndValidatePassphrase(weak);
    expect(new TextDecoder().decode(legacyInput)).toBe(weak);
    legacyInput.fill(0);

    await expect(wrapVmkWithPassphraseForFormat(
      sequence(32, 0x00),
      sequence(VAULT_ID_BYTES, 0x10),
      weak,
      VAULT_FORMAT_VERSION,
      kdfFixture(),
      new RejectRandomUse(),
    )).rejects.toThrow(WEAK_RECOVERY_PASSPHRASE_ERROR);
  });

  it("still unwraps a synthetic Recovery wrapper created before the weak-policy boundary", async () => {
    const weak = "aaaaaaaaaaaaaaa";
    const vmk = sequence(32, 0x30);
    const vaultId = sequence(VAULT_ID_BYTES, 0x50);
    const wrapped = await createSyntheticPrePolicyWeakWrapper(weak, vmk, vaultId);
    const unwrapped = await unwrapVmkWithPassphrase(wrapped, weak);
    expect(unwrapped).toEqual(vmk);
    unwrapped.fill(0);
    vmk.fill(0);
  });
});
