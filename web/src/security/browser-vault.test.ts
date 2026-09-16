import { describe, expect, it } from "vitest";
import {
  GenerationConflictError,
  RECOVERY_PASSPHRASE_CHANGE_NOTICE,
  assertCanonicalGeneration,
  changeRecoveryPassphrase,
  createBrowserCanonicalState,
  exportRecoveryPackage,
  importRecoveryPackage,
  mergeVaultAdvanceWithCurrentBrowserState,
  parseRecoveryPackage,
  sanitizeBrowserCanonicalState,
  unwrapVmkForTrustedBrowser,
} from "./browser-vault";
import {
  decryptVault,
  encryptVaultForFormat,
  unwrapVmkWithPassphrase,
  wrapVmkWithPassphraseForFormat,
} from "./vault-crypto";
import {
  LEGACY_VAULT_FORMAT_VERSION,
  VAULT_FORMAT_VERSION,
  decodeVaultPlaintext,
  encodeVaultPlaintext,
  type SupportedVaultFormatVersion,
  type VaultPlaintext,
} from "./vault-format";

const oldPassphrase = ["synthetic", "recovery", "phrase", "alpha"].join(" ");
const newPassphrase = ["synthetic", "recovery", "phrase", "beta"].join(" ");
const blockedPersistenceMarker = ["must", "not", "persist"].join("-");

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function samplePlaintext(autoLockDays: number | null): VaultPlaintext {
  return {
    credentials: [{
      credentialId: bytes(16, 0x20),
      secret: bytes(20, 0x40),
      issuer: "synthetic-issuer-only",
      account: "synthetic-account-only",
      displayName: "synthetic-display-only",
      algorithm: "SHA1",
      digits: 6,
      periodSeconds: 30,
      manualOrder: 0,
    }],
    wifi: null,
    autoLockDays,
  };
}

async function fixture(format: SupportedVaultFormatVersion = VAULT_FORMAT_VERSION, autoLockDays: number | null = null) {
  const vmk = bytes(32, 3);
  const vaultId = bytes(16, 41);
  const logical = samplePlaintext(format === LEGACY_VAULT_FORMAT_VERSION ? null : autoLockDays);
  const plaintext = encodeVaultPlaintext(logical, format);
  const vault = await encryptVaultForFormat(plaintext, vmk, vaultId, 7n, format);
  const wrapped = await wrapVmkWithPassphraseForFormat(vmk, vaultId, oldPassphrase, format);
  const state = await createBrowserCanonicalState({
    vault,
    recoveryWrappedVmk: wrapped,
    vmk,
    registrationEpoch: 4,
    status: "active",
    deviceMetadata: { deviceId: "synthetic-device" },
  });
  plaintext.fill(0);
  return { vmk, vaultId, state };
}

describe("browser canonical Vault", () => {
  it("uses non-extractable browser keys and a BUK-wrapped quick-unlock VMK", async () => {
    const { vmk, state } = await fixture();
    expect(state.trustedBrowser.buk.extractable).toBe(false);
    expect(state.trustedBrowser.brkPrivateKey.extractable).toBe(false);
    expect(state.trustedBrowser.brkPublicKeyRaw).toHaveLength(65);
    expect(state.trustedBrowser.status).toBe("active");

    const unlocked = await unwrapVmkForTrustedBrowser(state);
    expect(unlocked).toEqual(vmk);
    unlocked.fill(0);
    vmk.fill(0);
  });

  it.each([
    [LEGACY_VAULT_FORMAT_VERSION, null],
    [VAULT_FORMAT_VERSION, 31],
  ] as const)("exports/imports Recovery Package v1 carrying Vault Format %i", async (format, autoLockDays) => {
    const { vmk, state } = await fixture(format, autoLockDays);
    const serialized = exportRecoveryPackage(state);
    expect(serialized).not.toContain("buk");
    expect(serialized).not.toContain("brkPrivateKey");
    expect(JSON.parse(serialized).packageVersion).toBe(1);
    expect(JSON.parse(serialized).vault.vaultFormatVersion).toBe(format);

    const imported = await importRecoveryPackage(serialized, oldPassphrase);
    expect(imported.vault.vaultFormatVersion).toBe(format);
    expect(imported.recoveryWrappedVmk.vaultFormatVersion).toBe(format);
    expect(imported.trustedBrowser.status).toBe("replacement-pending");
    expect(imported.trustedBrowser.epoch).toBe(state.trustedBrowser.epoch + 1);

    const importedVmk = await unwrapVmkForTrustedBrowser(imported);
    const decrypted = await decryptVault(imported.vault, importedVmk);
    const logical = decodeVaultPlaintext(decrypted, format);
    expect(logical.autoLockDays).toBe(format === 1 ? null : autoLockDays);
    for (const credential of logical.credentials) credential.secret.fill(0);
    decrypted.fill(0);
    importedVmk.fill(0);
    vmk.fill(0);
  });

  it("rejects unknown Recovery Vault formats and mismatched wrapper metadata", async () => {
    const { vmk, state } = await fixture();
    const parsed = JSON.parse(exportRecoveryPackage(state));
    parsed.vault.vaultFormatVersion = 3;
    expect(() => parseRecoveryPackage(JSON.stringify(parsed))).toThrow(/unsupported vault.vaultFormatVersion/);

    const mismatched = JSON.parse(exportRecoveryPackage(state));
    mismatched.wrappedVmk.vaultFormatVersion = 1;
    expect(() => parseRecoveryPackage(JSON.stringify(mismatched))).toThrow(/format mismatch/);
    vmk.fill(0);
  });

  it("re-wraps the current VMK on Passphrase change without changing Vault format", async () => {
    const { vmk, state } = await fixture(VAULT_FORMAT_VERSION, 7);
    const oldPackage = exportRecoveryPackage(state);
    const changed = await changeRecoveryPassphrase(state, oldPassphrase, newPassphrase);
    expect(changed.vault.vaultFormatVersion).toBe(VAULT_FORMAT_VERSION);
    expect(changed.recoveryWrappedVmk.vaultFormatVersion).toBe(VAULT_FORMAT_VERSION);

    const currentVmk = await unwrapVmkWithPassphrase(changed.recoveryWrappedVmk, newPassphrase);
    expect(currentVmk).toEqual(vmk);
    currentVmk.fill(0);
    await expect(unwrapVmkWithPassphrase(changed.recoveryWrappedVmk, oldPassphrase)).rejects.toThrow();

    const historical = await importRecoveryPackage(oldPackage, oldPassphrase);
    const historicalVmk = await unwrapVmkForTrustedBrowser(historical);
    expect(historicalVmk).toEqual(vmk);
    historicalVmk.fill(0);
    expect(RECOVERY_PASSPHRASE_CHANGE_NOTICE).toContain("does not cryptographically revoke");
    vmk.fill(0);
  });

  it("preserves current browser security state while accepting an F1-to-F2 generation advance", async () => {
    const { vmk, state } = await fixture(LEGACY_VAULT_FORMAT_VERSION);
    const plaintext = await decryptVault(state.vault, vmk);
    const logical = decodeVaultPlaintext(plaintext, LEGACY_VAULT_FORMAT_VERSION);
    const encodedV2 = encodeVaultPlaintext({ ...logical, autoLockDays: 1 }, VAULT_FORMAT_VERSION);
    try {
      const nextVault = await encryptVaultForFormat(
        encodedV2,
        vmk,
        state.vault.vaultId,
        state.vault.generation + 1n,
        VAULT_FORMAT_VERSION,
      );
      const incoming = sanitizeBrowserCanonicalState({
        ...state,
        vault: nextVault,
        recoveryWrappedVmk: { ...state.recoveryWrappedVmk, vaultFormatVersion: VAULT_FORMAT_VERSION },
      });
      const merged = mergeVaultAdvanceWithCurrentBrowserState(state, incoming, state.vault.generation);
      expect(merged.vault.generation).toBe(8n);
      expect(merged.vault.vaultFormatVersion).toBe(2);
      expect(merged.recoveryWrappedVmk.vaultFormatVersion).toBe(2);
      expect(merged.trustedBrowser.registrationId).toEqual(state.trustedBrowser.registrationId);
    } finally {
      for (const credential of logical.credentials) credential.secret.fill(0);
      plaintext.fill(0);
      encodedV2.fill(0);
      vmk.fill(0);
    }
  });

  it("fails closed on generation or format divergence", async () => {
    const { vmk, vaultId, state } = await fixture();
    expect(() => assertCanonicalGeneration(state, {
      vaultId,
      generation: 7n,
      vaultFormatVersion: 2,
    })).not.toThrow();
    expect(() => assertCanonicalGeneration(state, { vaultId, generation: 8n, vaultFormatVersion: 2 }))
      .toThrow(GenerationConflictError);
    expect(() => assertCanonicalGeneration(state, { vaultId, generation: 7n, vaultFormatVersion: 1 }))
      .toThrow(GenerationConflictError);
    vmk.fill(0);
  });

  it("projects persistence through an allowlist so accidental plaintext properties are dropped", async () => {
    const { vmk, state } = await fixture(VAULT_FORMAT_VERSION, 1);
    const tainted = Object.assign({}, state, {
      plaintextVmk: blockedPersistenceMarker,
      passphrase: blockedPersistenceMarker,
      decryptedVault: { account: blockedPersistenceMarker },
    });
    const safe = sanitizeBrowserCanonicalState(tainted);
    expect(Object.hasOwn(safe, "plaintextVmk")).toBe(false);
    expect(Object.hasOwn(safe, "passphrase")).toBe(false);
    expect(Object.hasOwn(safe, "decryptedVault")).toBe(false);

    const quickVmk = await unwrapVmkForTrustedBrowser(safe);
    const decrypted = await decryptVault(safe.vault, quickVmk);
    const logical = decodeVaultPlaintext(decrypted, VAULT_FORMAT_VERSION);
    expect(logical.autoLockDays).toBe(1);
    for (const credential of logical.credentials) credential.secret.fill(0);
    decrypted.fill(0);
    quickVmk.fill(0);
    vmk.fill(0);
  });
});
