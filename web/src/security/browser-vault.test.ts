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
  sanitizeBrowserCanonicalState,
  unwrapVmkForTrustedBrowser,
} from "./browser-vault";
import { decryptVault, encryptVault, unwrapVmkWithPassphrase, wrapVmkWithPassphrase } from "./vault-crypto";

const oldPassphrase = ["synthetic", "recovery", "phrase", "alpha"].join(" ");
const newPassphrase = ["synthetic", "recovery", "phrase", "beta"].join(" ");
const blockedPersistenceMarker = ["must", "not", "persist"].join("-");

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

async function fixture() {
  const vmk = bytes(32, 3);
  const vaultId = bytes(16, 41);
  const plaintext = new TextEncoder().encode("synthetic-only-vault-plaintext");
  const vault = await encryptVault(plaintext, vmk, vaultId, 7n);
  const wrapped = await wrapVmkWithPassphrase(vmk, vaultId, oldPassphrase);
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

  it("exports only encrypted recovery material and imports a fresh replacement-pending browser", async () => {
    const { vmk, state } = await fixture();
    const serialized = exportRecoveryPackage(state);
    expect(serialized).not.toContain("buk");
    expect(serialized).not.toContain("brkPrivateKey");
    expect(serialized).not.toContain("synthetic-only-vault-plaintext");

    const imported = await importRecoveryPackage(serialized, oldPassphrase);
    expect(imported.trustedBrowser.status).toBe("replacement-pending");
    expect(imported.trustedBrowser.epoch).toBe(state.trustedBrowser.epoch + 1);
    expect(imported.trustedBrowser.registrationId).not.toEqual(state.trustedBrowser.registrationId);
    expect(imported.trustedBrowser.brkPublicKeyRaw).not.toEqual(state.trustedBrowser.brkPublicKeyRaw);
    expect(imported.vault.generation).toBe(state.vault.generation);

    const importedVmk = await unwrapVmkForTrustedBrowser(imported);
    expect(importedVmk).toEqual(vmk);
    importedVmk.fill(0);
    vmk.fill(0);
  });

  it("re-wraps the current VMK on Passphrase change without claiming old package revocation", async () => {
    const { vmk, state } = await fixture();
    const oldPackage = exportRecoveryPackage(state);
    const changed = await changeRecoveryPassphrase(state, oldPassphrase, newPassphrase);

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

  it("preserves same-generation browser security state when the encrypted Vault advances", async () => {
    const { vmk, state } = await fixture();
    const changed = await changeRecoveryPassphrase(state, oldPassphrase, newPassphrase);
    const plaintext = await decryptVault(state.vault, vmk);
    try {
      const nextVault = await encryptVault(plaintext, vmk, state.vault.vaultId, state.vault.generation + 1n);
      const staleVaultAdvance = sanitizeBrowserCanonicalState({ ...state, vault: nextVault });
      const merged = mergeVaultAdvanceWithCurrentBrowserState(changed, staleVaultAdvance, state.vault.generation);

      expect(merged.vault.generation).toBe(8n);
      expect(merged.trustedBrowser.registrationId).toEqual(changed.trustedBrowser.registrationId);
      expect(merged.trustedBrowser.wrappedVmk).toEqual(changed.trustedBrowser.wrappedVmk);

      const recovered = await unwrapVmkWithPassphrase(merged.recoveryWrappedVmk, newPassphrase);
      expect(recovered).toEqual(vmk);
      recovered.fill(0);
      await expect(unwrapVmkWithPassphrase(merged.recoveryWrappedVmk, oldPassphrase)).rejects.toThrow();
    } finally {
      plaintext.fill(0);
      vmk.fill(0);
    }
  });

  it("fails closed on unexpected generation divergence", async () => {
    const { vmk, vaultId, state } = await fixture();
    expect(() => assertCanonicalGeneration(state, { vaultId, generation: 7n })).not.toThrow();
    expect(() => assertCanonicalGeneration(state, { vaultId, generation: 8n })).toThrow(GenerationConflictError);
    expect(() => assertCanonicalGeneration(state, { vaultId: bytes(16, 99), generation: 7n })).toThrow(GenerationConflictError);
    vmk.fill(0);
  });

  it("projects persistence through an allowlist so accidental plaintext properties are dropped", async () => {
    const { vmk, state } = await fixture();
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
    expect(new TextDecoder().decode(decrypted)).toBe("synthetic-only-vault-plaintext");
    decrypted.fill(0);
    quickVmk.fill(0);
    vmk.fill(0);
  });
});
