import { describe, expect, it } from "vitest";
import {
  createBrowserCanonicalState,
  unwrapVmkForTrustedBrowser,
} from "./browser-vault";
import { rekeyTrustedBrowserState } from "./browser-vmk-rekey";
import {
  decryptVault,
  encryptVault,
  wrapVmkWithPassphrase,
} from "./vault-crypto";

const passphrase = ["synthetic", "rekey", "recovery", "phrase"].join(" ");

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

describe("Trusted Browser VMK re-key", () => {
  it("preserves BUK/BRK/registration while replacing both VMK wrappers", async () => {
    const vaultId = bytes(16, 0x10);
    const oldVmk = bytes(32, 0x20);
    const newVmk = bytes(32, 0x60);
    const plaintext = new TextEncoder().encode("synthetic-vault-payload");
    const oldVault = await encryptVault(plaintext, oldVmk, vaultId, 4n);
    const oldRecovery = await wrapVmkWithPassphrase(oldVmk, vaultId, passphrase);
    const current = await createBrowserCanonicalState({
      vault: oldVault,
      recoveryWrappedVmk: oldRecovery,
      vmk: oldVmk,
      registrationEpoch: 3,
      status: "active",
      deviceMetadata: { deviceId: "synthetic-device" },
    });

    const nextVault = await encryptVault(plaintext, newVmk, vaultId, 5n);
    const nextRecovery = await wrapVmkWithPassphrase(newVmk, vaultId, passphrase);
    const rekeyed = await rekeyTrustedBrowserState({
      current,
      nextVault,
      nextRecoveryWrappedVmk: nextRecovery,
      nextVmk: newVmk,
    });

    expect(rekeyed.vault.generation).toBe(5n);
    expect(rekeyed.trustedBrowser.registrationId).toEqual(current.trustedBrowser.registrationId);
    expect(rekeyed.trustedBrowser.epoch).toBe(current.trustedBrowser.epoch);
    expect(rekeyed.trustedBrowser.brkPublicKeyRaw).toEqual(current.trustedBrowser.brkPublicKeyRaw);
    expect(rekeyed.trustedBrowser.buk).toBe(current.trustedBrowser.buk);
    expect(rekeyed.trustedBrowser.brkPrivateKey).toBe(current.trustedBrowser.brkPrivateKey);

    const unwrapped = await unwrapVmkForTrustedBrowser(rekeyed);
    expect(unwrapped).toEqual(newVmk);
    const decrypted = await decryptVault(rekeyed.vault, unwrapped);
    expect(decrypted).toEqual(plaintext);

    unwrapped.fill(0);
    decrypted.fill(0);
    plaintext.fill(0);
    oldVmk.fill(0);
    newVmk.fill(0);
  });
});
