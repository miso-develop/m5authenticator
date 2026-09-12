import { describe, expect, it } from "vitest";
import {
  createBrowserCanonicalState,
  sanitizeBrowserCanonicalState,
  unwrapVmkForTrustedBrowser,
} from "./security/browser-vault";
import { encryptVault, wrapVmkWithPassphrase } from "./security/vault-crypto";

const passphrase = ["synthetic", "clean", "recovery", "package", "phrase"].join(" ");

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

describe("clean replacement Device browser registration", () => {
  it("re-wraps the recovered VMK under fresh epoch-1 BUK/BRK/registration identity", async () => {
    const vmk = bytes(32, 0x21);
    const vaultId = bytes(16, 0x51);
    const plaintext = new TextEncoder().encode("synthetic clean replacement payload");
    try {
      const vault = await encryptVault(plaintext, vmk, vaultId, 9n);
      const recoveryWrappedVmk = await wrapVmkWithPassphrase(vmk, vaultId, passphrase);
      const imported = await createBrowserCanonicalState({
        vault,
        recoveryWrappedVmk,
        vmk,
        registrationEpoch: 4,
        status: "replacement-pending",
        deviceMetadata: { deviceId: "old-device" },
      });

      const recoveredVmk = await unwrapVmkForTrustedBrowser(imported);
      let replacementVmk: Uint8Array | null = null;
      try {
        const replacement = await createBrowserCanonicalState({
          vault: imported.vault,
          recoveryWrappedVmk: imported.recoveryWrappedVmk,
          vmk: recoveredVmk,
          registrationEpoch: 1,
          status: "active",
          deviceMetadata: { deviceId: "new-device" },
        });
        const safe = sanitizeBrowserCanonicalState(replacement);
        expect(safe.vault.generation).toBe(9n);
        expect(safe.trustedBrowser.epoch).toBe(1);
        expect(safe.trustedBrowser.status).toBe("active");
        expect(safe.deviceMetadata?.deviceId).toBe("new-device");
        expect(sameBytes(safe.trustedBrowser.registrationId, imported.trustedBrowser.registrationId)).toBe(false);
        expect(sameBytes(safe.trustedBrowser.brkPublicKeyRaw, imported.trustedBrowser.brkPublicKeyRaw)).toBe(false);

        replacementVmk = await unwrapVmkForTrustedBrowser(safe);
        expect(replacementVmk).toEqual(vmk);
        replacementVmk.fill(0);
        replacementVmk = null;

        const tamperedRegistration = sanitizeBrowserCanonicalState({
          ...safe,
          trustedBrowser: {
            ...safe.trustedBrowser,
            registrationId: safe.trustedBrowser.registrationId.slice(),
          },
        });
        tamperedRegistration.trustedBrowser.registrationId[0] ^= 0x01;
        await expect(unwrapVmkForTrustedBrowser(tamperedRegistration)).rejects.toThrow();

        const tamperedEpoch = sanitizeBrowserCanonicalState({
          ...safe,
          trustedBrowser: {
            ...safe.trustedBrowser,
            epoch: 2,
          },
        });
        await expect(unwrapVmkForTrustedBrowser(tamperedEpoch)).rejects.toThrow();
      } finally {
        replacementVmk?.fill(0);
        recoveredVmk.fill(0);
      }
    } finally {
      plaintext.fill(0);
      vmk.fill(0);
      vaultId.fill(0);
    }
  });
});
