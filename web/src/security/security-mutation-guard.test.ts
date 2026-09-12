import { describe, expect, it } from "vitest";
import type { BrowserCanonicalState } from "./browser-vault";
import type { BrowserResetIntent } from "./browser-reset-intent";
import { PendingBrowserTransactionError } from "./browser-transaction-journal";
import { assertNoPendingSecurityMutation } from "./security-mutation-guard";

function state(): BrowserCanonicalState {
  return {
    deviceMetadata: { deviceId: "00112233445566778899aabbccddeeff" },
    vault: {
      vaultId: Uint8Array.from({ length: 16 }, (_, index) => index + 1),
      generation: 7n,
    },
  } as unknown as BrowserCanonicalState;
}

function resetIntent(
  canonical: BrowserCanonicalState,
  deviceId = canonical.deviceMetadata?.deviceId ?? "",
): BrowserResetIntent {
  return {
    deviceId,
    affectedVaults: [{
      vaultId: canonical.vault.vaultId.slice(),
      generation: canonical.vault.generation,
    }],
  };
}

describe("Security & Recovery pending mutation guard", () => {
  it("allows export/passphrase mutation only when no Device outcome is pending", async () => {
    const canonical = state();
    await expect(assertNoPendingSecurityMutation(
      canonical,
      { async get() { return null; } },
      { async list() { return []; } },
    )).resolves.toBeUndefined();
  });

  it("blocks while a canonical Vault transaction is pending", async () => {
    const canonical = state();
    await expect(assertNoPendingSecurityMutation(
      canonical,
      { async get() { return { kind: "vmk-rekey" }; } },
      { async list() { return []; } },
    )).rejects.toBeInstanceOf(PendingBrowserTransactionError);
  });

  it("blocks while a Device reset intent is pending", async () => {
    const canonical = state();
    await expect(assertNoPendingSecurityMutation(
      canonical,
      { async get() { return null; } },
      { async list() { return [resetIntent(canonical)]; } },
    )).rejects.toThrow(/pending Device reset outcome/i);
  });

  it("blocks by affected Vault even when Device-ID recovery changed the reset-intent Device ID", async () => {
    const canonical = state();
    await expect(assertNoPendingSecurityMutation(
      canonical,
      { async get() { return null; } },
      { async list() { return [resetIntent(canonical, "ffeeddccbbaa00998877665544332211")]; } },
    )).rejects.toThrow(/pending Device reset outcome/i);
  });
});
