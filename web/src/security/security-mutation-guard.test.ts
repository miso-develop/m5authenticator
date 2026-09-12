import { describe, expect, it } from "vitest";
import type { BrowserCanonicalState } from "./browser-vault";
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

describe("Security & Recovery pending mutation guard", () => {
  it("allows export/passphrase mutation only when no Device outcome is pending", async () => {
    const canonical = state();
    await expect(assertNoPendingSecurityMutation(
      canonical,
      { async get() { return null; } },
      { async get() { return null; } },
    )).resolves.toBeUndefined();
  });

  it("blocks while a canonical Vault transaction is pending", async () => {
    const canonical = state();
    await expect(assertNoPendingSecurityMutation(
      canonical,
      { async get() { return { kind: "vmk-rekey" }; } },
      { async get() { return null; } },
    )).rejects.toBeInstanceOf(PendingBrowserTransactionError);
  });

  it("blocks while a Device reset intent is pending", async () => {
    const canonical = state();
    await expect(assertNoPendingSecurityMutation(
      canonical,
      { async get() { return null; } },
      { async get(deviceId: string) { return { deviceId }; } },
    )).rejects.toThrow(/pending Device reset outcome/i);
  });
});
