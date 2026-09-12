import { describe, expect, it, vi } from "vitest";
import { CanonicalDeviceManagement } from "./canonical-management";
import type { CanonicalWireOperation } from "./canonical-protocol-v2";
import {
  IndexedDbBrowserVaultStore,
  createBrowserCanonicalState,
  sanitizeBrowserCanonicalState,
  type BrowserCanonicalState,
} from "./security/browser-vault";
import { encryptVault, wrapVmkWithPassphrase } from "./security/vault-crypto";
import { encodeBase64UrlCanonical, type SessionWireOperation } from "./security/session-protocol-v2";
import type { CanonicalV2Transport } from "./serial";

const recoveryPassphrase = ["synthetic", "locked", "privacy", "fixture"].join(" ");
const deviceId = "00112233445566778899aabbccddeeff";

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

class MemoryBrowserStore {
  public constructor(private readonly state: BrowserCanonicalState) {}

  async get(vaultId: Uint8Array): Promise<BrowserCanonicalState | null> {
    if (vaultId.length !== this.state.vault.vaultId.length ||
        !vaultId.every((value, index) => value === this.state.vault.vaultId[index])) return null;
    return sanitizeBrowserCanonicalState(this.state);
  }

  async list(): Promise<BrowserCanonicalState[]> {
    return [sanitizeBrowserCanonicalState(this.state)];
  }

  asIndexedDb(): IndexedDbBrowserVaultStore {
    return this as unknown as IndexedDbBrowserVaultStore;
  }
}

class LockedTransport implements CanonicalV2Transport {
  public constructor(private readonly state: BrowserCanonicalState) {}

  async requestCanonicalV2(
    op: CanonicalWireOperation,
  ): Promise<Record<string, unknown>> {
    if (op === "hello") {
      return {
        device: "M5StickS3",
        device_id: deviceId,
        firmware: "0.1.0",
        protocol: 2,
        storage_schema: 2,
        vault_format: 1,
        build_commit: "synthetic",
        state: "locked",
        storage_ready: true,
        vault_present: true,
        vault_id: encodeBase64UrlCanonical(this.state.vault.vaultId),
        generation: this.state.vault.generation.toString(10),
        registration_present: true,
        registration_id: encodeBase64UrlCanonical(this.state.trustedBrowser.registrationId),
        registration_epoch: this.state.trustedBrowser.epoch,
        brk_public_key: encodeBase64UrlCanonical(this.state.trustedBrowser.brkPublicKeyRaw),
      };
    }
    if (op === "time.status") {
      return {
        readiness: "not_synced",
        source: "none",
        last_sync_unix_seconds: "0",
        age_seconds: 0,
        resync_due: false,
      };
    }
    throw new Error(`unexpected canonical operation ${op}`);
  }

  async requestV2(op: SessionWireOperation): Promise<Record<string, unknown>> {
    throw new Error(`LOCKED refresh must not start a session: ${op}`);
  }

  async close(): Promise<void> {}
}

describe("canonical management LOCKED privacy", () => {
  it("does not decrypt browser Vault metadata while Device is LOCKED", async () => {
    const vmk = bytes(32, 3);
    const vaultId = bytes(16, 41);
    const plaintext = new TextEncoder().encode("synthetic encrypted fixture that must stay unopened while locked");
    const vault = await encryptVault(plaintext, vmk, vaultId, 4n);
    const recoveryWrappedVmk = await wrapVmkWithPassphrase(vmk, vaultId, recoveryPassphrase);
    const state = await createBrowserCanonicalState({
      vault,
      recoveryWrappedVmk,
      vmk,
      registrationEpoch: 2,
      status: "active",
      deviceMetadata: { deviceId },
    });
    plaintext.fill(0);
    vmk.fill(0);

    const decryptSpy = vi.spyOn(crypto.subtle, "decrypt");
    try {
      const transport = new LockedTransport(state);
      const initialHello = {
        device: "M5StickS3",
        deviceId,
        firmware: "0.1.0",
        protocol: 2 as const,
        storageSchema: 2 as const,
        vaultFormat: 1 as const,
        buildCommit: "synthetic",
        state: "locked" as const,
        storageReady: true,
        vaultPresent: true,
        vaultId: state.vault.vaultId.slice(),
        generation: state.vault.generation,
        registrationPresent: true,
        registrationId: state.trustedBrowser.registrationId.slice(),
        registrationEpoch: state.trustedBrowser.epoch,
        brkPublicKey: state.trustedBrowser.brkPublicKeyRaw.slice(),
      };
      const management = new CanonicalDeviceManagement(
        transport,
        initialHello,
        new MemoryBrowserStore(state).asIndexedDb(),
      );

      const snapshot = await management.refresh();
      expect(snapshot.hello.state).toBe("locked");
      expect(snapshot.browserOwnership).toBe("active");
      expect(snapshot.accounts).toEqual([]);
      expect(snapshot.wifi).toEqual({ configured: false, ssid: "" });
      expect(snapshot.time.readiness).toBe("not_synced");
      expect(decryptSpy).not.toHaveBeenCalled();
    } finally {
      decryptSpy.mockRestore();
    }
  });
});
