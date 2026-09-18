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

async function createActiveStateFixture(): Promise<BrowserCanonicalState> {
  const vmk = bytes(32, 73);
  const vaultId = bytes(16, 117);
  const plaintext = new TextEncoder().encode("synthetic active writer fixture");
  const vault = await encryptVault(plaintext, vmk, vaultId, 7n);
  const recoveryWrappedVmk = await wrapVmkWithPassphrase(vmk, vaultId, recoveryPassphrase);
  const state = await createBrowserCanonicalState({
    vault,
    recoveryWrappedVmk,
    vmk,
    registrationEpoch: 3,
    status: "active",
    deviceMetadata: { deviceId },
  });
  plaintext.fill(0);
  vmk.fill(0);
  return state;
}

function initialHelloFor(
  state: BrowserCanonicalState,
  runtimeState: "locked" | "unlocked",
) {
  return {
    device: "M5StickS3",
    deviceId,
    firmware: "0.1.0",
    protocol: 2 as const,
    storageSchema: 2 as const,
    vaultFormat: 1 as const,
    supportedVaultFormats: [1, 2] as const,
    buildCommit: "synthetic",
    state: runtimeState,
    storageReady: true,
    recoveryResetRequired: false,
    factoryResetPresenceRequired: true,
    vaultPresent: true,
    vaultId: state.vault.vaultId.slice(),
    generation: state.vault.generation,
    registrationPresent: true,
    registrationId: state.trustedBrowser.registrationId.slice(),
    registrationEpoch: state.trustedBrowser.epoch,
    brkPublicKey: state.trustedBrowser.brkPublicKeyRaw.slice(),
  };
}

class TimeMutationTransport implements CanonicalV2Transport {
  public readonly operations: CanonicalWireOperation[] = [];
  public timeSyncUnixSeconds: string | null = null;
  public helloSeen = false;

  public constructor(
    private readonly state: BrowserCanonicalState,
    private readonly runtimeState: "locked" | "unlocked",
  ) {}

  async requestCanonicalV2(
    op: CanonicalWireOperation,
    params: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    this.operations.push(op);
    if (op === "hello") {
      this.helloSeen = true;
      return {
        device: "M5StickS3",
        device_id: deviceId,
        firmware: "0.1.0",
        protocol: 2,
        storage_schema: 2,
        vault_format: 1,
        supported_vault_formats: [1, 2],
        build_commit: "synthetic",
        state: this.runtimeState,
        storage_ready: true,
        recovery_reset_required: false,
        factory_reset_presence_required: true,
        vault_present: true,
        vault_id: encodeBase64UrlCanonical(this.state.vault.vaultId),
        generation: this.state.vault.generation.toString(10),
        registration_present: true,
        registration_id: encodeBase64UrlCanonical(this.state.trustedBrowser.registrationId),
        registration_epoch: this.state.trustedBrowser.epoch,
        brk_public_key: encodeBase64UrlCanonical(this.state.trustedBrowser.brkPublicKeyRaw),
      };
    }
    if (op === "time.sync") {
      this.timeSyncUnixSeconds = String(params.unix_seconds);
      return {};
    }
    if (op === "time.status") {
      return {
        readiness: "ready",
        source: "usb",
        source_authenticity: "local_host_asserted",
        last_sync_unix_seconds: this.timeSyncUnixSeconds ?? "1789722000",
        age_seconds: 0,
        resync_due: false,
      };
    }
    throw new Error(`unexpected canonical operation ${op}`);
  }

  async requestV2(op: SessionWireOperation): Promise<Record<string, unknown>> {
    throw new Error(`time mutation test must not start a session: ${op}`);
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

  it("samples implicit PC time after the fresh write-time binding/UNLOCKED check", async () => {
    const state = await createActiveStateFixture();
    const transport = new TimeMutationTransport(state, "unlocked");
    const management = new CanonicalDeviceManagement(
      transport,
      initialHelloFor(state, "unlocked"),
      new MemoryBrowserStore(state).asIndexedDb(),
    );
    const sampledMilliseconds = 1_789_722_123_456;
    const dateSpy = vi.spyOn(Date, "now").mockImplementation(
      () => transport.helloSeen ? sampledMilliseconds : 1_000,
    );

    try {
      const status = await management.syncTime();
      expect(status.readiness).toBe("ready");
      expect(transport.operations).toEqual(["hello", "time.sync", "time.status"]);
      expect(transport.timeSyncUnixSeconds).toBe(String(Math.floor(sampledMilliseconds / 1000)));
    } finally {
      dateSpy.mockRestore();
    }
  });

  it("fails closed if Device becomes LOCKED after an eligible snapshot but before time.sync", async () => {
    const state = await createActiveStateFixture();
    const transport = new TimeMutationTransport(state, "locked");
    const management = new CanonicalDeviceManagement(
      transport,
      initialHelloFor(state, "unlocked"),
      new MemoryBrowserStore(state).asIndexedDb(),
    );

    await expect(management.syncTime()).rejects.toThrow(/UNLOCKED/);
    expect(transport.operations).toEqual(["hello"]);
    expect(transport.timeSyncUnixSeconds).toBeNull();
  });
});
