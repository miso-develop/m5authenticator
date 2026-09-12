import { describe, expect, it } from "vitest";
import { CanonicalDeviceManagement } from "./canonical-management";
import type { CanonicalHelloData, CanonicalWireOperation } from "./canonical-protocol-v2";
import {
  IndexedDbBrowserVaultStore,
  createBrowserCanonicalState,
  sanitizeBrowserCanonicalState,
  type BrowserCanonicalState,
} from "./security/browser-vault";
import {
  IndexedDbBrowserTransactionJournal,
  PendingBrowserTransactionError,
  type BrowserPendingTransaction,
} from "./security/browser-transaction-journal";
import {
  IndexedDbBrowserResetIntentStore,
  type BrowserResetIntent,
} from "./security/browser-reset-intent";
import { encodeVaultPlaintext, type VaultPlaintext } from "./security/vault-format";
import { encryptVault, wrapVmkWithPassphrase } from "./security/vault-crypto";
import { encodeBase64UrlCanonical, type SessionWireOperation } from "./security/session-protocol-v2";
import type { CanonicalV2Transport } from "./serial";

const deviceId = "aabbccddeeff00112233445566778899";
const passphrase = ["synthetic", "reset", "cleanup", "recovery", "phrase"].join(" ");

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

class MemoryStore {
  private state: BrowserCanonicalState | null;
  failNextDelete = false;

  constructor(initial: BrowserCanonicalState) {
    this.state = sanitizeBrowserCanonicalState(initial);
  }

  async get(vaultId: Uint8Array): Promise<BrowserCanonicalState | null> {
    if (!this.state || !sameBytes(this.state.vault.vaultId, vaultId)) return null;
    return sanitizeBrowserCanonicalState(this.state);
  }

  async list(): Promise<BrowserCanonicalState[]> {
    return this.state ? [sanitizeBrowserCanonicalState(this.state)] : [];
  }

  async put(state: BrowserCanonicalState, expectedGeneration?: bigint): Promise<void> {
    if (expectedGeneration !== undefined && this.state?.vault.generation !== expectedGeneration) {
      throw new Error("generation conflict");
    }
    this.state = sanitizeBrowserCanonicalState(state);
  }

  async delete(vaultId: Uint8Array, expectedGeneration?: bigint): Promise<void> {
    if (!this.state || !sameBytes(this.state.vault.vaultId, vaultId)) return;
    if (expectedGeneration !== undefined && this.state.vault.generation !== expectedGeneration) {
      throw new Error("generation conflict");
    }
    if (this.failNextDelete) {
      this.failNextDelete = false;
      throw new Error("synthetic IndexedDB cleanup failure");
    }
    this.state = null;
  }

  current(): BrowserCanonicalState | null {
    return this.state ? sanitizeBrowserCanonicalState(this.state) : null;
  }

  asIndexedDb(): IndexedDbBrowserVaultStore {
    return this as unknown as IndexedDbBrowserVaultStore;
  }
}

class MemoryJournal {
  private pending: BrowserPendingTransaction | null = null;

  async get(vaultId: Uint8Array): Promise<BrowserPendingTransaction | null> {
    if (!this.pending || !sameBytes(this.pending.candidate.vault.vaultId, vaultId)) return null;
    return this.clone(this.pending);
  }

  async list(): Promise<BrowserPendingTransaction[]> {
    return this.pending ? [this.clone(this.pending)] : [];
  }

  async listForDevice(targetDeviceId: string): Promise<BrowserPendingTransaction[]> {
    return this.pending?.candidate.deviceMetadata?.deviceId === targetDeviceId
      ? [this.clone(this.pending)]
      : [];
  }

  async stage(value: BrowserPendingTransaction): Promise<void> {
    if (this.pending) throw new PendingBrowserTransactionError();
    this.pending = this.clone(value);
  }

  async delete(vaultId: Uint8Array): Promise<void> {
    if (this.pending && sameBytes(this.pending.candidate.vault.vaultId, vaultId)) this.pending = null;
  }

  current(): BrowserPendingTransaction | null {
    return this.pending ? this.clone(this.pending) : null;
  }

  asIndexedDb(): IndexedDbBrowserTransactionJournal {
    return this as unknown as IndexedDbBrowserTransactionJournal;
  }

  private clone(value: BrowserPendingTransaction): BrowserPendingTransaction {
    return {
      kind: value.kind,
      expectedGeneration: value.expectedGeneration,
      candidate: sanitizeBrowserCanonicalState(value.candidate),
    };
  }
}

class MemoryResetIntents {
  private intent: BrowserResetIntent | null = null;

  async get(targetDeviceId: string): Promise<BrowserResetIntent | null> {
    if (!this.intent || this.intent.deviceId !== targetDeviceId) return null;
    return this.clone(this.intent);
  }

  async stage(value: BrowserResetIntent): Promise<void> {
    if (this.intent) throw new Error("reset intent already exists");
    this.intent = this.clone(value);
  }

  async delete(targetDeviceId: string): Promise<void> {
    if (this.intent?.deviceId === targetDeviceId) this.intent = null;
  }

  current(): BrowserResetIntent | null {
    return this.intent ? this.clone(this.intent) : null;
  }

  asIndexedDb(): IndexedDbBrowserResetIntentStore {
    return this as unknown as IndexedDbBrowserResetIntentStore;
  }

  private clone(value: BrowserResetIntent): BrowserResetIntent {
    return {
      deviceId: value.deviceId,
      affectedVaults: value.affectedVaults.map((item) => ({
        vaultId: item.vaultId.slice(),
        generation: item.generation,
      })),
    };
  }
}

class ResetDevice implements CanonicalV2Transport {
  resetCommitted = false;

  constructor(private readonly state: BrowserCanonicalState) {}

  async requestCanonicalV2(op: CanonicalWireOperation): Promise<Record<string, unknown>> {
    if (op === "hello") return this.resetCommitted ? cleanHello() : provisionedHello(this.state);
    if (op === "time.status") return readyTime();
    if (op === "factory_reset") {
      this.resetCommitted = true;
      return {};
    }
    throw new Error(`unexpected canonical operation ${op}`);
  }

  async requestV2(op: SessionWireOperation): Promise<Record<string, unknown>> {
    throw new Error(`unexpected session operation ${op}`);
  }

  async close(): Promise<void> {}
}

function typedProvisionedHello(state: BrowserCanonicalState): CanonicalHelloData {
  return {
    device: "M5StickS3",
    deviceId,
    firmware: "0.1.0",
    protocol: 2,
    storageSchema: 2,
    vaultFormat: 1,
    buildCommit: "synthetic",
    state: "unlocked",
    storageReady: true,
    recoveryResetRequired: false,
    vaultPresent: true,
    vaultId: state.vault.vaultId.slice(),
    generation: state.vault.generation,
    registrationPresent: true,
    registrationId: state.trustedBrowser.registrationId.slice(),
    registrationEpoch: state.trustedBrowser.epoch,
    brkPublicKey: state.trustedBrowser.brkPublicKeyRaw.slice(),
  };
}

function provisionedHello(state: BrowserCanonicalState): Record<string, unknown> {
  return {
    device: "M5StickS3",
    device_id: deviceId,
    firmware: "0.1.0",
    protocol: 2,
    storage_schema: 2,
    vault_format: 1,
    build_commit: "synthetic",
    state: "unlocked",
    storage_ready: true,
    recovery_reset_required: false,
    vault_present: true,
    vault_id: encodeBase64UrlCanonical(state.vault.vaultId),
    generation: state.vault.generation.toString(10),
    registration_present: true,
    registration_id: encodeBase64UrlCanonical(state.trustedBrowser.registrationId),
    registration_epoch: state.trustedBrowser.epoch,
    brk_public_key: encodeBase64UrlCanonical(state.trustedBrowser.brkPublicKeyRaw),
  };
}

function cleanHello(): Record<string, unknown> {
  return {
    device: "M5StickS3",
    device_id: deviceId,
    firmware: "0.1.0",
    protocol: 2,
    storage_schema: 2,
    vault_format: 1,
    build_commit: "synthetic",
    state: "unprovisioned",
    storage_ready: false,
    recovery_reset_required: false,
    vault_present: false,
    vault_id: null,
    generation: "0",
    registration_present: false,
    registration_id: null,
    registration_epoch: 0,
    brk_public_key: null,
  };
}

function typedCleanHello(): CanonicalHelloData {
  return {
    device: "M5StickS3",
    deviceId,
    firmware: "0.1.0",
    protocol: 2,
    storageSchema: 2,
    vaultFormat: 1,
    buildCommit: "synthetic",
    state: "unprovisioned",
    storageReady: false,
    recoveryResetRequired: false,
    vaultPresent: false,
    vaultId: null,
    generation: 0n,
    registrationPresent: false,
    registrationId: null,
    registrationEpoch: 0,
    brkPublicKey: null,
  };
}

function readyTime(): Record<string, unknown> {
  return {
    readiness: "ready",
    source: "usb",
    last_sync_unix_seconds: "1789156800",
    age_seconds: 0,
    resync_due: false,
  };
}

async function fixture(): Promise<{ state: BrowserCanonicalState; vmk: Uint8Array }> {
  const vmk = bytes(32, 0x31);
  const vaultId = bytes(16, 0x61);
  const plaintext: VaultPlaintext = {
    credentials: [{
      credentialId: bytes(16, 0x81),
      secret: bytes(20, 0xa1),
      issuer: "Synthetic",
      account: "reset@example.invalid",
      displayName: "",
      algorithm: "SHA1",
      digits: 6,
      periodSeconds: 30,
      manualOrder: 0,
    }],
    wifi: null,
  };
  const encoded = encodeVaultPlaintext(plaintext);
  try {
    const vault = await encryptVault(encoded, vmk, vaultId, 7n);
    const recoveryWrappedVmk = await wrapVmkWithPassphrase(vmk, vaultId, passphrase);
    const state = await createBrowserCanonicalState({
      vault,
      recoveryWrappedVmk,
      vmk,
      registrationEpoch: 3,
      status: "active",
      deviceMetadata: { deviceId },
    });
    return { state, vmk };
  } finally {
    encoded.fill(0);
    plaintext.credentials[0]!.credentialId.fill(0);
    plaintext.credentials[0]!.secret.fill(0);
  }
}

describe("Factory Reset browser cleanup reconciliation", () => {
  it("retains durable reset intent after local delete failure and completes cleanup on clean reconnect", async () => {
    const { state, vmk } = await fixture();
    try {
      const store = new MemoryStore(state);
      const journal = new MemoryJournal();
      const resetIntents = new MemoryResetIntents();
      const device = new ResetDevice(state);
      const manager = new CanonicalDeviceManagement(
        device,
        typedProvisionedHello(state),
        store.asIndexedDb(),
        journal.asIndexedDb(),
        resetIntents.asIndexedDb(),
      );
      await manager.initialize();

      store.failNextDelete = true;
      await expect(manager.factoryReset()).rejects.toThrow(PendingBrowserTransactionError);
      expect(device.resetCommitted).toBe(true);
      expect(store.current()).not.toBeNull();
      expect(journal.current()?.kind).toBe("factory-reset");
      expect(resetIntents.current()?.deviceId).toBe(deviceId);

      const reconnect = new CanonicalDeviceManagement(
        device,
        typedCleanHello(),
        store.asIndexedDb(),
        journal.asIndexedDb(),
        resetIntents.asIndexedDb(),
      );
      await reconnect.initialize();
      expect(store.current()).toBeNull();
      expect(journal.current()).toBeNull();
      expect(resetIntents.current()).toBeNull();
    } finally {
      vmk.fill(0);
    }
  });
});
