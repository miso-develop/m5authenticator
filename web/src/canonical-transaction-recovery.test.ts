import { describe, expect, it } from "vitest";
import { CanonicalDeviceManagement } from "./canonical-management";
import type { CanonicalWireOperation } from "./canonical-protocol-v2";
import {
  IndexedDbBrowserVaultStore,
  createBrowserCanonicalState,
  sanitizeBrowserCanonicalState,
  unwrapVmkForTrustedBrowser,
  type BrowserCanonicalState,
} from "./security/browser-vault";
import {
  IndexedDbBrowserTransactionJournal,
  PendingBrowserTransactionError,
  type BrowserPendingTransaction,
} from "./security/browser-transaction-journal";
import { rekeyTrustedBrowserState } from "./security/browser-vmk-rekey";
import { encodeVaultPlaintext, type VaultPlaintext } from "./security/vault-format";
import { encryptVault, wrapVmkWithPassphrase } from "./security/vault-crypto";
import { decodeBase64UrlCanonical, encodeBase64UrlCanonical, type SessionWireOperation } from "./security/session-protocol-v2";
import type { CanonicalV2Transport } from "./serial";

const passphrase = ["synthetic", "transaction", "recovery", "phrase"].join(" ");
const deviceId = "11223344556677889900aabbccddeeff";

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

class MemoryBrowserStore {
  private state: BrowserCanonicalState | null;

  constructor(initial: BrowserCanonicalState | null) {
    this.state = initial ? sanitizeBrowserCanonicalState(initial) : null;
  }

  async get(vaultId: Uint8Array): Promise<BrowserCanonicalState | null> {
    if (!this.state || !sameBytes(this.state.vault.vaultId, vaultId)) return null;
    return sanitizeBrowserCanonicalState(this.state);
  }

  async list(): Promise<BrowserCanonicalState[]> {
    return this.state ? [sanitizeBrowserCanonicalState(this.state)] : [];
  }

  async put(state: BrowserCanonicalState, expectedGeneration?: bigint): Promise<void> {
    if (expectedGeneration === undefined) {
      if (this.state) throw new Error("state already exists");
    } else if (!this.state || this.state.vault.generation !== expectedGeneration) {
      throw new Error("generation conflict");
    }
    this.state = sanitizeBrowserCanonicalState(state);
  }

  async delete(vaultId: Uint8Array, expectedGeneration?: bigint): Promise<void> {
    if (!this.state || !sameBytes(this.state.vault.vaultId, vaultId)) return;
    if (expectedGeneration !== undefined && this.state.vault.generation !== expectedGeneration) {
      throw new Error("generation conflict");
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

class GenerationDevice implements CanonicalV2Transport {
  connected = true;
  loseNextUpdateResponse = false;
  disconnectAfterNextUpdate = false;
  generation: bigint;
  readonly vaultId: Uint8Array;
  readonly registrationId: Uint8Array;
  readonly registrationEpoch: number;
  readonly brkPublicKey: Uint8Array;

  constructor(state: BrowserCanonicalState) {
    this.generation = state.vault.generation;
    this.vaultId = state.vault.vaultId.slice();
    this.registrationId = state.trustedBrowser.registrationId.slice();
    this.registrationEpoch = state.trustedBrowser.epoch;
    this.brkPublicKey = state.trustedBrowser.brkPublicKeyRaw.slice();
  }

  async requestCanonicalV2(
    op: CanonicalWireOperation,
    params: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    if (!this.connected) throw new Error("synthetic transport disconnected");
    if (op === "hello") return this.hello();
    if (op === "time.status") {
      return {
        readiness: "ready",
        source: "usb",
        last_sync_unix_seconds: "1789156800",
        age_seconds: 0,
        resync_due: false,
      };
    }
    if (op === "vault.update") {
      if (BigInt(String(params.expected_generation)) !== this.generation) {
        throw new Error("generation mismatch");
      }
      const next = BigInt(String(params.generation));
      const nextVaultId = decodeBase64UrlCanonical(String(params.vault_id), 16);
      if (next !== this.generation + 1n || !sameBytes(nextVaultId, this.vaultId)) {
        throw new Error("invalid candidate");
      }
      this.generation = next;
      if (this.disconnectAfterNextUpdate) {
        this.disconnectAfterNextUpdate = false;
        this.connected = false;
        throw new Error("synthetic response lost with disconnect");
      }
      if (this.loseNextUpdateResponse) {
        this.loseNextUpdateResponse = false;
        throw new Error("synthetic response lost");
      }
      return {};
    }
    throw new Error(`unexpected canonical operation ${op}`);
  }

  async requestV2(op: SessionWireOperation): Promise<Record<string, unknown>> {
    throw new Error(`unexpected session operation ${op}`);
  }

  async close(): Promise<void> {
    this.connected = false;
  }

  hello(): Record<string, unknown> {
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
      vault_present: true,
      vault_id: encodeBase64UrlCanonical(this.vaultId),
      generation: this.generation.toString(10),
      registration_present: true,
      registration_id: encodeBase64UrlCanonical(this.registrationId),
      registration_epoch: this.registrationEpoch,
      brk_public_key: encodeBase64UrlCanonical(this.brkPublicKey),
    };
  }
}

function helloFor(device: GenerationDevice) {
  const raw = device.hello();
  return {
    device: String(raw.device),
    deviceId: String(raw.device_id),
    firmware: String(raw.firmware),
    protocol: 2 as const,
    storageSchema: 2 as const,
    vaultFormat: 1 as const,
    buildCommit: String(raw.build_commit),
    state: "unlocked" as const,
    storageReady: true,
    vaultPresent: true,
    vaultId: decodeBase64UrlCanonical(String(raw.vault_id), 16),
    generation: BigInt(String(raw.generation)),
    registrationPresent: true,
    registrationId: decodeBase64UrlCanonical(String(raw.registration_id), 16),
    registrationEpoch: Number(raw.registration_epoch),
    brkPublicKey: decodeBase64UrlCanonical(String(raw.brk_public_key), 65),
  };
}

async function activeFixture(generation = 7n): Promise<{ state: BrowserCanonicalState; vmk: Uint8Array }> {
  const vmk = bytes(32, 9);
  const vaultId = bytes(16, 44);
  const plaintext: VaultPlaintext = {
    credentials: [{
      credentialId: bytes(16, 80),
      secret: bytes(20, 100),
      issuer: "Synthetic",
      account: "alice@example.com",
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
    const vault = await encryptVault(encoded, vmk, vaultId, generation);
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

describe("canonical browser transaction recovery", () => {
  it("promotes a committed generation after the Device response is lost", async () => {
    const { state, vmk } = await activeFixture();
    const store = new MemoryBrowserStore(state);
    const journal = new MemoryJournal();
    const device = new GenerationDevice(state);
    device.loseNextUpdateResponse = true;
    const manager = new CanonicalDeviceManagement(device, helloFor(device), store.asIndexedDb(), journal.asIndexedDb());
    await manager.initialize();

    await manager.renameAccount(encodeBase64UrlCanonical(bytes(16, 80)), "Primary");

    expect(device.generation).toBe(8n);
    expect(store.current()?.vault.generation).toBe(8n);
    expect(journal.current()).toBeNull();
    vmk.fill(0);
  });

  it("retains the encrypted N+1 candidate across an ambiguous disconnect and promotes on reconnect", async () => {
    const { state, vmk } = await activeFixture();
    const store = new MemoryBrowserStore(state);
    const journal = new MemoryJournal();
    const device = new GenerationDevice(state);
    device.disconnectAfterNextUpdate = true;
    const manager = new CanonicalDeviceManagement(device, helloFor(device), store.asIndexedDb(), journal.asIndexedDb());
    await manager.initialize();

    await expect(manager.renameAccount(encodeBase64UrlCanonical(bytes(16, 80)), "Primary"))
      .rejects.toThrow(PendingBrowserTransactionError);
    expect(store.current()?.vault.generation).toBe(7n);
    expect(journal.current()?.candidate.vault.generation).toBe(8n);

    device.connected = true;
    const reconnect = new CanonicalDeviceManagement(device, helloFor(device), store.asIndexedDb(), journal.asIndexedDb());
    await reconnect.initialize();
    expect(store.current()?.vault.generation).toBe(8n);
    expect(journal.current()).toBeNull();
    vmk.fill(0);
  });

  it("preserves the new VMK lineage when a re-key candidate must be reconciled after reconnect", async () => {
    const { state, vmk } = await activeFixture();
    const nextVmk = bytes(32, 170);
    const plaintext = new TextEncoder().encode("synthetic re-key payload");
    const nextVault = await encryptVault(plaintext, nextVmk, state.vault.vaultId, state.vault.generation + 1n);
    const nextRecoveryWrappedVmk = await wrapVmkWithPassphrase(nextVmk, state.vault.vaultId, passphrase);
    const candidate = await rekeyTrustedBrowserState({ current: state, nextVault, nextRecoveryWrappedVmk, nextVmk });
    const store = new MemoryBrowserStore(state);
    const journal = new MemoryJournal();
    await journal.stage({ kind: "vmk-rekey", expectedGeneration: state.vault.generation, candidate });
    const device = new GenerationDevice(candidate);

    const reconnect = new CanonicalDeviceManagement(device, helloFor(device), store.asIndexedDb(), journal.asIndexedDb());
    await reconnect.initialize();
    const promoted = store.current();
    expect(promoted?.vault.generation).toBe(candidate.vault.generation);
    const recoveredVmk = await unwrapVmkForTrustedBrowser(promoted!);
    expect(recoveredVmk).toEqual(nextVmk);
    expect(journal.current()).toBeNull();

    recoveredVmk.fill(0);
    plaintext.fill(0);
    nextVmk.fill(0);
    vmk.fill(0);
  });

  it("promotes a durably staged initial-provisioning candidate when the Device already committed it", async () => {
    const { state, vmk } = await activeFixture(1n);
    const store = new MemoryBrowserStore(null);
    const journal = new MemoryJournal();
    await journal.stage({ kind: "initial-provisioning", expectedGeneration: 0n, candidate: state });
    const device = new GenerationDevice(state);

    const reconnect = new CanonicalDeviceManagement(device, helloFor(device), store.asIndexedDb(), journal.asIndexedDb());
    await reconnect.initialize();
    expect(store.current()?.vault.generation).toBe(1n);
    expect(store.current()?.trustedBrowser.status).toBe("active");
    expect(journal.current()).toBeNull();
    vmk.fill(0);
  });

  it("promotes an exactly Device-confirmed replacement-pending browser after a crash", async () => {
    const { state, vmk } = await activeFixture();
    const pending = sanitizeBrowserCanonicalState({
      ...state,
      trustedBrowser: { ...state.trustedBrowser, status: "replacement-pending" },
    });
    const store = new MemoryBrowserStore(pending);
    const journal = new MemoryJournal();
    const device = new GenerationDevice(pending);

    const reconnect = new CanonicalDeviceManagement(device, helloFor(device), store.asIndexedDb(), journal.asIndexedDb());
    await reconnect.initialize();
    expect(store.current()?.trustedBrowser.status).toBe("active");
    vmk.fill(0);
  });
});
