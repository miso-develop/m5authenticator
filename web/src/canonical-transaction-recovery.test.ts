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
const replacementDeviceId = "ffeeddccbbaa00998877665544332211";

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
    if (op === "time.status") return readyTime();
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
    return provisionedHello({
      state: {
        vault: { vaultId: this.vaultId, generation: this.generation },
        registrationId: this.registrationId,
        registrationEpoch: this.registrationEpoch,
        brkPublicKey: this.brkPublicKey,
      },
      targetDeviceId: deviceId,
    });
  }
}

class CleanDevice implements CanonicalV2Transport {
  connected = true;

  constructor(readonly targetDeviceId: string) {}

  async requestCanonicalV2(op: CanonicalWireOperation): Promise<Record<string, unknown>> {
    if (!this.connected) throw new Error("synthetic transport disconnected");
    if (op === "hello") return cleanHello(this.targetDeviceId);
    if (op === "time.status") return readyTime();
    throw new Error(`unexpected canonical operation ${op}`);
  }

  async requestV2(op: SessionWireOperation): Promise<Record<string, unknown>> {
    throw new Error(`unexpected session operation ${op}`);
  }

  async close(): Promise<void> {
    this.connected = false;
  }
}

class ResettingDevice implements CanonicalV2Transport {
  connected = true;
  resetCommitted = false;

  constructor(private readonly state: BrowserCanonicalState) {}

  async requestCanonicalV2(op: CanonicalWireOperation): Promise<Record<string, unknown>> {
    if (!this.connected) throw new Error("synthetic transport disconnected");
    if (op === "hello") {
      return this.resetCommitted ? cleanHello(deviceId) : provisionedHello({ state: browserBinding(this.state), targetDeviceId: deviceId });
    }
    if (op === "time.status") return readyTime();
    if (op === "factory_reset") {
      this.resetCommitted = true;
      this.connected = false;
      throw new Error("synthetic reset response lost");
    }
    throw new Error(`unexpected canonical operation ${op}`);
  }

  async requestV2(op: SessionWireOperation): Promise<Record<string, unknown>> {
    throw new Error(`unexpected session operation ${op}`);
  }

  async close(): Promise<void> {
    this.connected = false;
  }
}

class ProvisionedReplacementDevice implements CanonicalV2Transport {
  constructor(
    private readonly state: BrowserCanonicalState,
    private readonly targetDeviceId: string,
  ) {}

  async requestCanonicalV2(op: CanonicalWireOperation): Promise<Record<string, unknown>> {
    if (op === "hello") return provisionedHello({ state: browserBinding(this.state), targetDeviceId: this.targetDeviceId });
    if (op === "time.status") return readyTime();
    throw new Error(`unexpected canonical operation ${op}`);
  }

  async requestV2(op: SessionWireOperation): Promise<Record<string, unknown>> {
    throw new Error(`unexpected session operation ${op}`);
  }

  async close(): Promise<void> {}
}

function browserBinding(state: BrowserCanonicalState) {
  return {
    vault: { vaultId: state.vault.vaultId, generation: state.vault.generation },
    registrationId: state.trustedBrowser.registrationId,
    registrationEpoch: state.trustedBrowser.epoch,
    brkPublicKey: state.trustedBrowser.brkPublicKeyRaw,
  };
}

function provisionedHello(input: {
  state: {
    vault: { vaultId: Uint8Array; generation: bigint };
    registrationId: Uint8Array;
    registrationEpoch: number;
    brkPublicKey: Uint8Array;
  };
  targetDeviceId: string;
}): Record<string, unknown> {
  return {
    device: "M5StickS3",
    device_id: input.targetDeviceId,
    firmware: "0.1.0",
    protocol: 2,
    storage_schema: 2,
    vault_format: 1,
    build_commit: "synthetic",
    state: "unlocked",
    storage_ready: true,
    recovery_reset_required: false,
    vault_present: true,
    vault_id: encodeBase64UrlCanonical(input.state.vault.vaultId),
    generation: input.state.vault.generation.toString(10),
    registration_present: true,
    registration_id: encodeBase64UrlCanonical(input.state.registrationId),
    registration_epoch: input.state.registrationEpoch,
    brk_public_key: encodeBase64UrlCanonical(input.state.brkPublicKey),
  };
}

function cleanHello(targetDeviceId: string): Record<string, unknown> {
  return {
    device: "M5StickS3",
    device_id: targetDeviceId,
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

function readyTime(): Record<string, unknown> {
  return {
    readiness: "ready",
    source: "usb",
    last_sync_unix_seconds: "1789156800",
    age_seconds: 0,
    resync_due: false,
  };
}

function helloFor(device: GenerationDevice) {
  const raw = device.hello();
  return typedProvisionedHello(raw);
}

function typedProvisionedHello(raw: Record<string, unknown>) {
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
    recoveryResetRequired: false,
    vaultPresent: true,
    vaultId: decodeBase64UrlCanonical(String(raw.vault_id), 16),
    generation: BigInt(String(raw.generation)),
    registrationPresent: true,
    registrationId: decodeBase64UrlCanonical(String(raw.registration_id), 16),
    registrationEpoch: Number(raw.registration_epoch),
    brkPublicKey: decodeBase64UrlCanonical(String(raw.brk_public_key), 65),
  };
}

function typedCleanHello(targetDeviceId: string) {
  return {
    device: "M5StickS3",
    deviceId: targetDeviceId,
    firmware: "0.1.0",
    protocol: 2 as const,
    storageSchema: 2 as const,
    vaultFormat: 1 as const,
    buildCommit: "synthetic",
    state: "unprovisioned" as const,
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

  it("keeps a Factory Reset tombstone across response loss and deletes local state when clean Device state is proven", async () => {
    const { state, vmk } = await activeFixture();
    const store = new MemoryBrowserStore(state);
    const journal = new MemoryJournal();
    const device = new ResettingDevice(state);
    const manager = new CanonicalDeviceManagement(
      device,
      typedProvisionedHello(provisionedHello({ state: browserBinding(state), targetDeviceId: deviceId })),
      store.asIndexedDb(),
      journal.asIndexedDb(),
    );
    await manager.initialize();

    await expect(manager.factoryReset()).rejects.toThrow(PendingBrowserTransactionError);
    expect(journal.current()?.kind).toBe("factory-reset");
    expect(store.current()).not.toBeNull();

    const clean = new CleanDevice(deviceId);
    const reconnect = new CanonicalDeviceManagement(
      clean,
      typedCleanHello(deviceId),
      store.asIndexedDb(),
      journal.asIndexedDb(),
    );
    await reconnect.initialize();
    expect(store.current()).toBeNull();
    expect(journal.current()).toBeNull();
    vmk.fill(0);
  });

  it("clears a Factory Reset tombstone without deleting state when reconnect proves reset did not commit", async () => {
    const { state, vmk } = await activeFixture();
    const store = new MemoryBrowserStore(state);
    const journal = new MemoryJournal();
    await journal.stage({ kind: "factory-reset", expectedGeneration: state.vault.generation, candidate: state });
    const device = new GenerationDevice(state);

    const reconnect = new CanonicalDeviceManagement(device, helloFor(device), store.asIndexedDb(), journal.asIndexedDb());
    await reconnect.initialize();
    expect(store.current()?.vault.generation).toBe(state.vault.generation);
    expect(journal.current()).toBeNull();
    vmk.fill(0);
  });

  it("reports one imported Recovery Vault as explicitly restorable on a clean replacement Device", async () => {
    const { state, vmk } = await activeFixture();
    const imported = sanitizeBrowserCanonicalState({
      ...state,
      trustedBrowser: { ...state.trustedBrowser, status: "replacement-pending" },
    });
    const store = new MemoryBrowserStore(imported);
    const journal = new MemoryJournal();
    const clean = new CleanDevice(replacementDeviceId);
    const manager = new CanonicalDeviceManagement(
      clean,
      typedCleanHello(replacementDeviceId),
      store.asIndexedDb(),
      journal.asIndexedDb(),
    );
    await manager.initialize();
    const snapshot = await manager.refresh();
    expect(snapshot.recoveryProvisioningAvailable).toBe(true);
    expect(snapshot.recoveryProvisioningCandidates).toBe(1);
    expect(snapshot.accounts).toEqual([]);
    vmk.fill(0);
  });

  it("clears an interrupted recovery-provisioning intent when reconnect proves the replacement Device is still clean", async () => {
    const { state, vmk } = await activeFixture();
    const imported = sanitizeBrowserCanonicalState({
      ...state,
      trustedBrowser: { ...state.trustedBrowser, status: "replacement-pending" },
    });
    const candidate = sanitizeBrowserCanonicalState({
      ...imported,
      trustedBrowser: { ...imported.trustedBrowser, epoch: 1, status: "active" },
      deviceMetadata: { deviceId: replacementDeviceId },
    });
    const store = new MemoryBrowserStore(imported);
    const journal = new MemoryJournal();
    await journal.stage({ kind: "recovery-provisioning", expectedGeneration: state.vault.generation, candidate });
    const clean = new CleanDevice(replacementDeviceId);

    const reconnect = new CanonicalDeviceManagement(
      clean,
      typedCleanHello(replacementDeviceId),
      store.asIndexedDb(),
      journal.asIndexedDb(),
    );
    await reconnect.initialize();
    expect(journal.current()).toBeNull();
    expect(store.current()?.trustedBrowser.status).toBe("replacement-pending");
    vmk.fill(0);
  });

  it("promotes a committed clean-Device recovery candidate only on exact Device binding", async () => {
    const { state, vmk } = await activeFixture();
    const imported = sanitizeBrowserCanonicalState({
      ...state,
      trustedBrowser: { ...state.trustedBrowser, status: "replacement-pending" },
    });
    const candidate = sanitizeBrowserCanonicalState({
      ...imported,
      trustedBrowser: { ...imported.trustedBrowser, epoch: 1, status: "active" },
      deviceMetadata: { deviceId: replacementDeviceId },
    });
    const store = new MemoryBrowserStore(imported);
    const journal = new MemoryJournal();
    await journal.stage({ kind: "recovery-provisioning", expectedGeneration: state.vault.generation, candidate });
    const device = new ProvisionedReplacementDevice(candidate, replacementDeviceId);

    const reconnect = new CanonicalDeviceManagement(
      device,
      typedProvisionedHello(provisionedHello({ state: browserBinding(candidate), targetDeviceId: replacementDeviceId })),
      store.asIndexedDb(),
      journal.asIndexedDb(),
    );
    await reconnect.initialize();
    expect(store.current()?.trustedBrowser.status).toBe("active");
    expect(store.current()?.trustedBrowser.epoch).toBe(1);
    expect(store.current()?.deviceMetadata?.deviceId).toBe(replacementDeviceId);
    expect(journal.current()).toBeNull();
    vmk.fill(0);
  });
});
