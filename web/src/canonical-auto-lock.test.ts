import { describe, expect, it } from "vitest";
import {
  CanonicalDeviceManagement,
} from "./canonical-management";
import type {
  CanonicalHelloData,
  CanonicalWireOperation,
} from "./canonical-protocol-v2";
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
import {
  LEGACY_VAULT_FORMAT_VERSION,
  VAULT_FORMAT_VERSION,
  decodeVaultPlaintext,
  encodeVaultPlaintext,
  type VaultPlaintext,
} from "./security/vault-format";
import {
  decryptVault,
  encryptVault,
  wrapVmkWithPassphrase,
} from "./security/vault-crypto";
import {
  decodeBase64UrlCanonical,
  encodeBase64UrlCanonical,
  type SessionWireOperation,
} from "./security/session-protocol-v2";
import type { CanonicalV2Transport } from "./serial";

const passphrase = ["synthetic", "automatic", "lock", "fixture"].join(" ");
const deviceId = "aabbccddeeff00112233445566778899";

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

class MemoryBrowserStore {
  private state: BrowserCanonicalState;

  constructor(initial: BrowserCanonicalState) {
    this.state = sanitizeBrowserCanonicalState(initial);
  }

  async get(vaultId: Uint8Array): Promise<BrowserCanonicalState | null> {
    return sameBytes(this.state.vault.vaultId, vaultId) ? sanitizeBrowserCanonicalState(this.state) : null;
  }

  async list(): Promise<BrowserCanonicalState[]> {
    return [sanitizeBrowserCanonicalState(this.state)];
  }

  async put(state: BrowserCanonicalState, expectedGeneration?: bigint): Promise<void> {
    if (expectedGeneration === undefined || this.state.vault.generation !== expectedGeneration) {
      throw new Error("generation conflict");
    }
    this.state = sanitizeBrowserCanonicalState(state);
  }

  async delete(): Promise<void> {
    throw new Error("delete is not expected in automatic LOCK tests");
  }

  current(): BrowserCanonicalState {
    return sanitizeBrowserCanonicalState(this.state);
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
    return this.pending?.candidate.deviceMetadata?.deviceId === targetDeviceId ? [this.clone(this.pending)] : [];
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

class AutoLockDevice implements CanonicalV2Transport {
  connected = true;
  state: "unlocked" | "locked" = "unlocked";
  generation: bigint;
  vaultFormat: 1 | 2;
  supportedVaultFormats: number[];
  updateCalls = 0;
  commitAndDisconnect = false;
  lockAfterUpdate = false;

  constructor(
    private readonly browserState: BrowserCanonicalState,
    supportedVaultFormats: number[],
  ) {
    this.generation = browserState.vault.generation;
    this.vaultFormat = browserState.vault.vaultFormatVersion;
    this.supportedVaultFormats = [...supportedVaultFormats];
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
      this.updateCalls += 1;
      if (String(params.expected_generation) !== this.generation.toString(10)) {
        throw new Error("generation mismatch");
      }
      const nextGeneration = BigInt(String(params.generation));
      const nextVaultId = decodeBase64UrlCanonical(String(params.vault_id), 16);
      const nextFormat = Number(params.vault_format_version);
      if (nextGeneration !== this.generation + 1n || !sameBytes(nextVaultId, this.browserState.vault.vaultId)) {
        throw new Error("invalid candidate");
      }
      if (nextFormat !== 1 && nextFormat !== 2) throw new Error("invalid candidate format");
      if (!this.supportedVaultFormats.includes(nextFormat)) throw new Error("unsupported candidate format");
      this.generation = nextGeneration;
      this.vaultFormat = nextFormat;
      if (this.lockAfterUpdate) this.state = "locked";
      if (this.commitAndDisconnect) {
        this.commitAndDisconnect = false;
        this.connected = false;
        throw new Error("synthetic response lost after commit");
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
      firmware: "synthetic",
      protocol: 2,
      storage_schema: 2,
      vault_format: this.vaultFormat,
      supported_vault_formats: [...this.supportedVaultFormats],
      build_commit: "synthetic",
      state: this.state,
      storage_ready: true,
      recovery_reset_required: false,
      vault_present: true,
      vault_id: encodeBase64UrlCanonical(this.browserState.vault.vaultId),
      generation: this.generation.toString(10),
      registration_present: true,
      registration_id: encodeBase64UrlCanonical(this.browserState.trustedBrowser.registrationId),
      registration_epoch: this.browserState.trustedBrowser.epoch,
      brk_public_key: encodeBase64UrlCanonical(this.browserState.trustedBrowser.brkPublicKeyRaw),
    };
  }

  typedHello(): CanonicalHelloData {
    return {
      device: "M5StickS3",
      deviceId,
      firmware: "synthetic",
      protocol: 2,
      storageSchema: 2,
      vaultFormat: this.vaultFormat,
      supportedVaultFormats: [...this.supportedVaultFormats],
      buildCommit: "synthetic",
      state: this.state,
      storageReady: true,
      recoveryResetRequired: false,
      vaultPresent: true,
      vaultId: this.browserState.vault.vaultId.slice(),
      generation: this.generation,
      registrationPresent: true,
      registrationId: this.browserState.trustedBrowser.registrationId.slice(),
      registrationEpoch: this.browserState.trustedBrowser.epoch,
      brkPublicKey: this.browserState.trustedBrowser.brkPublicKeyRaw.slice(),
    };
  }
}

async function fixture(): Promise<{ state: BrowserCanonicalState; vmk: Uint8Array }> {
  const vmk = bytes(32, 0x11);
  const vaultId = bytes(16, 0x44);
  const plaintext: VaultPlaintext = {
    credentials: [{
      credentialId: bytes(16, 0x70),
      secret: bytes(20, 0x90),
      issuer: "Synthetic",
      account: "automatic-lock@example.invalid",
      displayName: "",
      algorithm: "SHA1",
      digits: 6,
      periodSeconds: 30,
      manualOrder: 0,
    }],
    wifi: null,
  };
  const encoded = encodeVaultPlaintext(plaintext, LEGACY_VAULT_FORMAT_VERSION);
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

async function readAutoLock(state: BrowserCanonicalState): Promise<number | null> {
  const vmk = await unwrapVmkForTrustedBrowser(state);
  const decrypted = await decryptVault(state.vault, vmk);
  try {
    return decodeVaultPlaintext(decrypted, state.vault.vaultFormatVersion).autoLockDays ?? null;
  } finally {
    decrypted.fill(0);
    vmk.fill(0);
  }
}

describe("automatic LOCK canonical Web flow", () => {
  it("reads Format 1 as disabled and never sends Format 2 without explicit Device capability", async () => {
    const { state, vmk } = await fixture();
    const store = new MemoryBrowserStore(state);
    const journal = new MemoryJournal();
    const device = new AutoLockDevice(state, [1]);
    const management = new CanonicalDeviceManagement(device, device.typedHello(), store.asIndexedDb(), journal.asIndexedDb());
    await management.initialize();

    const snapshot = await management.refresh();
    expect(snapshot.autoLock).toEqual({ known: true, days: null, format2Writable: false });
    await expect(management.setAutoLockDays(1)).rejects.toThrow(/Format 2/);
    expect(device.updateCalls).toBe(0);
    expect(store.current().vault.vaultFormatVersion).toBe(LEGACY_VAULT_FORMAT_VERSION);
    expect(store.current().vault.generation).toBe(7n);
    vmk.fill(0);
  });

  it("migrates F1 to F2 on save, preserves Vault identity/VMK, and remains F2 for disable and 31-day writes", async () => {
    const { state, vmk } = await fixture();
    const store = new MemoryBrowserStore(state);
    const journal = new MemoryJournal();
    const device = new AutoLockDevice(state, [1, 2]);
    const management = new CanonicalDeviceManagement(device, device.typedHello(), store.asIndexedDb(), journal.asIndexedDb());
    await management.initialize();

    const originalNonce = state.vault.nonce.slice();
    const originalVaultId = state.vault.vaultId.slice();
    const originalQuickVmk = await unwrapVmkForTrustedBrowser(state);

    await management.setAutoLockDays(1);
    const enabled = store.current();
    expect(enabled.vault.vaultFormatVersion).toBe(VAULT_FORMAT_VERSION);
    expect(enabled.vault.generation).toBe(8n);
    expect(enabled.vault.vaultId).toEqual(originalVaultId);
    expect(enabled.vault.nonce).not.toEqual(originalNonce);
    expect(enabled.recoveryWrappedVmk.vaultFormatVersion).toBe(VAULT_FORMAT_VERSION);
    expect(await readAutoLock(enabled)).toBe(1);
    const migratedQuickVmk = await unwrapVmkForTrustedBrowser(enabled);
    expect(migratedQuickVmk).toEqual(originalQuickVmk);
    migratedQuickVmk.fill(0);
    originalQuickVmk.fill(0);

    await management.setAutoLockDays(null);
    const disabled = store.current();
    expect(disabled.vault.vaultFormatVersion).toBe(VAULT_FORMAT_VERSION);
    expect(disabled.vault.generation).toBe(9n);
    expect(await readAutoLock(disabled)).toBeNull();

    await management.setAutoLockDays(31);
    const maximum = store.current();
    expect(maximum.vault.vaultFormatVersion).toBe(VAULT_FORMAT_VERSION);
    expect(maximum.vault.generation).toBe(10n);
    expect(await readAutoLock(maximum)).toBe(31);

    const reconnect = new CanonicalDeviceManagement(device, device.typedHello(), store.asIndexedDb(), journal.asIndexedDb());
    await reconnect.initialize();
    const snapshot = await reconnect.refresh();
    expect(snapshot.autoLock).toEqual({ known: true, days: 31, format2Writable: true });
    vmk.fill(0);
  });

  it("treats a successful setting write followed by immediate Device LOCK as committed", async () => {
    const { state, vmk } = await fixture();
    const store = new MemoryBrowserStore(state);
    const journal = new MemoryJournal();
    const device = new AutoLockDevice(state, [1, 2]);
    device.lockAfterUpdate = true;
    const management = new CanonicalDeviceManagement(device, device.typedHello(), store.asIndexedDb(), journal.asIndexedDb());
    await management.initialize();

    await expect(management.setAutoLockDays(1)).resolves.toBeUndefined();
    expect(store.current().vault.vaultFormatVersion).toBe(VAULT_FORMAT_VERSION);
    expect(await readAutoLock(store.current())).toBe(1);
    const snapshot = await management.refresh();
    expect(snapshot.hello.state).toBe("locked");
    expect(snapshot.unlockRequired).toBe(true);
    expect(snapshot.autoLock.known).toBe(false);
    vmk.fill(0);
  });

  it("keeps an ambiguous committed candidate journaled and refuses format-mismatched exact reconciliation", async () => {
    const { state, vmk } = await fixture();
    const store = new MemoryBrowserStore(state);
    const journal = new MemoryJournal();
    const device = new AutoLockDevice(state, [1, 2]);
    device.commitAndDisconnect = true;
    const management = new CanonicalDeviceManagement(device, device.typedHello(), store.asIndexedDb(), journal.asIndexedDb());
    await management.initialize();

    await expect(management.setAutoLockDays(1)).rejects.toBeInstanceOf(PendingBrowserTransactionError);
    expect(store.current().vault.vaultFormatVersion).toBe(LEGACY_VAULT_FORMAT_VERSION);
    expect(store.current().vault.generation).toBe(7n);
    expect(journal.current()?.candidate.vault.vaultFormatVersion).toBe(VAULT_FORMAT_VERSION);
    expect(journal.current()?.candidate.vault.generation).toBe(8n);

    device.connected = true;
    device.vaultFormat = LEGACY_VAULT_FORMAT_VERSION;
    const mismatched = new CanonicalDeviceManagement(device, device.typedHello(), store.asIndexedDb(), journal.asIndexedDb());
    await expect(mismatched.initialize()).rejects.toThrow(/cannot be reconciled|generation conflict/i);
    expect(store.current().vault.generation).toBe(7n);
    expect(journal.current()).not.toBeNull();

    device.vaultFormat = VAULT_FORMAT_VERSION;
    const reconciled = new CanonicalDeviceManagement(device, device.typedHello(), store.asIndexedDb(), journal.asIndexedDb());
    await reconciled.initialize();
    expect(store.current().vault.vaultFormatVersion).toBe(VAULT_FORMAT_VERSION);
    expect(store.current().vault.generation).toBe(8n);
    expect(await readAutoLock(store.current())).toBe(1);
    expect(journal.current()).toBeNull();
    vmk.fill(0);
  });
});
