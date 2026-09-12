import {
  encryptedVaultParams,
  parseCanonicalHelloData,
  parseCanonicalTimeStatus,
  type CanonicalHelloData,
  type CanonicalTimeStatus,
} from "./canonical-protocol-v2";
import { ImportSession } from "./import/session";
import {
  IndexedDbBrowserVaultStore,
  GenerationConflictError,
  assertCanonicalGeneration,
  createBrowserCanonicalState,
  sanitizeBrowserCanonicalState,
  unwrapVmkForTrustedBrowser,
  type BrowserCanonicalState,
} from "./security/browser-vault";
import {
  CANONICAL_BROWSER_STATE_CHANGED_EVENT,
  notifyCanonicalBrowserStateChanged,
  withCanonicalBrowserStateLock,
} from "./security/browser-state-lock";
import {
  IndexedDbBrowserTransactionJournal,
  PendingBrowserTransactionError,
  type BrowserPendingTransaction,
} from "./security/browser-transaction-journal";
import { rekeyTrustedBrowserState } from "./security/browser-vmk-rekey";
import { deliverVmkOverSessionV2, absentBrkIdentity, registrationMatches } from "./security/session-flow-v2";
import {
  CREDENTIAL_ID_BYTES,
  MAX_VAULT_CREDENTIALS,
  decodeVaultPlaintext,
  encodeVaultPlaintext,
  type VaultPlaintext,
} from "./security/vault-format";
import {
  decryptVault,
  encryptVault,
  unwrapVmkWithPassphrase,
  wrapVmkWithPassphrase,
} from "./security/vault-crypto";
import { encodeBase64UrlCanonical } from "./security/session-protocol-v2";
import type { CanonicalV2Transport } from "./serial";

export { CANONICAL_BROWSER_STATE_CHANGED_EVENT };

export interface CanonicalAccountView {
  id: string;
  issuer: string;
  account: string;
  displayName: string;
  order: number;
}

export interface CanonicalDeviceSnapshot {
  hello: CanonicalHelloData;
  time: CanonicalTimeStatus;
  browserOwnership: "none" | "active" | "replacement-pending" | "conflict";
  unlockRequired: boolean;
  accounts: CanonicalAccountView[];
  wifi: { configured: boolean; ssid: string };
}

interface ImportedCredential {
  secret: Uint8Array;
  issuer: string;
  account: string;
}

function randomBytes(length: number): Uint8Array {
  const value = new Uint8Array(length);
  crypto.getRandomValues(value);
  return value;
}

function sameBytes(left: Uint8Array | null, right: Uint8Array | null): boolean {
  if (left === null || right === null || left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return diff === 0;
}

function wipeVaultPlaintext(plaintext: VaultPlaintext | null): void {
  if (!plaintext) return;
  for (const credential of plaintext.credentials) {
    credential.credentialId.fill(0);
    credential.secret.fill(0);
    credential.issuer = "";
    credential.account = "";
    credential.displayName = "";
  }
  plaintext.credentials.length = 0;
  if (plaintext.wifi) {
    plaintext.wifi.ssid = "";
    plaintext.wifi.password = "";
    plaintext.wifi = null;
  }
}

function wipeImported(values: ImportedCredential[]): void {
  for (const value of values) {
    value.secret.fill(0);
    value.issuer = "";
    value.account = "";
  }
  values.length = 0;
}

function credentialViewId(value: Uint8Array): string {
  return encodeBase64UrlCanonical(value);
}

function findCredential(plaintext: VaultPlaintext, id: string) {
  return plaintext.credentials.find((credential) => credentialViewId(credential.credentialId) === id);
}

function assertActiveDeviceBinding(state: BrowserCanonicalState, hello: CanonicalHelloData): void {
  if (!hello.vaultPresent || !hello.registrationPresent || hello.vaultId === null ||
      hello.registrationId === null || hello.brkPublicKey === null) {
    throw new Error("Device is not canonically provisioned");
  }
  if (state.deviceMetadata?.deviceId !== hello.deviceId) {
    throw new Error("Browser Vault belongs to a different Device ID");
  }
  assertCanonicalGeneration(state, { vaultId: hello.vaultId, generation: hello.generation });
  if (!registrationMatches(
    {
      registrationId: state.trustedBrowser.registrationId,
      epoch: state.trustedBrowser.epoch,
      brkPublicKey: state.trustedBrowser.brkPublicKeyRaw,
    },
    {
      registrationId: hello.registrationId,
      epoch: hello.registrationEpoch,
      brkPublicKey: hello.brkPublicKey,
    },
  )) {
    throw new Error("Trusted Browser registration no longer matches the Device; explicit recovery is required");
  }
}

function exactBindingMatches(state: BrowserCanonicalState, hello: CanonicalHelloData): boolean {
  try {
    assertActiveDeviceBinding(state, hello);
    return true;
  } catch {
    return false;
  }
}

export class CanonicalDeviceManagement {
  private hello: CanonicalHelloData;
  private state: BrowserCanonicalState | null = null;
  private ownership: CanonicalDeviceSnapshot["browserOwnership"] = "none";
  private unlockRequired = false;

  public constructor(
    private readonly transport: CanonicalV2Transport,
    initialHello: CanonicalHelloData,
    private readonly store = new IndexedDbBrowserVaultStore(),
    private readonly journal = new IndexedDbBrowserTransactionJournal(),
  ) {
    this.hello = initialHello;
  }

  public async initialize(): Promise<void> {
    await withCanonicalBrowserStateLock(async () => {
      await this.reconcilePendingForHello();
      await this.reloadBrowserState();
      if (!this.hello.vaultPresent) {
        this.ownership = "none";
        this.unlockRequired = false;
        return;
      }
      if (!this.state) {
        this.ownership = "conflict";
        this.unlockRequired = false;
        return;
      }

      if (this.state.trustedBrowser.status === "replacement-pending") {
        await this.completePendingReplacement();
        return;
      }

      try {
        assertActiveDeviceBinding(this.state, this.hello);
      } catch {
        this.ownership = "conflict";
        this.unlockRequired = false;
        throw new Error("Trusted Browser registration does not match the Device; use Recovery Package replacement");
      }

      this.ownership = "active";
      if (this.hello.state === "locked") {
        try {
          await this.quickUnlock();
          this.unlockRequired = false;
        } catch {
          // Fresh user-presence rejection/expiry is not an ownership conflict.
          // Keep the valid Trusted Browser active-but-LOCKED so the user can retry.
          this.ownership = "active";
          this.unlockRequired = true;
        }
      } else if (this.hello.state === "unlocked") {
        this.unlockRequired = false;
      } else {
        this.ownership = "conflict";
        this.unlockRequired = false;
        throw new Error("Device is not available for Trusted Browser unlock");
      }
    });
  }

  public async requestUnlock(): Promise<void> {
    await withCanonicalBrowserStateLock(async () => {
      await this.refreshHelloAndBrowserState();
      if (!this.state || this.state.trustedBrowser.status !== "active" || this.ownership !== "active") {
        throw new Error("Active Trusted Browser state is required for unlock");
      }
      assertActiveDeviceBinding(this.state, this.hello);
      if (this.hello.state === "unlocked") {
        this.unlockRequired = false;
        return;
      }
      if (this.hello.state !== "locked") throw new Error("Device is not available for unlock");
      try {
        await this.quickUnlock();
        this.unlockRequired = false;
      } catch (error) {
        this.ownership = "active";
        this.unlockRequired = true;
        throw error;
      }
    });
  }

  public async refresh(): Promise<CanonicalDeviceSnapshot> {
    return withCanonicalBrowserStateLock(async () => {
      await this.refreshHelloAndBrowserState();
      if (this.state?.trustedBrowser.status === "active" && this.hello.vaultPresent) {
        try {
          assertActiveDeviceBinding(this.state, this.hello);
          this.ownership = "active";
        } catch {
          this.ownership = "conflict";
        }
      }
      this.unlockRequired = this.ownership === "active" && this.hello.state === "locked";

      let accounts: CanonicalAccountView[] = [];
      let wifi = { configured: false, ssid: "" };
      if (this.state && this.ownership === "active" && this.hello.state === "unlocked") {
        const view = await this.readBrowserVaultView(this.state);
        accounts = view.accounts;
        wifi = view.wifi;
      }
      const time = parseCanonicalTimeStatus(await this.transport.requestCanonicalV2("time.status"));
      return {
        hello: this.hello,
        time,
        browserOwnership: this.ownership,
        unlockRequired: this.unlockRequired,
        accounts,
        wifi,
      };
    });
  }

  public async importAccounts(importSession: ImportSession, recoveryPassphrase?: string): Promise<number> {
    const imported = await this.copyImportedAccounts(importSession);
    try {
      if (!this.hello.vaultPresent) {
        if (!recoveryPassphrase) throw new Error("Initial provisioning requires a Recovery Passphrase");
        return await this.initialProvision(imported, recoveryPassphrase);
      }
      await this.mutateVault((plaintext) => {
        if (plaintext.credentials.length + imported.length > MAX_VAULT_CREDENTIALS) {
          throw new Error(`Vault supports at most ${MAX_VAULT_CREDENTIALS} accounts`);
        }
        let order = plaintext.credentials.reduce((maximum, item) => Math.max(maximum, item.manualOrder), -1) + 1;
        for (const account of imported) {
          plaintext.credentials.push({
            credentialId: randomBytes(CREDENTIAL_ID_BYTES),
            secret: account.secret.slice(),
            issuer: account.issuer,
            account: account.account,
            displayName: "",
            algorithm: "SHA1",
            digits: 6,
            periodSeconds: 30,
            manualOrder: order++,
          });
        }
      });
      return imported.length;
    } finally {
      wipeImported(imported);
    }
  }

  public async renameAccount(id: string, displayName: string): Promise<void> {
    await this.mutateVault((plaintext) => {
      const credential = findCredential(plaintext, id);
      if (!credential) throw new Error("Account no longer exists in canonical Vault");
      credential.displayName = displayName;
    });
  }

  public async deleteAccount(id: string): Promise<void> {
    await this.mutateVault((plaintext) => {
      const index = plaintext.credentials.findIndex((credential) => credentialViewId(credential.credentialId) === id);
      if (index < 0) throw new Error("Account no longer exists in canonical Vault");
      const removed = plaintext.credentials.splice(index, 1)[0];
      if (removed) {
        removed.credentialId.fill(0);
        removed.secret.fill(0);
        removed.issuer = "";
        removed.account = "";
        removed.displayName = "";
      }
      plaintext.credentials.forEach((credential, order) => { credential.manualOrder = order; });
    });
  }

  public async reorderAccounts(ids: string[]): Promise<void> {
    await this.mutateVault((plaintext) => {
      if (ids.length !== plaintext.credentials.length || new Set(ids).size !== ids.length) {
        throw new Error("Account reorder set is inconsistent");
      }
      const byId = new Map(plaintext.credentials.map((credential) => [credentialViewId(credential.credentialId), credential]));
      const reordered = ids.map((id, order) => {
        const credential = byId.get(id);
        if (!credential) throw new Error("Account reorder set is stale");
        credential.manualOrder = order;
        return credential;
      });
      plaintext.credentials = reordered;
    });
  }

  public async setWifi(ssid: string, password: string): Promise<void> {
    if (ssid.length === 0 || ssid.length > 32 || password.length === 0 || password.length > 64) {
      throw new Error("Invalid Wi-Fi credentials");
    }
    await this.mutateVault((plaintext) => { plaintext.wifi = { ssid, password }; });
  }

  public async clearWifi(): Promise<void> {
    await this.mutateVault((plaintext) => {
      if (plaintext.wifi) {
        plaintext.wifi.ssid = "";
        plaintext.wifi.password = "";
      }
      plaintext.wifi = null;
    });
  }

  public async rotateVmk(recoveryPassphrase: string): Promise<void> {
    if (recoveryPassphrase.length === 0) throw new Error("VMK re-key requires the Recovery Passphrase");
    await withCanonicalBrowserStateLock(async () => {
      await this.refreshHelloAndBrowserState();
      this.requireActiveWriter();
      const state = this.state!;
      const currentVmk = await unwrapVmkForTrustedBrowser(state);
      const nextVmk = randomBytes(32);
      let verifiedRecoveryVmk: Uint8Array | null = null;
      let decrypted: Uint8Array | null = null;
      let candidate: BrowserCanonicalState | null = null;
      const nextGeneration = state.vault.generation + 1n;
      if (nextGeneration > 0xffff_ffff_ffff_ffffn) {
        currentVmk.fill(0);
        nextVmk.fill(0);
        throw new Error("Canonical Vault generation overflow");
      }

      try {
        verifiedRecoveryVmk = await unwrapVmkWithPassphrase(state.recoveryWrappedVmk, recoveryPassphrase);
        if (!sameBytes(currentVmk, verifiedRecoveryVmk)) {
          throw new Error("Recovery Passphrase does not match the current canonical Vault");
        }
        decrypted = await decryptVault(state.vault, currentVmk);
        const nextVault = await encryptVault(decrypted, nextVmk, state.vault.vaultId, nextGeneration);
        const nextRecoveryWrappedVmk = await wrapVmkWithPassphrase(nextVmk, state.vault.vaultId, recoveryPassphrase);
        candidate = await rekeyTrustedBrowserState({
          current: state,
          nextVault,
          nextRecoveryWrappedVmk,
          nextVmk,
        });
        const pending: BrowserPendingTransaction = {
          kind: "vmk-rekey",
          expectedGeneration: state.vault.generation,
          candidate,
        };
        await this.journal.stage(pending);

        let operationError: unknown = null;
        try {
          await deliverVmkOverSessionV2({
            transport: this.transport,
            operation: "vmk_rekey",
            deviceId: this.hello.deviceId,
            vaultId: state.vault.vaultId,
            expectedGeneration: state.vault.generation,
            registrationId: state.trustedBrowser.registrationId,
            registrationEpoch: state.trustedBrowser.epoch,
            currentBrkPublicKey: state.trustedBrowser.brkPublicKeyRaw,
            proposedBrkPublicKey: absentBrkIdentity(),
            brkPrivateKey: state.trustedBrowser.brkPrivateKey,
            vmk: nextVmk,
          });
          await this.transport.requestCanonicalV2("vault.rekey", {
            expected_generation: state.vault.generation.toString(10),
            ...encryptedVaultParams(nextVault),
          });
        } catch (error) {
          operationError = error;
        }
        await this.resolvePendingOperation(pending, operationError);
      } finally {
        verifiedRecoveryVmk?.fill(0);
        decrypted?.fill(0);
        currentVmk.fill(0);
        nextVmk.fill(0);
        candidate = null;
      }
    });
  }

  public async syncTime(unixSeconds = Math.floor(Date.now() / 1000)): Promise<CanonicalTimeStatus> {
    if (!Number.isSafeInteger(unixSeconds) || unixSeconds < 0) throw new Error("Invalid local time");
    return withCanonicalBrowserStateLock(async () => {
      await this.refreshHelloAndBrowserState();
      this.requireActiveWriter();
      await this.transport.requestCanonicalV2("time.sync", { unix_seconds: String(unixSeconds) });
      return parseCanonicalTimeStatus(await this.transport.requestCanonicalV2("time.status"));
    });
  }

  public async factoryReset(): Promise<void> {
    await withCanonicalBrowserStateLock(async () => {
      await this.refreshHelloAndBrowserState();
      this.requireActiveWriter();
      const state = this.state!;
      await this.transport.requestCanonicalV2("factory_reset");
      await this.store.delete(state.vault.vaultId, state.vault.generation);
      await this.journal.delete(state.vault.vaultId);
      this.state = null;
      this.ownership = "none";
      this.unlockRequired = false;
      notifyCanonicalBrowserStateChanged();
      this.hello = parseCanonicalHelloData(await this.transport.requestCanonicalV2("hello"));
    });
  }

  public async close(): Promise<void> {
    try {
      await this.transport.requestCanonicalV2("device.lock");
    } catch {
      // Explicit close is also the explicit browser Lock action. If transport
      // is already gone, Device-side transport teardown only cancels sessions.
    }
    await this.disconnectTransport();
  }

  public async disconnectTransport(): Promise<void> {
    this.state = null;
    this.ownership = "none";
    this.unlockRequired = false;
    await this.transport.close();
  }

  private async refreshHelloAndBrowserState(): Promise<void> {
    this.hello = parseCanonicalHelloData(await this.transport.requestCanonicalV2("hello"));
    await this.reconcilePendingForHello();
    await this.reloadBrowserState();
  }

  private async reconcilePendingForHello(): Promise<void> {
    if (!this.hello.vaultPresent || this.hello.vaultId === null) {
      if (this.hello.state === "unprovisioned" && !this.hello.registrationPresent) {
        const pendingForDevice = await this.journal.listForDevice(this.hello.deviceId);
        for (const pending of pendingForDevice) {
          if (pending.kind === "initial-provisioning" && pending.expectedGeneration === 0n) {
            await this.journal.delete(pending.candidate.vault.vaultId);
          }
        }
      }
      return;
    }

    const pending = await this.journal.get(this.hello.vaultId);
    if (!pending) return;
    const candidate = pending.candidate;
    if (candidate.deviceMetadata?.deviceId !== this.hello.deviceId ||
        !sameBytes(candidate.vault.vaultId, this.hello.vaultId)) {
      this.ownership = "conflict";
      throw new GenerationConflictError("Pending browser transaction belongs to a different Device/Vault");
    }

    const current = await this.store.get(this.hello.vaultId);
    if (exactBindingMatches(candidate, this.hello)) {
      if (!current) {
        if (pending.expectedGeneration !== 0n) {
          throw new GenerationConflictError("Committed browser state disappeared while a transaction was pending");
        }
        await this.store.put(candidate);
      } else if (current.vault.generation === pending.expectedGeneration) {
        await this.store.put(candidate, pending.expectedGeneration);
      } else if (current.vault.generation === candidate.vault.generation) {
        if (!exactBindingMatches(current, this.hello)) {
          throw new GenerationConflictError("Committed browser state does not match the Device after pending promotion");
        }
      } else {
        throw new GenerationConflictError("Browser transaction generations cannot be reconciled");
      }
      await this.journal.delete(candidate.vault.vaultId);
      notifyCanonicalBrowserStateChanged();
      return;
    }

    if (pending.kind !== "initial-provisioning" &&
        this.hello.generation === pending.expectedGeneration && current &&
        exactBindingMatches(current, this.hello)) {
      await this.journal.delete(candidate.vault.vaultId);
      return;
    }

    this.ownership = "conflict";
    throw new GenerationConflictError("Pending canonical transaction cannot be reconciled with the connected Device");
  }

  private async resolvePendingOperation(
    pending: BrowserPendingTransaction,
    operationError: unknown,
  ): Promise<void> {
    try {
      this.hello = parseCanonicalHelloData(await this.transport.requestCanonicalV2("hello"));
      await this.reconcilePendingForHello();
      await this.reloadBrowserState();
    } catch (error) {
      const stillPending = await this.journal.get(pending.candidate.vault.vaultId);
      if (stillPending) {
        this.ownership = "conflict";
        this.unlockRequired = false;
        throw new PendingBrowserTransactionError(
          "Device outcome is not yet provable. The encrypted candidate remains durably journaled; reconnect to reconcile before any further write.",
        );
      }
      throw error;
    }

    const stillPending = await this.journal.get(pending.candidate.vault.vaultId);
    if (stillPending) {
      this.ownership = "conflict";
      throw new PendingBrowserTransactionError();
    }
    if (this.state?.vault.generation === pending.candidate.vault.generation &&
        exactBindingMatches(this.state, this.hello)) {
      this.ownership = "active";
      this.unlockRequired = this.hello.state === "locked";
      return;
    }
    if (operationError) throw operationError;
    throw new Error("Device did not commit the staged canonical transaction");
  }

  private async reloadBrowserState(): Promise<void> {
    if (!this.hello.vaultPresent || this.hello.vaultId === null) {
      this.state = null;
      this.ownership = "none";
      return;
    }
    const state = await this.store.get(this.hello.vaultId);
    if (!state) {
      this.state = null;
      this.ownership = "conflict";
      return;
    }
    if (state.deviceMetadata?.deviceId !== this.hello.deviceId) {
      this.state = null;
      this.ownership = "conflict";
      return;
    }
    this.state = state;
    this.ownership = state.trustedBrowser.status;
  }

  private async quickUnlock(): Promise<void> {
    const state = this.state;
    if (!state || state.trustedBrowser.status !== "active") throw new Error("Active Trusted Browser state is required");
    assertActiveDeviceBinding(state, this.hello);
    const vmk = await unwrapVmkForTrustedBrowser(state);
    try {
      await deliverVmkOverSessionV2({
        transport: this.transport,
        operation: "trusted_browser_unlock",
        deviceId: this.hello.deviceId,
        vaultId: state.vault.vaultId,
        expectedGeneration: state.vault.generation,
        registrationId: state.trustedBrowser.registrationId,
        registrationEpoch: state.trustedBrowser.epoch,
        currentBrkPublicKey: state.trustedBrowser.brkPublicKeyRaw,
        proposedBrkPublicKey: absentBrkIdentity(),
        brkPrivateKey: state.trustedBrowser.brkPrivateKey,
        vmk,
      });
    } finally {
      vmk.fill(0);
    }
    this.hello = parseCanonicalHelloData(await this.transport.requestCanonicalV2("hello"));
    assertActiveDeviceBinding(state, this.hello);
    if (this.hello.state !== "unlocked") throw new Error("Device did not enter UNLOCKED after Trusted Browser approval");
  }

  private async completePendingReplacement(): Promise<void> {
    const state = this.state;
    if (!state || state.trustedBrowser.status !== "replacement-pending") return;
    if (!this.hello.vaultPresent || this.hello.vaultId === null || this.hello.registrationId === null ||
        this.hello.brkPublicKey === null || !this.hello.registrationPresent) {
      this.ownership = "conflict";
      throw new Error("Recovery replacement requires an existing canonical Device registration");
    }
    assertCanonicalGeneration(state, { vaultId: this.hello.vaultId, generation: this.hello.generation });

    const exactPendingAlreadyConfirmed = state.deviceMetadata?.deviceId === this.hello.deviceId &&
      registrationMatches(
        {
          registrationId: state.trustedBrowser.registrationId,
          epoch: state.trustedBrowser.epoch,
          brkPublicKey: state.trustedBrowser.brkPublicKeyRaw,
        },
        {
          registrationId: this.hello.registrationId,
          epoch: this.hello.registrationEpoch,
          brkPublicKey: this.hello.brkPublicKey,
        },
      );
    if (exactPendingAlreadyConfirmed) {
      const activated = sanitizeBrowserCanonicalState({
        ...state,
        trustedBrowser: { ...state.trustedBrowser, status: "active" },
      });
      await this.store.put(activated, state.vault.generation);
      this.state = activated;
      this.ownership = "active";
      notifyCanonicalBrowserStateChanged();
      if (this.hello.state === "locked") await this.quickUnlock();
      this.unlockRequired = this.hello.state === "locked";
      return;
    }

    if (state.trustedBrowser.epoch !== this.hello.registrationEpoch + 1 ||
        sameBytes(state.trustedBrowser.registrationId, this.hello.registrationId) ||
        sameBytes(state.trustedBrowser.brkPublicKeyRaw, this.hello.brkPublicKey)) {
      this.ownership = "conflict";
      throw new Error("Recovery replacement registration does not advance the Device epoch");
    }

    const vmk = await unwrapVmkForTrustedBrowser(state);
    try {
      await deliverVmkOverSessionV2({
        transport: this.transport,
        operation: "browser_replacement",
        deviceId: this.hello.deviceId,
        vaultId: state.vault.vaultId,
        expectedGeneration: state.vault.generation,
        registrationId: state.trustedBrowser.registrationId,
        registrationEpoch: state.trustedBrowser.epoch,
        currentBrkPublicKey: this.hello.brkPublicKey,
        proposedBrkPublicKey: state.trustedBrowser.brkPublicKeyRaw,
        vmk,
      });
    } finally {
      vmk.fill(0);
    }

    this.hello = parseCanonicalHelloData(await this.transport.requestCanonicalV2("hello"));
    const activated = sanitizeBrowserCanonicalState({
      ...state,
      trustedBrowser: { ...state.trustedBrowser, status: "active" },
      deviceMetadata: { deviceId: this.hello.deviceId },
    });
    assertActiveDeviceBinding(activated, this.hello);
    if (this.hello.state !== "unlocked") throw new Error("Device did not unlock after Browser replacement");
    await this.store.put(activated, state.vault.generation);
    this.state = activated;
    this.ownership = "active";
    this.unlockRequired = false;
    notifyCanonicalBrowserStateChanged();
  }

  private async initialProvision(imported: ImportedCredential[], passphrase: string): Promise<number> {
    return withCanonicalBrowserStateLock(async () => {
      this.hello = parseCanonicalHelloData(await this.transport.requestCanonicalV2("hello"));
      await this.reconcilePendingForHello();
      if (this.hello.vaultPresent || this.hello.registrationPresent) {
        throw new Error("Initial provisioning requires an unprovisioned Device");
      }
      if (imported.length === 0 || imported.length > MAX_VAULT_CREDENTIALS) {
        throw new Error("Initial provisioning requires 1 to 32 accounts");
      }

      const vmk = randomBytes(32);
      const vaultId = randomBytes(16);
      const plaintext: VaultPlaintext = {
        credentials: imported.map((account, order) => ({
          credentialId: randomBytes(CREDENTIAL_ID_BYTES),
          secret: account.secret.slice(),
          issuer: account.issuer,
          account: account.account,
          displayName: "",
          algorithm: "SHA1",
          digits: 6,
          periodSeconds: 30,
          manualOrder: order,
        })),
        wifi: null,
      };
      let encoded: Uint8Array | null = null;
      let candidate: BrowserCanonicalState | null = null;
      try {
        encoded = encodeVaultPlaintext(plaintext);
        const vault = await encryptVault(encoded, vmk, vaultId, 1n);
        const recoveryWrappedVmk = await wrapVmkWithPassphrase(vmk, vaultId, passphrase);
        candidate = await createBrowserCanonicalState({
          vault,
          recoveryWrappedVmk,
          vmk,
          registrationEpoch: 1,
          status: "active",
          deviceMetadata: { deviceId: this.hello.deviceId },
        });
        const pending: BrowserPendingTransaction = {
          kind: "initial-provisioning",
          expectedGeneration: 0n,
          candidate,
        };
        await this.journal.stage(pending);

        let operationError: unknown = null;
        try {
          await deliverVmkOverSessionV2({
            transport: this.transport,
            operation: "initial_provisioning",
            deviceId: this.hello.deviceId,
            vaultId,
            expectedGeneration: 0n,
            registrationId: candidate.trustedBrowser.registrationId,
            registrationEpoch: 0,
            currentBrkPublicKey: absentBrkIdentity(),
            proposedBrkPublicKey: candidate.trustedBrowser.brkPublicKeyRaw,
            vmk,
          });
          await this.transport.requestCanonicalV2("vault.install", encryptedVaultParams(vault));
        } catch (error) {
          operationError = error;
        }
        await this.resolvePendingOperation(pending, operationError);
        return imported.length;
      } finally {
        encoded?.fill(0);
        vmk.fill(0);
        vaultId.fill(0);
        wipeVaultPlaintext(plaintext);
        candidate = null;
      }
    });
  }

  private async copyImportedAccounts(importSession: ImportSession): Promise<ImportedCredential[]> {
    const imported: ImportedCredential[] = [];
    try {
      await importSession.forEachCompleteAccount(async (account) => {
        imported.push({ secret: account.secret.slice(), issuer: account.issuer, account: account.account });
      });
      return imported;
    } catch (error) {
      wipeImported(imported);
      throw error;
    }
  }

  private requireActiveWriter(): void {
    if (!this.state || this.state.trustedBrowser.status !== "active" || this.ownership !== "active") {
      throw new Error("Canonical writes require an active Trusted Browser");
    }
    if (this.hello.state !== "unlocked") throw new Error("Device must be UNLOCKED before canonical writes");
    assertActiveDeviceBinding(this.state, this.hello);
  }

  private async mutateVault(mutator: (plaintext: VaultPlaintext) => void): Promise<void> {
    await withCanonicalBrowserStateLock(async () => {
      await this.refreshHelloAndBrowserState();
      this.requireActiveWriter();
      const state = this.state!;
      const vmk = await unwrapVmkForTrustedBrowser(state);
      let decrypted: Uint8Array | null = null;
      let encoded: Uint8Array | null = null;
      let plaintext: VaultPlaintext | null = null;
      try {
        decrypted = await decryptVault(state.vault, vmk);
        plaintext = decodeVaultPlaintext(decrypted);
        mutator(plaintext);
        encoded = encodeVaultPlaintext(plaintext);
        const nextGeneration = state.vault.generation + 1n;
        if (nextGeneration > 0xffff_ffff_ffff_ffffn) throw new Error("Canonical Vault generation overflow");
        const nextVault = await encryptVault(encoded, vmk, state.vault.vaultId, nextGeneration);
        const candidate = sanitizeBrowserCanonicalState({ ...state, vault: nextVault });
        const pending: BrowserPendingTransaction = {
          kind: "vault-update",
          expectedGeneration: state.vault.generation,
          candidate,
        };
        await this.journal.stage(pending);

        let operationError: unknown = null;
        try {
          await this.transport.requestCanonicalV2("vault.update", {
            expected_generation: state.vault.generation.toString(10),
            ...encryptedVaultParams(nextVault),
          });
        } catch (error) {
          operationError = error;
        }
        await this.resolvePendingOperation(pending, operationError);
      } finally {
        decrypted?.fill(0);
        encoded?.fill(0);
        vmk.fill(0);
        wipeVaultPlaintext(plaintext);
      }
    });
  }

  private async readBrowserVaultView(state: BrowserCanonicalState): Promise<{
    accounts: CanonicalAccountView[];
    wifi: { configured: boolean; ssid: string };
  }> {
    const vmk = await unwrapVmkForTrustedBrowser(state);
    let decrypted: Uint8Array | null = null;
    let plaintext: VaultPlaintext | null = null;
    try {
      decrypted = await decryptVault(state.vault, vmk);
      plaintext = decodeVaultPlaintext(decrypted);
      const accounts = plaintext.credentials
        .map((credential) => ({
          id: credentialViewId(credential.credentialId),
          issuer: credential.issuer,
          account: credential.account,
          displayName: credential.displayName,
          order: credential.manualOrder,
        }))
        .sort((left, right) => left.order - right.order);
      return {
        accounts,
        wifi: plaintext.wifi ? { configured: true, ssid: plaintext.wifi.ssid } : { configured: false, ssid: "" },
      };
    } finally {
      decrypted?.fill(0);
      vmk.fill(0);
      wipeVaultPlaintext(plaintext);
    }
  }
}
