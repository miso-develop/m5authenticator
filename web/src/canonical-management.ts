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
  assertCanonicalGeneration,
  createBrowserCanonicalState,
  sanitizeBrowserCanonicalState,
  unwrapVmkForTrustedBrowser,
  type BrowserCanonicalState,
} from "./security/browser-vault";
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
  wrapVmkWithPassphrase,
} from "./security/vault-crypto";
import {
  encodeBase64UrlCanonical,
  SESSION_P256_PUBLIC_KEY_BYTES,
} from "./security/session-protocol-v2";
import type { CanonicalV2Transport } from "./serial";

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

export class CanonicalDeviceManagement {
  private hello: CanonicalHelloData;
  private state: BrowserCanonicalState | null = null;
  private ownership: CanonicalDeviceSnapshot["browserOwnership"] = "none";

  public constructor(
    private readonly transport: CanonicalV2Transport,
    initialHello: CanonicalHelloData,
    private readonly store = new IndexedDbBrowserVaultStore(),
  ) {
    this.hello = initialHello;
  }

  public async initialize(): Promise<void> {
    await this.reloadBrowserState();
    if (!this.hello.vaultPresent) {
      this.ownership = "none";
      return;
    }
    if (!this.state) {
      this.ownership = "conflict";
      return;
    }

    if (this.state.trustedBrowser.status === "replacement-pending") {
      await this.completePendingReplacement();
      return;
    }

    try {
      assertActiveDeviceBinding(this.state, this.hello);
      if (this.hello.state === "locked") await this.quickUnlock();
      else if (this.hello.state !== "unlocked") throw new Error("Device is not available for Trusted Browser unlock");
      this.ownership = "active";
    } catch {
      this.ownership = "conflict";
      throw new Error("Trusted Browser registration does not match the Device; use Recovery Package replacement");
    }
  }

  public async refresh(): Promise<CanonicalDeviceSnapshot> {
    this.hello = parseCanonicalHelloData(await this.transport.requestCanonicalV2("hello"));
    await this.reloadBrowserState();

    let accounts: CanonicalAccountView[] = [];
    let wifi = { configured: false, ssid: "" };
    if (this.state) {
      const view = await this.readBrowserVaultView(this.state);
      accounts = view.accounts;
      wifi = view.wifi;
    }
    const time = parseCanonicalTimeStatus(await this.transport.requestCanonicalV2("time.status"));
    return { hello: this.hello, time, browserOwnership: this.ownership, accounts, wifi };
  }

  public async importAccounts(importSession: ImportSession, recoveryPassphrase?: string): Promise<number> {
    const imported = await this.copyImportedAccounts(importSession);
    try {
      if (!this.hello.vaultPresent) {
        if (!recoveryPassphrase) throw new Error("Initial provisioning requires a Recovery Passphrase");
        return await this.initialProvision(imported, recoveryPassphrase);
      }
      this.requireActiveWriter();
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
    this.requireActiveWriter();
    await this.mutateVault((plaintext) => {
      const credential = findCredential(plaintext, id);
      if (!credential) throw new Error("Account no longer exists in canonical Vault");
      credential.displayName = displayName;
    });
  }

  public async deleteAccount(id: string): Promise<void> {
    this.requireActiveWriter();
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
    this.requireActiveWriter();
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
    this.requireActiveWriter();
    if (ssid.length === 0 || ssid.length > 32 || password.length === 0 || password.length > 64) {
      throw new Error("Invalid Wi-Fi credentials");
    }
    await this.mutateVault((plaintext) => { plaintext.wifi = { ssid, password }; });
  }

  public async clearWifi(): Promise<void> {
    this.requireActiveWriter();
    await this.mutateVault((plaintext) => {
      if (plaintext.wifi) {
        plaintext.wifi.ssid = "";
        plaintext.wifi.password = "";
      }
      plaintext.wifi = null;
    });
  }

  public async syncTime(unixSeconds = Math.floor(Date.now() / 1000)): Promise<CanonicalTimeStatus> {
    this.requireActiveWriter();
    if (!Number.isSafeInteger(unixSeconds) || unixSeconds < 0) throw new Error("Invalid local time");
    await this.transport.requestCanonicalV2("time.sync", { unix_seconds: String(unixSeconds) });
    return parseCanonicalTimeStatus(await this.transport.requestCanonicalV2("time.status"));
  }

  public async factoryReset(): Promise<void> {
    this.requireActiveWriter();
    const state = this.state!;
    await this.transport.requestCanonicalV2("factory_reset");
    try {
      await this.store.delete(state.vault.vaultId, state.vault.generation);
    } finally {
      this.state = null;
      this.ownership = "none";
      this.hello = parseCanonicalHelloData(await this.transport.requestCanonicalV2("hello"));
    }
  }

  public async close(): Promise<void> {
    try {
      await this.transport.requestCanonicalV2("device.lock");
    } catch {
      // Physical transport close is itself a Device-side lock boundary.
    }
    this.state = null;
    this.ownership = "none";
    await this.transport.close();
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
  }

  private async initialProvision(imported: ImportedCredential[], passphrase: string): Promise<number> {
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

      this.hello = parseCanonicalHelloData(await this.transport.requestCanonicalV2("hello"));
      assertActiveDeviceBinding(candidate, this.hello);
      if (this.hello.state !== "unlocked") throw new Error("Initial provisioning did not leave Device UNLOCKED");
      try {
        await this.store.put(candidate);
      } catch (error) {
        // Avoid leaving a Device provisioned with the only Trusted Browser state
        // lost before IndexedDB commit. Device is still UNLOCKED, so roll back.
        try { await this.transport.requestCanonicalV2("factory_reset"); } catch { /* fail closed on disconnect */ }
        throw error;
      }
      this.state = candidate;
      this.ownership = "active";
      return imported.length;
    } finally {
      encoded?.fill(0);
      vmk.fill(0);
      vaultId.fill(0);
      wipeVaultPlaintext(plaintext);
      candidate = null;
    }
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
      await this.transport.requestCanonicalV2("vault.update", {
        expected_generation: state.vault.generation.toString(10),
        ...encryptedVaultParams(nextVault),
      });
      const updated = sanitizeBrowserCanonicalState({ ...state, vault: nextVault });
      await this.store.put(updated, state.vault.generation);
      this.state = updated;
      this.hello = parseCanonicalHelloData(await this.transport.requestCanonicalV2("hello"));
      assertActiveDeviceBinding(updated, this.hello);
    } finally {
      decrypted?.fill(0);
      encoded?.fill(0);
      vmk.fill(0);
      wipeVaultPlaintext(plaintext);
    }
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
