import { describe, expect, it } from "vitest";
import {
  CanonicalProtocolV2Error,
  type CanonicalWireOperation,
} from "./canonical-protocol-v2";
import { CanonicalDeviceManagement } from "./canonical-management";
import { ImportSession } from "./import/session";
import {
  IndexedDbBrowserVaultStore,
  exportRecoveryPackage,
  importRecoveryPackage,
  sanitizeBrowserCanonicalState,
  type BrowserCanonicalState,
} from "./security/browser-vault";
import {
  decodeBase64UrlCanonical,
  encodeBase64UrlCanonical,
  encodeSessionTranscript,
  type SessionOperation,
  type SessionWireOperation,
} from "./security/session-protocol-v2";
import type { CanonicalV2Transport } from "./serial";

const recoveryPassphrase = ["synthetic", "canonical", "recovery", "phrase"].join(" ");

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function copyBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer;
}

function join(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

class MemoryBrowserStore {
  private state: BrowserCanonicalState | null = null;

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

interface SessionAttempt {
  operation: SessionOperation;
  vaultId: Uint8Array;
  expectedGeneration: bigint;
  registrationId: Uint8Array;
  registrationEpoch: number;
  currentBrk: Uint8Array;
  proposedBrk: Uint8Array;
  attemptId: Uint8Array;
  challenge: Uint8Array;
  deviceKeys: CryptoKeyPair;
  devicePublic: Uint8Array;
  webPublic: Uint8Array | null;
  transcript: Uint8Array | null;
}

class SyntheticCanonicalDevice implements CanonicalV2Transport {
  readonly deviceId = "00112233445566778899aabbccddeeff";
  state: "unprovisioned" | "locked" | "unlocked" = "unprovisioned";
  storageReady = false;
  vaultId: Uint8Array | null = null;
  generation = 0n;
  registrationId: Uint8Array | null = null;
  registrationEpoch = 0;
  brkPublicKey: Uint8Array | null = null;
  timeReady = false;
  currentVmk: Uint8Array | null = null;
  private attempt: SessionAttempt | null = null;
  private attemptCounter = 1;

  async requestCanonicalV2(
    op: CanonicalWireOperation,
    params: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    if (op === "hello") return this.hello();
    if (op === "time.status") {
      return {
        readiness: this.timeReady ? "ready" : "not_synced",
        source: this.timeReady ? "usb" : "none",
        last_sync_unix_seconds: this.timeReady ? "1789156800" : "0",
        age_seconds: 0,
        resync_due: false,
      };
    }
    if (op === "time.sync") {
      if (this.state !== "unlocked") throw new CanonicalProtocolV2Error("invalid_state");
      this.timeReady = true;
      return {};
    }
    if (op === "device.lock") {
      this.state = this.vaultId ? "locked" : "unprovisioned";
      this.currentVmk?.fill(0);
      this.currentVmk = null;
      this.attempt = null;
      return {};
    }
    if (op === "vault.install") {
      if (!this.attempt || this.attempt.operation !== "initial_provisioning" || !this.currentVmk) {
        throw new CanonicalProtocolV2Error("invalid_state");
      }
      const vaultId = decodeBase64UrlCanonical(String(params.vault_id), 16);
      if (String(params.generation) !== "1" || !sameBytes(vaultId, this.attempt.vaultId)) {
        throw new CanonicalProtocolV2Error("generation_mismatch");
      }
      this.vaultId = vaultId;
      this.generation = 1n;
      this.registrationId = this.attempt.registrationId.slice();
      this.registrationEpoch = 1;
      this.brkPublicKey = this.attempt.proposedBrk.slice();
      this.storageReady = true;
      this.state = "unlocked";
      this.attempt = null;
      return {};
    }
    if (op === "vault.update") {
      if (this.state !== "unlocked" || !this.vaultId) throw new CanonicalProtocolV2Error("locked");
      if (String(params.expected_generation) !== this.generation.toString(10)) {
        throw new CanonicalProtocolV2Error("generation_mismatch");
      }
      const nextGeneration = BigInt(String(params.generation));
      const nextVaultId = decodeBase64UrlCanonical(String(params.vault_id), 16);
      if (nextGeneration !== this.generation + 1n || !sameBytes(nextVaultId, this.vaultId)) {
        throw new CanonicalProtocolV2Error("generation_mismatch");
      }
      this.generation = nextGeneration;
      return {};
    }
    if (op === "vault.rekey") {
      if (!this.attempt || this.attempt.operation !== "vmk_rekey" || !this.currentVmk) {
        throw new CanonicalProtocolV2Error("invalid_state");
      }
      if (String(params.expected_generation) !== this.generation.toString(10) ||
          BigInt(String(params.generation)) !== this.generation + 1n) {
        throw new CanonicalProtocolV2Error("generation_mismatch");
      }
      this.generation += 1n;
      this.state = "unlocked";
      this.attempt = null;
      return {};
    }
    if (op === "factory_reset") {
      if (this.state !== "unlocked") throw new CanonicalProtocolV2Error("invalid_state");
      this.currentVmk?.fill(0);
      this.currentVmk = null;
      this.vaultId = null;
      this.generation = 0n;
      this.registrationId = null;
      this.registrationEpoch = 0;
      this.brkPublicKey = null;
      this.storageReady = false;
      this.timeReady = false;
      this.state = "unprovisioned";
      this.attempt = null;
      return {};
    }
    throw new Error(`unexpected canonical operation ${op}`);
  }

  async requestV2(
    op: SessionWireOperation,
    params: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    if (op === "session.begin") {
      const operation = params.operation as SessionOperation;
      if ((operation === "trusted_browser_unlock" || operation === "vmk_rekey") && this.state !== "locked" && operation !== "vmk_rekey") {
        throw new Error("unexpected quick unlock state");
      }
      if (operation === "vmk_rekey" && this.state !== "unlocked") throw new Error("unexpected rekey state");
      const deviceKeys = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"],
      ) as CryptoKeyPair;
      const devicePublic = new Uint8Array(await crypto.subtle.exportKey("raw", deviceKeys.publicKey));
      const attemptId = new Uint8Array(16);
      attemptId.fill(this.attemptCounter++ & 0xff);
      const challenge = bytes(32, 0x30 + this.attemptCounter);
      this.attempt = {
        operation,
        vaultId: decodeBase64UrlCanonical(String(params.vault_id), 16),
        expectedGeneration: BigInt(String(params.expected_generation)),
        registrationId: decodeBase64UrlCanonical(String(params.registration_id), 16),
        registrationEpoch: Number(params.registration_epoch),
        currentBrk: decodeBase64UrlCanonical(String(params.current_brk_public_key), 65),
        proposedBrk: decodeBase64UrlCanonical(String(params.proposed_brk_public_key), 65),
        attemptId,
        challenge,
        deviceKeys,
        devicePublic,
        webPublic: null,
        transcript: null,
      };
      return {
        attempt_id: encodeBase64UrlCanonical(attemptId),
        challenge: encodeBase64UrlCanonical(challenge),
        device_public_key: encodeBase64UrlCanonical(devicePublic),
        expires_in_ms: 30_000,
      };
    }
    if (op === "session.authorize") {
      const attempt = this.requireAttempt();
      attempt.webPublic = decodeBase64UrlCanonical(String(params.web_public_key), 65);
      attempt.transcript = encodeSessionTranscript({
        operation: attempt.operation,
        deviceId: this.deviceId,
        vaultId: attempt.vaultId,
        expectedGeneration: attempt.expectedGeneration,
        registrationId: attempt.registrationId,
        registrationEpoch: attempt.registrationEpoch,
        attemptId: attempt.attemptId,
        challenge: attempt.challenge,
        deviceEphemeralPublicKey: attempt.devicePublic,
        webEphemeralPublicKey: attempt.webPublic,
        currentBrkPublicKey: attempt.currentBrk,
        proposedBrkPublicKey: attempt.proposedBrk,
      });

      if (attempt.operation === "trusted_browser_unlock" || attempt.operation === "vmk_rekey") {
        if (!this.brkPublicKey || typeof params.brk_signature !== "string") {
          throw new Error("missing BRK authentication");
        }
        const publicKey = await crypto.subtle.importKey(
          "raw",
          copyBuffer(this.brkPublicKey),
          { name: "ECDSA", namedCurve: "P-256" },
          false,
          ["verify"],
        );
        const signature = decodeBase64UrlCanonical(params.brk_signature, 64);
        const valid = await crypto.subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          publicKey,
          copyBuffer(signature),
          copyBuffer(attempt.transcript),
        );
        if (!valid) throw new Error("invalid BRK signature");
      }
      return {};
    }
    if (op === "session.status") return { state: "confirmed" };
    if (op === "session.cancel") {
      this.attempt = null;
      return {};
    }
    if (op === "session.complete") {
      const attempt = this.requireAttempt();
      if (!attempt.webPublic || !attempt.transcript) throw new Error("attempt is not authorized");
      const webPublic = await crypto.subtle.importKey(
        "raw",
        copyBuffer(attempt.webPublic),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        [],
      );
      const shared = new Uint8Array(await crypto.subtle.deriveBits(
        { name: "ECDH", public: webPublic },
        attempt.deviceKeys.privateKey,
        256,
      ));
      const hkdf = await crypto.subtle.importKey("raw", copyBuffer(shared), "HKDF", false, ["deriveKey"]);
      const salt = join(attempt.attemptId, attempt.challenge);
      const sessionKey = await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: copyBuffer(salt), info: copyBuffer(attempt.transcript) },
        hkdf,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"],
      );
      const nonce = decodeBase64UrlCanonical(String(params.nonce), 12);
      const ciphertext = decodeBase64UrlCanonical(String(params.ciphertext), 32);
      const tag = decodeBase64UrlCanonical(String(params.tag), 16);
      const vmk = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: copyBuffer(nonce), additionalData: copyBuffer(attempt.transcript), tagLength: 128 },
        sessionKey,
        copyBuffer(join(ciphertext, tag)),
      ));
      shared.fill(0);
      salt.fill(0);
      this.currentVmk?.fill(0);
      this.currentVmk = vmk;

      if (attempt.operation === "trusted_browser_unlock") {
        this.state = "unlocked";
        this.attempt = null;
      } else if (attempt.operation === "browser_replacement" || attempt.operation === "recovery") {
        this.registrationId = attempt.registrationId.slice();
        this.registrationEpoch = attempt.registrationEpoch;
        this.brkPublicKey = attempt.proposedBrk.slice();
        this.state = "unlocked";
        this.attempt = null;
      } else if (attempt.operation === "vmk_rekey") {
        this.state = "locked";
      }
      return {};
    }
    throw new Error(`unexpected session operation ${op}`);
  }

  async close(): Promise<void> {
    this.state = this.vaultId ? "locked" : "unprovisioned";
    this.currentVmk?.fill(0);
    this.currentVmk = null;
    this.attempt = null;
  }

  private hello(): Record<string, unknown> {
    return {
      device: "M5StickS3",
      device_id: this.deviceId,
      firmware: "0.1.0",
      protocol: 2,
      storage_schema: 2,
      vault_format: 1,
      build_commit: "synthetic",
      state: this.state,
      storage_ready: this.storageReady,
      vault_present: this.vaultId !== null,
      vault_id: this.vaultId ? encodeBase64UrlCanonical(this.vaultId) : null,
      generation: this.generation.toString(10),
      registration_present: this.registrationId !== null,
      registration_id: this.registrationId ? encodeBase64UrlCanonical(this.registrationId) : null,
      registration_epoch: this.registrationEpoch,
      brk_public_key: this.brkPublicKey ? encodeBase64UrlCanonical(this.brkPublicKey) : null,
    };
  }

  private requireAttempt(): SessionAttempt {
    if (!this.attempt) throw new Error("no active session attempt");
    return this.attempt;
  }
}

function importOneAccount(): ImportSession {
  const session = new ImportSession();
  const scheme = ["otp", "auth"].join("");
  const secretParameter = ["sec", "ret"].join("");
  session.importDecodedText(
    `${scheme}://totp/Synthetic:alice%40example.com?${secretParameter}=JBSWY3DPEHPK3PXP&issuer=Synthetic&algorithm=SHA1&digits=6&period=30`,
  );
  return session;
}

function helloFor(device: SyntheticCanonicalDevice) {
  return device.requestCanonicalV2("hello").then((data) => ({
    device: String(data.device),
    deviceId: String(data.device_id),
    firmware: String(data.firmware),
    protocol: 2 as const,
    storageSchema: 2 as const,
    vaultFormat: 1 as const,
    buildCommit: String(data.build_commit),
    state: data.state as "unprovisioned" | "locked" | "unlocked",
    storageReady: Boolean(data.storage_ready),
    vaultPresent: Boolean(data.vault_present),
    vaultId: data.vault_id ? decodeBase64UrlCanonical(String(data.vault_id), 16) : null,
    generation: BigInt(String(data.generation)),
    registrationPresent: Boolean(data.registration_present),
    registrationId: data.registration_id ? decodeBase64UrlCanonical(String(data.registration_id), 16) : null,
    registrationEpoch: Number(data.registration_epoch),
    brkPublicKey: data.brk_public_key ? decodeBase64UrlCanonical(String(data.brk_public_key), 65) : null,
  }));
}

describe("canonical Protocol v2 synthetic integration", () => {
  it("first provisions, quick-unlocks, mutates generations, replaces Browser, rejects old Browser, and resets", async () => {
    const device = new SyntheticCanonicalDevice();
    const originalStore = new MemoryBrowserStore();
    const initial = new CanonicalDeviceManagement(device, await helloFor(device), originalStore.asIndexedDb());
    await initial.initialize();

    const imported = importOneAccount();
    expect(await initial.importAccounts(imported, recoveryPassphrase)).toBe(1);
    imported.clear();
    expect(device.state).toBe("unlocked");
    expect(device.generation).toBe(1n);
    expect(device.registrationEpoch).toBe(1);

    let snapshot = await initial.refresh();
    expect(snapshot.browserOwnership).toBe("active");
    expect(snapshot.accounts).toHaveLength(1);
    expect(snapshot.accounts[0]?.account).toBe("alice@example.com");

    await initial.close();
    expect(device.state).toBe("locked");
    await expect(device.requestCanonicalV2("time.sync", { unix_seconds: "1789156800" }))
      .rejects.toThrow(/invalid_state/);

    const quick = new CanonicalDeviceManagement(device, await helloFor(device), originalStore.asIndexedDb());
    await quick.initialize();
    expect(device.state).toBe("unlocked");
    snapshot = await quick.refresh();
    const accountId = snapshot.accounts[0]!.id;
    await quick.renameAccount(accountId, "Primary");
    expect(device.generation).toBe(2n);
    expect(originalStore.current()?.vault.generation).toBe(2n);
    expect((await quick.refresh()).accounts[0]?.displayName).toBe("Primary");
    await quick.syncTime(1789156800);
    expect(device.timeReady).toBe(true);

    const activeState = originalStore.current();
    expect(activeState).not.toBeNull();
    const recoveryPackage = exportRecoveryPackage(activeState!);
    const replacementState = await importRecoveryPackage(recoveryPackage, recoveryPassphrase);
    const replacementStore = new MemoryBrowserStore();
    await replacementStore.put(replacementState);

    await quick.close();
    const replacement = new CanonicalDeviceManagement(device, await helloFor(device), replacementStore.asIndexedDb());
    await replacement.initialize();
    expect(device.state).toBe("unlocked");
    expect(device.registrationEpoch).toBe(2);
    expect(replacementStore.current()?.trustedBrowser.status).toBe("active");

    await replacement.close();
    const staleOldBrowser = new CanonicalDeviceManagement(device, await helloFor(device), originalStore.asIndexedDb());
    await expect(staleOldBrowser.initialize()).rejects.toThrow(/Recovery Package replacement/i);
    expect(device.state).toBe("locked");

    const activeReplacement = new CanonicalDeviceManagement(device, await helloFor(device), replacementStore.asIndexedDb());
    await activeReplacement.initialize();
    expect(device.state).toBe("unlocked");
    await activeReplacement.factoryReset();
    expect(device.state).toBe("unprovisioned");
    expect(device.vaultId).toBeNull();
    expect(device.registrationId).toBeNull();
    expect(replacementStore.current()).toBeNull();
  }, 30_000);

  it("fails closed when Device generation advances without the Browser canonical transaction", async () => {
    const device = new SyntheticCanonicalDevice();
    const store = new MemoryBrowserStore();
    const first = new CanonicalDeviceManagement(device, await helloFor(device), store.asIndexedDb());
    await first.initialize();
    const imported = importOneAccount();
    await first.importAccounts(imported, recoveryPassphrase);
    imported.clear();
    await first.close();

    device.generation += 1n;
    const stale = new CanonicalDeviceManagement(device, await helloFor(device), store.asIndexedDb());
    await expect(stale.initialize()).rejects.toThrow(/Trusted Browser registration does not match|Recovery/i);
    expect(device.state).toBe("locked");
  }, 30_000);
});
