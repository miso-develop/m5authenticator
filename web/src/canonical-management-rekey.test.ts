import { describe, expect, it } from "vitest";
import {
  type CanonicalHelloData,
  type CanonicalWireOperation,
} from "./canonical-protocol-v2";
import { CanonicalDeviceManagement } from "./canonical-management";
import {
  IndexedDbBrowserVaultStore,
  createBrowserCanonicalState,
  sanitizeBrowserCanonicalState,
  unwrapVmkForTrustedBrowser,
  type BrowserCanonicalState,
} from "./security/browser-vault";
import {
  decryptVault,
  encryptVault,
  wrapVmkWithPassphrase,
} from "./security/vault-crypto";
import {
  encodeBase64UrlCanonical,
  type SessionWireOperation,
} from "./security/session-protocol-v2";
import type { CanonicalV2Transport } from "./serial";

const recoveryPassphrase = ["synthetic", "rekey", "integration", "phrase"].join(" ");

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

class MemoryStore {
  constructor(private state: BrowserCanonicalState) {}

  async get(vaultId: Uint8Array): Promise<BrowserCanonicalState | null> {
    return sameBytes(this.state.vault.vaultId, vaultId)
      ? sanitizeBrowserCanonicalState(this.state)
      : null;
  }

  async put(state: BrowserCanonicalState, expectedGeneration?: bigint): Promise<void> {
    if (expectedGeneration !== undefined && this.state.vault.generation !== expectedGeneration) {
      throw new Error("generation conflict");
    }
    this.state = sanitizeBrowserCanonicalState(state);
  }

  current(): BrowserCanonicalState {
    return sanitizeBrowserCanonicalState(this.state);
  }

  asIndexedDb(): IndexedDbBrowserVaultStore {
    return this as unknown as IndexedDbBrowserVaultStore;
  }
}

class RekeyTransport implements CanonicalV2Transport {
  generation = 4n;
  state: "unlocked" | "locked" = "unlocked";
  beginOperation: string | null = null;
  statusCalls = 0;
  completed = false;
  rekeyCommitted = false;

  constructor(private readonly browserState: BrowserCanonicalState) {}

  async requestCanonicalV2(
    op: CanonicalWireOperation,
    params: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    if (op === "hello") return this.hello();
    if (op === "vault.rekey") {
      expect(this.completed).toBe(true);
      expect(String(params.expected_generation)).toBe("4");
      expect(String(params.generation)).toBe("5");
      this.generation = 5n;
      this.state = "unlocked";
      this.rekeyCommitted = true;
      return {};
    }
    if (op === "device.lock") {
      this.state = "locked";
      return {};
    }
    throw new Error(`unexpected canonical operation ${op}`);
  }

  async requestV2(
    op: SessionWireOperation,
    params: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    if (op === "session.begin") {
      this.beginOperation = String(params.operation);
      expect(this.beginOperation).toBe("vmk_rekey");
      expect(String(params.expected_generation)).toBe("4");
      this.state = "locked";
      const pair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"],
      ) as CryptoKeyPair;
      const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
      return {
        attempt_id: encodeBase64UrlCanonical(bytes(16, 0x11)),
        challenge: encodeBase64UrlCanonical(bytes(32, 0x22)),
        device_public_key: encodeBase64UrlCanonical(publicKey),
        expires_in_ms: 30_000,
      };
    }
    if (op === "session.authorize") {
      expect(typeof params.brk_signature).toBe("string");
      return {};
    }
    if (op === "session.status") {
      this.statusCalls += 1;
      return { state: "confirmed" };
    }
    if (op === "session.complete") {
      this.completed = true;
      return {};
    }
    if (op === "session.cancel") return {};
    throw new Error(`unexpected session operation ${op}`);
  }

  async close(): Promise<void> {
    this.state = "locked";
  }

  private hello(): Record<string, unknown> {
    return {
      device: "M5StickS3",
      device_id: "synthetic-device",
      firmware: "0.1.0",
      protocol: 2,
      storage_schema: 2,
      vault_format: 1,
      build_commit: "synthetic",
      state: this.state,
      storage_ready: true,
      vault_present: true,
      vault_id: encodeBase64UrlCanonical(this.browserState.vault.vaultId),
      generation: this.generation.toString(10),
      registration_present: true,
      registration_id: encodeBase64UrlCanonical(this.browserState.trustedBrowser.registrationId),
      registration_epoch: this.browserState.trustedBrowser.epoch,
      brk_public_key: encodeBase64UrlCanonical(this.browserState.trustedBrowser.brkPublicKeyRaw),
    };
  }
}

function initialHello(state: BrowserCanonicalState): CanonicalHelloData {
  return {
    device: "M5StickS3",
    deviceId: "synthetic-device",
    firmware: "0.1.0",
    protocol: 2,
    storageSchema: 2,
    vaultFormat: 1,
    buildCommit: "synthetic",
    state: "unlocked",
    storageReady: true,
    vaultPresent: true,
    vaultId: state.vault.vaultId.slice(),
    generation: state.vault.generation,
    registrationPresent: true,
    registrationId: state.trustedBrowser.registrationId.slice(),
    registrationEpoch: state.trustedBrowser.epoch,
    brkPublicKey: state.trustedBrowser.brkPublicKeyRaw.slice(),
  };
}

describe("canonical VMK re-key integration", () => {
  it("stages Browser state, requires a fresh authenticated session, and commits generation +1", async () => {
    const vaultId = bytes(16, 0x30);
    const oldVmk = bytes(32, 0x40);
    const plaintext = new TextEncoder().encode("synthetic-rekey-payload");
    const vault = await encryptVault(plaintext, oldVmk, vaultId, 4n);
    const recovery = await wrapVmkWithPassphrase(oldVmk, vaultId, recoveryPassphrase);
    const state = await createBrowserCanonicalState({
      vault,
      recoveryWrappedVmk: recovery,
      vmk: oldVmk,
      registrationEpoch: 2,
      status: "active",
      deviceMetadata: { deviceId: "synthetic-device" },
    });
    const store = new MemoryStore(state);
    const transport = new RekeyTransport(state);
    const management = new CanonicalDeviceManagement(
      transport,
      initialHello(state),
      store.asIndexedDb(),
    );
    await management.initialize();

    await management.rotateVmk(recoveryPassphrase);

    expect(transport.beginOperation).toBe("vmk_rekey");
    expect(transport.statusCalls).toBeGreaterThan(0);
    expect(transport.completed).toBe(true);
    expect(transport.rekeyCommitted).toBe(true);
    expect(transport.generation).toBe(5n);
    expect(transport.state).toBe("unlocked");
    expect(store.current().vault.generation).toBe(5n);

    const newVmk = await unwrapVmkForTrustedBrowser(store.current());
    expect(newVmk).not.toEqual(oldVmk);
    const decrypted = await decryptVault(store.current().vault, newVmk);
    expect(decrypted).toEqual(plaintext);

    newVmk.fill(0);
    decrypted.fill(0);
    plaintext.fill(0);
    oldVmk.fill(0);
  }, 30_000);
});
