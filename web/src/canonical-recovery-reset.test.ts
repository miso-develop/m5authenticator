import { describe, expect, it } from "vitest";
import { CanonicalRecoveryResetController } from "./canonical-recovery-reset";
import { parseCanonicalHelloData, type CanonicalHelloData, type CanonicalWireOperation } from "./canonical-protocol-v2";
import type { BrowserCanonicalState } from "./security/browser-vault";
import { encodeBase64UrlCanonical, type SessionWireOperation } from "./security/session-protocol-v2";
import type { CanonicalV2Transport } from "./serial";

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function recoveryHelloRaw() {
  return {
    device: "M5StickS3",
    device_id: "00112233445566778899aabbccddeeff",
    firmware: "0.1.0",
    protocol: 2,
    storage_schema: 2,
    vault_format: 1,
    build_commit: "synthetic",
    state: "locked",
    storage_ready: true,
    recovery_reset_required: true,
    vault_present: true,
    vault_id: encodeBase64UrlCanonical(bytes(16, 0x10)),
    generation: "4",
    registration_present: false,
    registration_id: null,
    registration_epoch: 0,
    brk_public_key: null,
  };
}

function finalHelloRaw() {
  return {
    device: "M5StickS3",
    device_id: "00112233445566778899aabbccddeeff",
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

class FakeRecoveryTransport implements CanonicalV2Transport {
  readonly operations: CanonicalWireOperation[] = [];
  private reset = false;
  private statusReads = 0;
  private readonly attemptId = bytes(16, 0x70);

  async requestCanonicalV2(
    op: CanonicalWireOperation,
    params: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    this.operations.push(op);
    if (op === "hello") return this.reset ? finalHelloRaw() : recoveryHelloRaw();
    if (op === "factory_reset.recovery_begin") {
      return { attempt_id: encodeBase64UrlCanonical(this.attemptId), expires_in_ms: 30_000 };
    }
    if (op === "factory_reset.recovery_status") {
      expect(params.attempt_id).toBe(encodeBase64UrlCanonical(this.attemptId));
      this.statusReads += 1;
      return { state: this.statusReads >= 2 ? "confirmed" : "awaiting_confirmation" };
    }
    if (op === "factory_reset.recovery_complete") {
      expect(params.attempt_id).toBe(encodeBase64UrlCanonical(this.attemptId));
      this.reset = true;
      return {};
    }
    throw new Error(`unexpected canonical op: ${op}`);
  }

  async requestV2(_op: SessionWireOperation): Promise<Record<string, unknown>> {
    throw new Error("Session Protocol must not be used by Recovery Factory Reset");
  }

  async close(): Promise<void> {}
}

function cleanupState(deviceId: string, vaultId: Uint8Array, generation: bigint): BrowserCanonicalState {
  return {
    deviceMetadata: { deviceId },
    vault: { vaultId, generation },
  } as unknown as BrowserCanonicalState;
}

describe("Recovery Factory Reset isolation", () => {
  it("cannot be constructed for a normal canonical Device state", () => {
    const normal = parseCanonicalHelloData({ ...finalHelloRaw(), state: "unprovisioned" });
    const transport = new FakeRecoveryTransport();
    expect(() => new CanonicalRecoveryResetController(transport, normal)).toThrow(/not available/);
  });

  it("requires fresh Device confirmation, resets only the broken Device, and clears matching local state", async () => {
    const initial = parseCanonicalHelloData(recoveryHelloRaw());
    const transport = new FakeRecoveryTransport();
    const localVaultId = bytes(16, 0x10);
    const orphanVaultId = bytes(16, 0x30);
    const otherVaultId = bytes(16, 0x50);
    const local = cleanupState(initial.deviceId, localVaultId, 4n);
    const orphan = cleanupState(initial.deviceId, orphanVaultId, 9n);
    const other = cleanupState("different-device", otherVaultId, 2n);
    const deletedVaults: string[] = [];
    const deletedJournal: string[] = [];

    const store = {
      async list() { return [local, other]; },
      async delete(vaultId: Uint8Array, expectedGeneration?: bigint) {
        deletedVaults.push(`${encodeBase64UrlCanonical(vaultId)}:${expectedGeneration?.toString() ?? "none"}`);
      },
    };
    const journal = {
      async listForDevice(deviceId: string) {
        return deviceId === initial.deviceId ? [{ candidate: orphan }] : [];
      },
      async delete(vaultId: Uint8Array) {
        deletedJournal.push(encodeBase64UrlCanonical(vaultId));
      },
    };

    const controller = new CanonicalRecoveryResetController(transport, initial, store, journal);
    let prompted = 0;
    const result: CanonicalHelloData = await controller.perform(() => { prompted += 1; }, 0);

    expect(prompted).toBe(1);
    expect(result.state).toBe("unprovisioned");
    expect(result.recoveryResetRequired).toBe(false);
    expect(result.vaultPresent).toBe(false);
    expect(result.registrationPresent).toBe(false);
    expect(transport.operations).toEqual([
      "hello",
      "factory_reset.recovery_begin",
      "factory_reset.recovery_status",
      "factory_reset.recovery_status",
      "factory_reset.recovery_complete",
      "hello",
    ]);
    expect(deletedVaults).toEqual([
      `${encodeBase64UrlCanonical(localVaultId)}:4`,
    ]);
    expect(deletedJournal).toEqual([
      encodeBase64UrlCanonical(localVaultId),
      encodeBase64UrlCanonical(orphanVaultId),
    ]);
    expect(deletedVaults.some((value) => value.startsWith(encodeBase64UrlCanonical(otherVaultId)))).toBe(false);
  });
});
