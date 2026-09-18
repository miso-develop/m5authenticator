import { describe, expect, it, vi } from "vitest";

import { cleanupBrowserLifecycle } from "./browser-lifecycle";
import { CanonicalDeviceManagement } from "./canonical-management";
import type { CanonicalWireOperation, CanonicalHelloData } from "./canonical-protocol-v2";
import type { SessionWireOperation } from "./security/session-protocol-v2";
import type { CanonicalV2Transport } from "./serial";

const initialHello: CanonicalHelloData = {
  device: "M5StickS3",
  deviceId: "synthetic-lifecycle-device",
  firmware: "0.0.0-test",
  protocol: 2,
  storageSchema: 2,
  vaultFormat: 2,
  supportedVaultFormats: [1, 2],
  buildCommit: "synthetic",
  state: "unlocked",
  storageReady: true,
  recoveryResetRequired: false,
  factoryResetPresenceRequired: true,
  vaultPresent: true,
  vaultId: new Uint8Array(16),
  generation: 1n,
  registrationPresent: true,
  registrationId: new Uint8Array(16),
  registrationEpoch: 1,
  brkPublicKey: new Uint8Array(65),
};

class OperationTransport implements CanonicalV2Transport {
  public readonly canonicalOperations: CanonicalWireOperation[] = [];
  public closeCount = 0;

  async requestCanonicalV2(op: CanonicalWireOperation): Promise<Record<string, unknown>> {
    this.canonicalOperations.push(op);
    return {};
  }

  async requestV2(_op: SessionWireOperation): Promise<Record<string, unknown>> {
    throw new Error("session operation not expected");
  }

  async close(): Promise<void> {
    this.closeCount += 1;
  }
}

describe("browser lifecycle transport boundary", () => {
  it("runs transient cleanup and uses transport-only management disconnect", async () => {
    const abortPending = vi.fn();
    const clearTransientState = vi.fn();
    const disconnectTransport = vi.fn(async () => undefined);
    const explicitClose = vi.fn(async () => undefined);
    const serialClose = vi.fn(async () => undefined);

    cleanupBrowserLifecycle({
      abortPending,
      clearTransientState,
      management: { disconnectTransport },
      serialSession: { close: serialClose },
    });
    await Promise.resolve();

    expect(abortPending).toHaveBeenCalledTimes(1);
    expect(clearTransientState).toHaveBeenCalledTimes(1);
    expect(disconnectTransport).toHaveBeenCalledTimes(1);
    expect(serialClose).not.toHaveBeenCalled();
    expect(explicitClose).not.toHaveBeenCalled();
  });

  it("falls back to transport close when canonical management is not active", async () => {
    const serialClose = vi.fn(async () => undefined);
    cleanupBrowserLifecycle({
      abortPending: () => undefined,
      clearTransientState: () => undefined,
      management: null,
      serialSession: { close: serialClose },
    });
    await Promise.resolve();
    expect(serialClose).toHaveBeenCalledTimes(1);
  });

  it("CanonicalDeviceManagement transport teardown sends no device.lock", async () => {
    const transport = new OperationTransport();
    const management = new CanonicalDeviceManagement(transport, initialHello);

    await management.disconnectTransport();

    expect(transport.canonicalOperations).toEqual([]);
    expect(transport.closeCount).toBe(1);
  });

  it("explicit close sends one device.lock before transport close", async () => {
    const transport = new OperationTransport();
    const management = new CanonicalDeviceManagement(transport, initialHello);

    await management.close();

    expect(transport.canonicalOperations).toEqual(["device.lock"]);
    expect(transport.closeCount).toBe(1);
  });
});
