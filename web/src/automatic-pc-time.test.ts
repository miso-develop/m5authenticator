import { describe, expect, it, vi } from "vitest";

import {
  isAutomaticPcTimeSyncEligible,
  synchronizePcTimeIfEligible,
} from "./automatic-pc-time";
import type { CanonicalDeviceSnapshot } from "./canonical-management";

function snapshot(
  state: CanonicalDeviceSnapshot["hello"]["state"] = "unlocked",
  ownership: CanonicalDeviceSnapshot["browserOwnership"] = "active",
  readiness: CanonicalDeviceSnapshot["time"]["readiness"] = "not_synced",
): CanonicalDeviceSnapshot {
  return {
    hello: {
      device: "M5StickS3",
      deviceId: "synthetic-device",
      firmware: "0.0.0-test",
      protocol: 2,
      storageSchema: 2,
      vaultFormat: 2,
      supportedVaultFormats: [1, 2],
      buildCommit: "synthetic",
      state,
      storageReady: true,
      recoveryResetRequired: false,
      factoryResetPresenceRequired: true,
      vaultPresent: state !== "unprovisioned",
      vaultId: state !== "unprovisioned" ? new Uint8Array(16) : null,
      generation: state !== "unprovisioned" ? 1n : 0n,
      registrationPresent: state !== "unprovisioned",
      registrationId: state !== "unprovisioned" ? new Uint8Array(16) : null,
      registrationEpoch: state !== "unprovisioned" ? 1 : 0,
      brkPublicKey: state !== "unprovisioned" ? new Uint8Array(65) : null,
    },
    time: {
      readiness,
      source: readiness === "ready" ? "ntp" : "none",
      sourceAuthenticity: readiness === "ready" ? "unauthenticated_network" : "none",
      lastSyncUnixSeconds: readiness === "ready" ? 1n : 0n,
      ageSeconds: 0,
      resyncDue: readiness === "stale",
    },
    browserOwnership: ownership,
    unlockRequired: state === "locked" && ownership === "active",
    recoveryProvisioningAvailable: false,
    recoveryProvisioningCandidates: 0,
    accounts: [],
    wifi: { configured: false, ssid: "" },
    autoLock: { known: state === "unlocked", days: null, format2Writable: true },
  };
}

describe("automatic PC time synchronization guard", () => {
  it.each(["not_synced", "stale"] as const)(
    "permits active Trusted Browser + UNLOCKED + %s",
    async (readiness) => {
      const syncTime = vi.fn(async () => snapshot("unlocked", "active", "ready").time);
      const current = snapshot("unlocked", "active", readiness);

      expect(isAutomaticPcTimeSyncEligible(current, false)).toBe(true);
      await expect(synchronizePcTimeIfEligible({ syncTime }, current, false))
        .resolves.toEqual({ kind: "synchronized" });
      expect(syncTime).toHaveBeenCalledTimes(1);
    },
  );

  it("does not overwrite a READY anchor automatically", async () => {
    const syncTime = vi.fn();
    const current = snapshot("unlocked", "active", "ready");

    expect(isAutomaticPcTimeSyncEligible(current, false)).toBe(false);
    await expect(synchronizePcTimeIfEligible({ syncTime }, current, false))
      .resolves.toEqual({ kind: "skipped" });
    expect(syncTime).not.toHaveBeenCalled();
  });

  it.each([
    ["locked Device", snapshot("locked", "active", "not_synced"), false],
    ["unprovisioned Device", snapshot("unprovisioned", "none", "not_synced"), false],
    ["no ownership", snapshot("unlocked", "none", "not_synced"), false],
    ["replacement-pending ownership", snapshot("unlocked", "replacement-pending", "not_synced"), false],
    ["conflicting ownership", snapshot("unlocked", "conflict", "not_synced"), false],
    ["Recovery Factory Reset mode", snapshot("unlocked", "active", "not_synced"), true],
  ] as const)("skips %s", async (_name, current, recoveryResetActive) => {
    const syncTime = vi.fn();
    await expect(synchronizePcTimeIfEligible({ syncTime }, current, recoveryResetActive))
      .resolves.toEqual({ kind: "skipped" });
    expect(syncTime).not.toHaveBeenCalled();
  });

  it("reports one best-effort failure without retrying", async () => {
    const failure = new Error("synthetic time sync failure");
    const syncTime = vi.fn(async () => { throw failure; });

    await expect(synchronizePcTimeIfEligible(
      { syncTime },
      snapshot("unlocked", "active", "stale"),
      false,
    )).resolves.toEqual({ kind: "failed", error: failure });
    expect(syncTime).toHaveBeenCalledTimes(1);
  });
});
