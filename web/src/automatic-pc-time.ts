import type { CanonicalDeviceManagement, CanonicalDeviceSnapshot } from "./canonical-management";

export type AutomaticPcTimeSyncResult =
  | { kind: "skipped" }
  | { kind: "synchronized" }
  | { kind: "failed"; error: unknown };

export function isAutomaticPcTimeSyncEligible(
  snapshot: CanonicalDeviceSnapshot | null,
  recoveryResetActive: boolean,
): boolean {
  if (recoveryResetActive || !snapshot) return false;
  if (snapshot.browserOwnership !== "active") return false;
  if (snapshot.hello.state !== "unlocked") return false;
  return snapshot.time.readiness === "not_synced" || snapshot.time.readiness === "stale";
}

export async function synchronizePcTimeIfEligible(
  management: Pick<CanonicalDeviceManagement, "syncTime"> | null,
  snapshot: CanonicalDeviceSnapshot | null,
  recoveryResetActive: boolean,
): Promise<AutomaticPcTimeSyncResult> {
  if (!management || !isAutomaticPcTimeSyncEligible(snapshot, recoveryResetActive)) {
    return { kind: "skipped" };
  }

  try {
    // CanonicalDeviceManagement.syncTime() re-reads Device/browser state and
    // applies requireActiveWriter() immediately before the mutation. The
    // eligibility snapshot is advisory and never replaces that authoritative
    // write-time gate.
    await management.syncTime();
    return { kind: "synchronized" };
  } catch (error) {
    return { kind: "failed", error };
  }
}
