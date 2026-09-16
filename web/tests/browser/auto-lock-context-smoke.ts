import { createAutoLockSettingsController } from "../../src/auto-lock-settings";
import type { CanonicalDeviceSnapshot } from "../../src/canonical-management";
import { setLanguage } from "../../src/i18n";

function expectCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function required<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error(`Automatic LOCK context smoke fixture is missing ${selector}`);
  return element;
}

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function snapshot(
  deviceId: string,
  vaultStart: number,
  registrationStart: number,
  generation: bigint,
  autoLockDays: number | null,
): CanonicalDeviceSnapshot {
  return {
    hello: {
      device: "M5StickS3",
      deviceId,
      firmware: "0.1.0-test",
      protocol: 2,
      storageSchema: 2,
      vaultFormat: 2,
      supportedVaultFormats: [1, 2],
      buildCommit: "0123456789abcdef",
      state: "unlocked",
      storageReady: true,
      recoveryResetRequired: false,
      vaultPresent: true,
      vaultId: bytes(16, vaultStart),
      generation,
      registrationPresent: true,
      registrationId: bytes(16, registrationStart),
      registrationEpoch: 1,
      brkPublicKey: bytes(65, registrationStart + 32),
    },
    time: {
      readiness: "ready",
      source: "usb",
      lastSyncUnixSeconds: 1_800_000_000n,
      ageSeconds: 0,
      resyncDue: false,
    },
    browserOwnership: "active",
    unlockRequired: false,
    recoveryProvisioningAvailable: false,
    recoveryProvisioningCandidates: 0,
    accounts: [],
    wifi: { configured: false, ssid: "" },
    autoLock: {
      known: true,
      days: autoLockDays,
      format2Writable: true,
    },
  };
}

export async function runAutoLockContextSmoke(): Promise<void> {
  document.body.innerHTML = `
    <div id="app">
      <main class="shell">
        <section class="panel" aria-labelledby="rekey-heading">
          <h2 id="rekey-heading">Synthetic re-key boundary</h2>
        </section>
      </main>
    </div>
  `;
  setLanguage("en", false);

  const saves: Array<number | null> = [];
  const controller = createAutoLockSettingsController(async (days) => {
    saves.push(days);
  });
  const enabled = required<HTMLInputElement>("#auto-lock-enabled");
  const days = required<HTMLSelectElement>("#auto-lock-days");
  const save = required<HTMLButtonElement>("#save-auto-lock");

  const deviceA = snapshot("device-a", 0x10, 0x30, 4n, null);
  const deviceB = snapshot("device-b", 0x50, 0x70, 9n, 31);

  controller.render(deviceA, false, false);
  expectCondition(!enabled.checked, "Device A canonical disabled state was not rendered");
  expectCondition(days.value === "1", "Disabled Device A did not keep the 1-day draft selector default");

  enabled.click();
  expectCondition(enabled.checked, "Device A draft did not become enabled");
  expectCondition(!save.disabled, "Device A dirty draft did not enable Save");

  // Re-rendering the same canonical context may preserve the unsaved edit.
  controller.render(deviceA, false, false);
  expectCondition(enabled.checked && !save.disabled, "Same-context Device A draft was discarded unexpectedly");

  // Losing the canonical/Device context must invalidate the dirty draft.
  controller.render(null, false, false);
  expectCondition(save.disabled, "Disconnected automatic-LOCK form retained an actionable stale Save");

  // Connecting a different canonical context must render Device B's authoritative
  // setting and must not make Device A's stale draft actionable on Device B.
  controller.render(deviceB, false, false);
  expectCondition(enabled.checked, "Device B enabled canonical state was masked by Device A draft");
  expectCondition(days.value === "31", "Device B 31-day canonical setting was masked by Device A draft");
  expectCondition(save.disabled, "Device B exposed Save for Device A's stale dirty draft");
  save.click();
  await Promise.resolve();
  expectCondition(saves.length === 0, "Device A stale draft was saved into Device B context");

  // Cover the security-significant reverse direction as well: a stale disabled
  // draft must not be able to disable another Device's active policy.
  const deviceAEnabled = snapshot("device-a", 0x10, 0x30, 5n, 1);
  controller.render(deviceAEnabled, false, false);
  expectCondition(enabled.checked && days.value === "1", "Device A enabled canonical state was not rendered");
  enabled.click();
  expectCondition(!enabled.checked && !save.disabled, "Device A disabled draft did not become dirty");
  controller.render(null, false, false);
  controller.render(deviceB, false, false);
  expectCondition(enabled.checked && days.value === "31", "Stale disabled draft masked Device B policy");
  expectCondition(save.disabled, "Stale disabled draft remained actionable on Device B");
  save.click();
  await Promise.resolve();
  expectCondition(saves.length === 0, "Stale disabled draft changed Device B automatic-LOCK policy");

  controller.dispose();
  document.body.dataset.autoLockContextStatus = "pass";
}
