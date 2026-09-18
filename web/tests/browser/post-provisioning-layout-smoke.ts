import "../../src/style.css";
import "../../src/post-provisioning-layout.css";
import { CanonicalDeviceManagement, type CanonicalDeviceSnapshot } from "../../src/canonical-management";
import { SerialSession } from "../../src/serial";
import { ImportSession } from "../../src/import/session";
import { sourceTextOf } from "../../src/ui-localization";
import { installWebBuildInfo } from "../../src/web-build-info";

const GEOMETRY_EPSILON_PX = 0.5;
const ROUTE_WIDTH_PX = 1280;
const FIRMWARE_SMOKE_BUILD_COMMIT = "fedcba9876543210";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function near(left: number, right: number): boolean {
  return Math.abs(left - right) <= GEOMETRY_EPSILON_PX;
}

function flushLayout(doc: Document = document): void {
  void doc.documentElement.offsetWidth;
}

async function waitUntil(predicate: () => boolean, message: string, timeoutMs = 4000): Promise<void> {
  const deadline = performance.now() + timeoutMs;
  while (!predicate()) {
    if (performance.now() >= deadline) throw new Error(message);
    await new Promise<void>((resolve) => window.setTimeout(resolve, 10));
  }
}

export async function runPostProvisioningLayoutSmoke(): Promise<void> {
  try {
    await verifyProductionProvisioningLifecycle();
    await verifyProductionFirmwareGeometry();
    await verifySharedRouteGeometryPolicy();
    await verifyStickyHeaderPolicy();
    document.body.dataset.postProvisioningLayoutStatus = "pass";
  } catch (error) {
    document.body.dataset.postProvisioningLayoutError = error instanceof Error ? error.message : "Unknown layout smoke failure";
    throw error;
  }
}

async function verifyProductionProvisioningLifecycle(): Promise<void> {
  const app = document.createElement("main");
  app.id = "app";
  document.body.append(app);

  let currentSnapshot = createSnapshot(false);
  const originalConnect = SerialSession.connect;
  const originalInitialize = CanonicalDeviceManagement.prototype.initialize;
  const originalRefresh = CanonicalDeviceManagement.prototype.refresh;
  const originalImportAccounts = CanonicalDeviceManagement.prototype.importAccounts;
  const originalFactoryReset = CanonicalDeviceManagement.prototype.factoryReset;
  const originalRequestUnlock = CanonicalDeviceManagement.prototype.requestUnlock;
  const originalSyncTime = CanonicalDeviceManagement.prototype.syncTime;
  const originalClose = CanonicalDeviceManagement.prototype.close;
  const originalDisconnectTransport = CanonicalDeviceManagement.prototype.disconnectTransport;
  const originalHasCompleteAccounts = ImportSession.prototype.hasCompleteAccounts;
  const originalConfirm = window.confirm;

  let syncTimeCalls = 0;
  let requestUnlockCalls = 0;
  let explicitCloseCalls = 0;
  let transportDisconnectCalls = 0;
  let syncFailure: Error | null = null;
  let unlockFailure: Error | null = null;
  let unlockGate: Promise<void> | null = null;

  SerialSession.connect = async () => ({
    session: {
      isClosed: () => false,
      close: async () => undefined,
    } as unknown as SerialSession,
    hello: currentSnapshot.hello,
  });
  CanonicalDeviceManagement.prototype.initialize = async function (): Promise<void> {};
  const refreshFromSnapshot = async function (): Promise<CanonicalDeviceSnapshot> {
    return currentSnapshot;
  };
  CanonicalDeviceManagement.prototype.refresh = refreshFromSnapshot;
  CanonicalDeviceManagement.prototype.importAccounts = async function (
    _importSession: ImportSession,
    _recoveryPassphrase?: string,
  ): Promise<number> {
    currentSnapshot = createSnapshot(true, false);
    return 1;
  };
  CanonicalDeviceManagement.prototype.requestUnlock = async function (): Promise<void> {
    requestUnlockCalls += 1;
    if (unlockGate) await unlockGate;
    if (unlockFailure) throw unlockFailure;
    currentSnapshot = {
      ...currentSnapshot,
      hello: { ...currentSnapshot.hello, state: "unlocked" },
      browserOwnership: "active",
      unlockRequired: false,
    };
  };
  CanonicalDeviceManagement.prototype.syncTime = async function () {
    syncTimeCalls += 1;
    if (syncFailure) throw syncFailure;
    currentSnapshot = {
      ...currentSnapshot,
      time: {
        readiness: "ready",
        source: "usb",
        sourceAuthenticity: "local_host_asserted",
        lastSyncUnixSeconds: 1n,
        ageSeconds: 0,
        resyncDue: false,
      },
    };
    return currentSnapshot.time;
  };
  CanonicalDeviceManagement.prototype.close = async function (): Promise<void> {
    explicitCloseCalls += 1;
  };
  CanonicalDeviceManagement.prototype.disconnectTransport = async function (): Promise<void> {
    transportDisconnectCalls += 1;
  };
  ImportSession.prototype.hasCompleteAccounts = function (): boolean {
    return true;
  };
  CanonicalDeviceManagement.prototype.factoryReset = async function (
    options: Parameters<CanonicalDeviceManagement["factoryReset"]>[0] = {},
  ): Promise<void> {
    options.onAwaitingConfirmation?.();
    await new Promise<void>((_resolve, reject) => {
      const signal = options.signal;
      if (!signal) {
        reject(new Error("Factory Reset UI smoke requires an AbortSignal"));
        return;
      }
      if (signal.aborted) {
        reject(new Error("Factory Reset canceled. Device and browser canonical state were not cleared."));
        return;
      }
      signal.addEventListener("abort", () => {
        reject(new Error("Factory Reset canceled. Device and browser canonical state were not cleared."));
      }, { once: true });
    });
  };
  window.confirm = () => true;

  try {
    await import("../../src/main");

    const connect = required<HTMLButtonElement>(document, "#connect");
    const unlock = required<HTMLButtonElement>(document, "#unlock-device");
    const disconnect = required<HTMLButtonElement>(document, "#disconnect");
    const refresh = required<HTMLButtonElement>(document, "#refresh-device");
    const syncTime = required<HTMLButtonElement>(document, "#sync-time");
    const connectionState = required<HTMLElement>(document, "#connection-state");
    const deviceStatus = required<HTMLElement>(document, "#device-status");
    const fields = required<HTMLElement>(document, "#initial-passphrase-fields");
    const passphrase = required<HTMLInputElement>(document, "#initial-recovery-passphrase");
    const passphraseConfirm = required<HTMLInputElement>(document, "#initial-recovery-passphrase-confirm");
    const wifiPassword = required<HTMLInputElement>(document, "#wifi-password");
    const rekeyPassphrase = required<HTMLInputElement>(document, "#rekey-recovery-passphrase");
    const provision = required<HTMLButtonElement>(document, "#provision-import");
    const resetConfirmation = required<HTMLInputElement>(document, "#reset-confirmation");
    const factoryReset = required<HTMLButtonElement>(document, "#factory-reset");
    const cancelFactoryReset = required<HTMLButtonElement>(document, "#cancel-factory-reset");
    const factoryResetHint = required<HTMLElement>(document, "#factory-reset-hint");
    const deviceNotice = required<HTMLElement>(document, "#device-notice");
    const shell = required<HTMLElement>(document, "#app > .shell");
    const panels = shell.querySelectorAll<HTMLElement>(":scope > section.panel");
    assert(panels.length >= 2, "Production Provisioning route must render multiple major panels");

    flushLayout();
    assert(passphrase.disabled && passphraseConfirm.disabled, "Disconnected production UI must keep initial Recovery Passphrase inactive");
    assert(getComputedStyle(fields).display === "none", "Inactive production Recovery Passphrase block must be hidden");

    connect.click();
    await waitUntil(
      () => connectionState.textContent === "Connected" && deviceStatus.textContent?.includes("unprovisioned") === true && !passphrase.disabled,
      "Production Provisioning route did not reach the unprovisioned snapshot state",
    );
    flushLayout();
    assert(!passphrase.disabled && !passphraseConfirm.disabled, "Initial provisioning must enable Recovery Passphrase inputs");
    assert(getComputedStyle(fields).display !== "none", "Initial provisioning must show Recovery Passphrase inputs");
    assert(!provision.disabled, "Synthetic complete import must enable initial provisioning");

    passphrase.value = "synthetic-recovery-passphrase";
    passphraseConfirm.value = "synthetic-recovery-passphrase";
    provision.click();
    await waitUntil(
      () => deviceStatus.textContent?.includes("unlocked") === true &&
        deviceNotice.textContent === "Canonical Vault update completed.",
      "Successful initial provisioning must replace the busy notice with a stable terminal success message",
    );

    currentSnapshot = createSnapshot(true, false);
    refresh.click();
    await waitUntil(
      () => deviceStatus.textContent?.includes("unlocked") === true &&
        passphrase.disabled &&
        deviceNotice.textContent === "Canonical status refreshed.",
      "Production Provisioning route did not reach the provisioned snapshot state with a terminal refresh notice",
    );
    flushLayout();
    assert(passphrase.disabled && passphraseConfirm.disabled, "Provisioned management UI must make initial Recovery Passphrase inputs inactive");
    assert(getComputedStyle(fields).display === "none", "Provisioned management UI must hide the non-actionable initial Recovery Passphrase block");
    assert(resetConfirmation.disabled && factoryReset.disabled, "Legacy/no-capability firmware must keep normal Factory Reset unavailable");
    assert(factoryResetHint.textContent?.includes("requires updated firmware") === true, "Legacy/no-capability firmware must show update-required Factory Reset guidance");
    assert(sourceTextOf(deviceStatus).includes("READY — operational readiness only"), "Production status must describe READY as operational readiness");
    assert(
      sourceTextOf(deviceStatus).includes("PC/local-host asserted time (not cryptographically authenticated)"),
      "Production status must distinguish local-host asserted time without an authentication claim",
    );

    currentSnapshot = {
      ...createSnapshot(true, false),
      time: {
        ...createSnapshot(true, false).time,
        source: "ntp",
        sourceAuthenticity: "unauthenticated_network",
      },
    };
    refresh.click();
    await waitUntil(
      () => sourceTextOf(deviceStatus).includes("Network time (unauthenticated)"),
      "Production status did not surface unauthenticated network time",
    );

    currentSnapshot = {
      ...createSnapshot(true, false),
      time: {
        ...createSnapshot(true, false).time,
        source: "ntp",
        sourceAuthenticity: "unknown",
      },
    };
    refresh.click();
    await waitUntil(
      () => sourceTextOf(deviceStatus).includes("NTP time (authenticity metadata unavailable)"),
      "Production status must not invent authenticity when Device metadata is unavailable",
    );

    CanonicalDeviceManagement.prototype.refresh = async function (): Promise<CanonicalDeviceSnapshot> {
      throw new Error("Synthetic refresh failure.");
    };
    refresh.click();
    await waitUntil(
      () => deviceNotice.textContent === "Synthetic refresh failure.",
      "Failed Device action must keep the actual error instead of applying terminal success text",
    );
    CanonicalDeviceManagement.prototype.refresh = refreshFromSnapshot;

    currentSnapshot = createSnapshot(true, true);
    refresh.click();
    await waitUntil(
      () => !resetConfirmation.disabled &&
        factoryResetHint.textContent?.includes("fresh confirmation on M5StickS3") === true &&
        deviceNotice.textContent === "Canonical status refreshed.",
      "Capable production UI did not enable secure Factory Reset controls with a stable terminal refresh notice",
    );
    resetConfirmation.value = "RESET";
    resetConfirmation.dispatchEvent(new Event("input", { bubbles: true }));
    assert(!factoryReset.disabled, "Typed RESET gate must arm Factory Reset only on capable firmware");
    factoryReset.click();
    await waitUntil(
      () => !cancelFactoryReset.hidden && sourceTextOf(deviceNotice).includes("press A on M5StickS3"),
      "Production Factory Reset UI did not enter fresh Device-confirmation pending state",
    );
    assert(factoryReset.disabled, "Factory Reset must not be re-armed while Device confirmation is pending");
    cancelFactoryReset.click();
    await waitUntil(
      () => cancelFactoryReset.hidden && sourceTextOf(deviceNotice).includes("Device and browser canonical state were not cleared"),
      "Production Factory Reset UI did not reach the explicit canceled state",
    );

    const firstStyle = getComputedStyle(panels[0]!);
    const secondStyle = getComputedStyle(panels[1]!);
    assert(parseFloat(firstStyle.marginTop) < 32, "First Provisioning section must not gain the large subsequent-section margin");
    assert(parseFloat(secondStyle.marginTop) >= 32, "Subsequent Provisioning sections require at least 32px top separation");
    assert(parseFloat(secondStyle.paddingTop) >= 32, "Subsequent Provisioning headings require at least 32px boundary padding");

    installWebBuildInfo(shell);
    flushLayout();

    const buildSection = required<HTMLElement>(shell, "#web-build-info-section");
    const buildHeading = required<HTMLElement>(buildSection, "#web-build-info-heading");
    const buildIdentity = required<HTMLElement>(buildSection, "#web-build-identity");
    assert(buildSection.tagName === "SECTION", "Web build provenance must use a semantic section");
    assert(buildSection.getAttribute("aria-labelledby") === buildHeading.id, "Web build section heading must label its section");
    assert(sourceTextOf(buildHeading) === "Build information", "Web build section must expose the localized Build information heading source");
    assert(buildSection.contains(buildIdentity), "Web build identity rows must remain inside the Build information section");
    assert(shell.lastElementChild === buildSection, "Web Build information section must follow primary Provisioning content");

    const majorSections = Array.from(shell.querySelectorAll<HTMLElement>(":scope > section.panel"));
    assert(majorSections.length >= 7, "Provisioning must render all required operational peers plus the Build information section");
    const requiredHeadings = [
      "Device",
      "Import accounts",
      "Canonical accounts",
      "Wi-Fi for NTP",
      "Rotate Vault Master Key",
      "Factory Reset",
      "Build information",
    ];
    const renderedHeadings = majorSections.map((section, index) => {
      const heading = section.querySelector("h2");
      assert(heading !== null, `Provisioning section ${index + 1} must have a section heading`);
      return sourceTextOf(heading);
    });
    for (const expected of requiredHeadings) {
      assert(renderedHeadings.includes(expected), `Provisioning must retain the required peer section: ${expected}`);
    }
    majorSections.forEach((section, index) => {
      const style = getComputedStyle(section);
      assert(style.borderTopStyle !== "none" && parseFloat(style.borderTopWidth) >= 1, `Provisioning section ${index + 1} must have one visible top divider`);
      assert(section.querySelector(":scope > hr") === null, `Provisioning section ${index + 1} must not add a duplicate hr divider`);
      if (index > 0) {
        assert(parseFloat(style.marginTop) >= 32, `Provisioning section ${index + 1} requires at least 32px separation`);
        assert(parseFloat(style.paddingTop) >= 32, `Provisioning section ${index + 1} requires at least 32px boundary padding`);
      }
    });
    const recoverySubsection = required<HTMLElement>(shell, '[data-security-subsection="recovery-package"]');
    const passphraseSubsection = required<HTMLElement>(shell, '[data-security-subsection="change-passphrase"]');
    for (const [name, subsection] of [
      ["Recovery Package", recoverySubsection],
      ["Change Recovery Passphrase", passphraseSubsection],
    ] as const) {
      const heading = subsection.querySelector(":scope > h3");
      assert(heading?.textContent === name, `${name} must retain its semantic h3 heading`);
      const style = getComputedStyle(subsection);
      assert(style.borderTopStyle !== "none" && parseFloat(style.borderTopWidth) >= 1, `${name} must have one visible subsection divider`);
      assert(parseFloat(style.marginTop) > 0 && parseFloat(style.paddingTop) > 0, `${name} divider must retain subsection spacing`);
      assert(subsection.querySelector(":scope > hr") === null, `${name} must not duplicate the CSS divider with an hr`);
      assert(getComputedStyle(heading).marginTop === "0px", `${name} heading must start immediately after the shared divider spacing`);
    }
    assert(
      getComputedStyle(recoverySubsection).borderTopColor === getComputedStyle(passphraseSubsection).borderTopColor,
      "Recovery subsections must share the same neutral divider treatment",
    );

    const regularDivider = getComputedStyle(majorSections[0]!).borderTopColor;
    const dangerDivider = getComputedStyle(required<HTMLElement>(shell, "section.danger")).borderTopColor;
    assert(dangerDivider !== regularDivider, "Factory Reset must retain its danger-tinted divider semantics");

    // Explicit user disconnect remains the Device Lock path.
    const closeBeforeExplicitDisconnect = explicitCloseCalls;
    disconnect.click();
    await waitUntil(
      () => connectionState.textContent === "Disconnected",
      "Explicit Lock & Disconnect did not tear down the production connection",
    );
    assert(explicitCloseCalls === closeBeforeExplicitDisconnect + 1, "Explicit Lock & Disconnect must invoke canonical close exactly once");

    // Connect to an already-UNLOCKED active Device with no usable anchor.
    currentSnapshot = createSnapshot(true, false, { readiness: "not_synced" });
    syncTimeCalls = 0;
    syncFailure = null;
    connect.click();
    await waitUntil(
      () => connectionState.textContent === "Connected" &&
        syncTimeCalls === 1 &&
        sourceTextOf(deviceStatus).includes("PC/local-host asserted time (not cryptographically authenticated)") &&
        sourceTextOf(deviceNotice).includes("PC time synchronized automatically"),
      "Connect-to-UNLOCKED not_synced path did not auto-sync PC time exactly once",
    );
    assert(syncTimeCalls === 1, "Connect-to-UNLOCKED not_synced must send one automatic time sync");
    disconnect.click();
    await waitUntil(() => connectionState.textContent === "Disconnected", "Disconnect after not_synced auto-sync did not complete");

    // STALE is also eligible.
    currentSnapshot = createSnapshot(true, false, { readiness: "stale" });
    syncTimeCalls = 0;
    connect.click();
    await waitUntil(
      () => connectionState.textContent === "Connected" && syncTimeCalls === 1 &&
        sourceTextOf(deviceNotice).includes("PC time synchronized automatically"),
      "Connect-to-UNLOCKED stale path did not auto-sync PC time",
    );
    assert(syncTimeCalls === 1, "Connect-to-UNLOCKED stale must send one automatic time sync");
    disconnect.click();
    await waitUntil(() => connectionState.textContent === "Disconnected", "Disconnect after stale auto-sync did not complete");

    // A READY anchor, including unauthenticated NTP, must never be overwritten automatically.
    currentSnapshot = {
      ...createSnapshot(true, false, { readiness: "ready" }),
      time: {
        ...createSnapshot(true, false, { readiness: "ready" }).time,
        source: "ntp",
        sourceAuthenticity: "unauthenticated_network",
      },
    };
    syncTimeCalls = 0;
    connect.click();
    await waitUntil(
      () => connectionState.textContent === "Connected" &&
        sourceTextOf(deviceNotice).includes("Trusted Browser active; Device is UNLOCKED.") &&
        sourceTextOf(deviceStatus).includes("Network time (unauthenticated)"),
      "READY NTP connect path did not preserve the existing anchor",
    );
    await new Promise<void>((resolve) => window.setTimeout(resolve, 20));
    assert(syncTimeCalls === 0, "READY anchor must not be replaced by automatic PC time sync");
    disconnect.click();
    await waitUntil(() => connectionState.textContent === "Disconnected", "Disconnect after READY preservation did not complete");

    // LOCKED Connect must not sync. Unlock must not sync until physical-presence completion resolves.
    currentSnapshot = createSnapshot(true, false, { state: "locked", readiness: "not_synced" });
    syncTimeCalls = 0;
    requestUnlockCalls = 0;
    connect.click();
    await waitUntil(
      () => connectionState.textContent === "Connected" && !unlock.disabled &&
        sourceTextOf(deviceNotice).includes("Device remains LOCKED"),
      "LOCKED production connection did not expose the explicit Unlock path",
    );
    assert(syncTimeCalls === 0, "LOCKED Connect must not send automatic time sync");

    let releaseUnlock!: () => void;
    unlockGate = new Promise<void>((resolve) => { releaseUnlock = resolve; });
    unlock.click();
    await waitUntil(
      () => requestUnlockCalls === 1 && sourceTextOf(deviceNotice).includes("UNLOCK REQUEST"),
      "Unlock smoke did not enter the physical-presence pending state",
    );
    await new Promise<void>((resolve) => window.setTimeout(resolve, 20));
    assert(syncTimeCalls === 0, "Automatic time sync must not run before Unlock physical confirmation completes");
    releaseUnlock();
    unlockGate = null;
    await waitUntil(
      () => syncTimeCalls === 1 &&
        deviceStatus.textContent?.includes("unlocked") === true &&
        sourceTextOf(deviceNotice).includes("PC time synchronized automatically"),
      "Successful Unlock + fresh not_synced status did not auto-sync PC time",
    );
    assert(syncTimeCalls === 1, "Successful Unlock + not_synced must issue one automatic time sync");
    disconnect.click();
    await waitUntil(() => connectionState.textContent === "Disconnected", "Disconnect after Unlock auto-sync did not complete");

    // Successful Unlock from STALE also syncs once.
    currentSnapshot = createSnapshot(true, false, { state: "locked", readiness: "stale" });
    syncTimeCalls = 0;
    requestUnlockCalls = 0;
    connect.click();
    await waitUntil(() => connectionState.textContent === "Connected" && !unlock.disabled, "STALE locked connection did not expose Unlock");
    unlock.click();
    await waitUntil(
      () => requestUnlockCalls === 1 && syncTimeCalls === 1 &&
        sourceTextOf(deviceNotice).includes("PC time synchronized automatically"),
      "Successful Unlock + stale status did not auto-sync PC time",
    );
    disconnect.click();
    await waitUntil(() => connectionState.textContent === "Disconnected", "Disconnect after STALE Unlock auto-sync did not complete");

    // Successful Unlock with an already-READY anchor does not mutate it.
    currentSnapshot = createSnapshot(true, false, { state: "locked", readiness: "ready" });
    syncTimeCalls = 0;
    requestUnlockCalls = 0;
    connect.click();
    await waitUntil(() => connectionState.textContent === "Connected" && !unlock.disabled, "READY locked connection did not expose Unlock");
    unlock.click();
    await waitUntil(
      () => requestUnlockCalls === 1 && deviceStatus.textContent?.includes("unlocked") === true &&
        sourceTextOf(deviceNotice).includes("Trusted Browser active; Device is UNLOCKED."),
      "Successful Unlock + READY did not settle without automatic mutation",
    );
    await new Promise<void>((resolve) => window.setTimeout(resolve, 20));
    assert(syncTimeCalls === 0, "Successful Unlock + READY must not auto-sync");
    disconnect.click();
    await waitUntil(() => connectionState.textContent === "Disconnected", "Disconnect after READY Unlock did not complete");

    // Failed/cancelled Unlock never triggers automatic sync.
    currentSnapshot = createSnapshot(true, false, { state: "locked", readiness: "not_synced" });
    syncTimeCalls = 0;
    requestUnlockCalls = 0;
    unlockFailure = new Error("Synthetic Unlock canceled.");
    connect.click();
    await waitUntil(() => connectionState.textContent === "Connected" && !unlock.disabled, "Failed-Unlock fixture did not connect");
    unlock.click();
    await waitUntil(
      () => requestUnlockCalls === 1 && sourceTextOf(deviceNotice).includes("Synthetic Unlock canceled."),
      "Failed Unlock did not preserve the actual error",
    );
    assert(syncTimeCalls === 0, "Failed/cancelled Unlock must not auto-sync PC time");
    unlockFailure = null;
    disconnect.click();
    await waitUntil(() => connectionState.textContent === "Disconnected", "Disconnect after failed Unlock did not complete");

    // Automatic sync failure is one-shot, non-destructive, and leaves manual retry available.
    currentSnapshot = createSnapshot(true, false, { readiness: "not_synced" });
    syncTimeCalls = 0;
    syncFailure = new Error("Synthetic automatic PC time failure.");
    const closeBeforeSyncFailure = explicitCloseCalls;
    const transportDisconnectBeforeSyncFailure = transportDisconnectCalls;
    connect.click();
    await waitUntil(
      () => connectionState.textContent === "Connected" &&
        sourceTextOf(deviceNotice).includes("automatic PC time sync failed"),
      "Automatic PC time sync failure warning was not shown",
    );
    assert(syncTimeCalls === 1, "Automatic PC time failure must not enter a retry loop");
    assert(deviceStatus.textContent?.includes("unlocked") === true, "Automatic sync failure must not turn the successful connection into LOCKED state");
    assert(!syncTime.disabled, "Manual Sync PC time must remain available after a recoverable automatic-sync failure");
    assert(explicitCloseCalls === closeBeforeSyncFailure, "Automatic sync failure must not issue explicit Device Lock");
    assert(transportDisconnectCalls === transportDisconnectBeforeSyncFailure, "Healthy transport must not be disconnected solely because automatic sync failed");
    await new Promise<void>((resolve) => window.setTimeout(resolve, 30));
    assert(syncTimeCalls === 1, "Automatic PC time failure must remain one-shot");
    syncFailure = null;

    // pagehide is transport lifecycle only and still clears transient form state.
    wifiPassword.value = "synthetic-transient-wifi-password";
    rekeyPassphrase.value = "synthetic-transient-recovery-passphrase";
    passphrase.value = "synthetic-transient-initial-passphrase";
    passphraseConfirm.value = "synthetic-transient-initial-passphrase";
    const closeBeforePagehide = explicitCloseCalls;
    const transportDisconnectBeforePagehide = transportDisconnectCalls;
    window.dispatchEvent(new Event("pagehide"));
    await waitUntil(
      () => transportDisconnectCalls === transportDisconnectBeforePagehide + 1,
      "pagehide did not use transport-only canonical disconnect",
    );
    assert(explicitCloseCalls === closeBeforePagehide, "pagehide must not invoke explicit Device Lock");
    assert(wifiPassword.value === "", "pagehide must clear transient Wi-Fi password state");
    assert(rekeyPassphrase.value === "", "pagehide must clear transient re-key Passphrase state");
    assert(passphrase.value === "" && passphraseConfirm.value === "", "pagehide must clear transient initial Recovery Passphrase state");
  } finally {
    SerialSession.connect = originalConnect;
    CanonicalDeviceManagement.prototype.initialize = originalInitialize;
    CanonicalDeviceManagement.prototype.refresh = originalRefresh;
    CanonicalDeviceManagement.prototype.importAccounts = originalImportAccounts;
    CanonicalDeviceManagement.prototype.factoryReset = originalFactoryReset;
    CanonicalDeviceManagement.prototype.requestUnlock = originalRequestUnlock;
    CanonicalDeviceManagement.prototype.syncTime = originalSyncTime;
    CanonicalDeviceManagement.prototype.close = originalClose;
    CanonicalDeviceManagement.prototype.disconnectTransport = originalDisconnectTransport;
    ImportSession.prototype.hasCompleteAccounts = originalHasCompleteAccounts;
    window.confirm = originalConfirm;
    app.remove();
  }
}

async function verifyProductionFirmwareGeometry(): Promise<void> {
  const frame = await loadRouteFrame("flash.html?layout-smoke=1", 560);
  try {
    const doc = requiredFrameDocument(frame);
    const frameWindow = requiredFrameWindow(frame) as Window & {
      __m5authFirmwareLayoutSmoke?: { resume(): void };
    };
    await waitUntil(
      () => frameWindow.__m5authFirmwareLayoutSmoke !== undefined,
      "Production Firmware route did not expose the qr-smoke async geometry gate",
    );

    const nav = required<HTMLElement>(doc, ".site-nav-shell");
    const shell = required<HTMLElement>(doc, "#flash-app > .shell");
    const status = required<HTMLElement>(doc, "#flash-status");
    const buildSection = required<HTMLElement>(doc, "#firmware-build-info-section");
    const buildHeading = required<HTMLElement>(doc, "#firmware-build-info-heading");
    const buildIdentity = required<HTMLElement>(doc, "#firmware-build-identity");
    flushLayout(doc);

    assert(status.textContent?.includes("Loading and validating pinned firmware target") === true, "Production Firmware route must be measured while actual target resolution is pending");
    assert(buildSection.tagName === "SECTION", "Firmware build provenance must use a semantic section");
    assert(buildSection.getAttribute("aria-labelledby") === buildHeading.id, "Firmware Build information heading must label its section");
    assert(
      buildHeading.textContent === "Build information" || buildHeading.textContent === "ビルド情報",
      "Firmware build section must expose the localized Build information heading",
    );
    assert(buildSection.contains(buildIdentity), "Firmware build identity rows must remain inside the Build information section");
    assert(shell.lastElementChild === buildSection, "Firmware Build information section must follow primary Flash/Update content");
    const beforeShell = shell.getBoundingClientRect();
    const beforeNav = nav.getBoundingClientRect();
    const beforeBuildSection = buildSection.getBoundingClientRect();

    frameWindow.__m5authFirmwareLayoutSmoke!.resume();
    await waitUntil(
      () => status.querySelectorAll("button").length === 2 && buildIdentity.textContent?.includes(FIRMWARE_SMOKE_BUILD_COMMIT) === true,
      "Production Firmware route did not reach the ready Flash/Update UI through pinned target resolution",
    );
    flushLayout(doc);

    assert(status.textContent?.includes("Firmware target unavailable") !== true, "Firmware layout smoke must exercise the successful target-resolution path");
    assert(status.querySelectorAll("button").length === 2, "Successful Firmware resolution must render First install and Update controls");
    assert(buildIdentity.textContent?.includes(FIRMWARE_SMOKE_BUILD_COMMIT) === true, "Successful Firmware resolution must display the pinned fixture build identity");

    const flashChoices = Array.from(status.querySelectorAll<HTMLElement>(":scope > section.panel"));
    assert(flashChoices.length === 2, "Firmware status must contain exactly First install and Update peer panels");
    const statusStyle = getComputedStyle(status);
    assert(
      statusStyle.borderTopStyle === "none" || parseFloat(statusStyle.borderTopWidth) === 0,
      "Firmware structural status container must not add a duplicate top divider",
    );
    const firstInstallStyle = getComputedStyle(flashChoices[0]!);
    const updateStyle = getComputedStyle(flashChoices[1]!);
    assert(
      firstInstallStyle.borderTopStyle !== "none" && parseFloat(firstInstallStyle.borderTopWidth) >= 1,
      "First install must have exactly one panel boundary supplied by its own section",
    );
    assert(
      updateStyle.borderTopStyle !== "none" && parseFloat(updateStyle.borderTopWidth) >= 1,
      "Update must retain exactly one panel boundary",
    );
    assert(parseFloat(firstInstallStyle.marginTop) === 0, "First install must not retain redundant nested-panel top spacing");
    assert(parseFloat(updateStyle.marginTop) > 0, "Update must remain visually separated from First install");
    assert(status.querySelector("hr") === null, "Firmware divider normalization must not introduce decorative hr elements");

    const afterShell = shell.getBoundingClientRect();
    const afterNav = nav.getBoundingClientRect();
    const afterBuildSection = buildSection.getBoundingClientRect();
    assert(getComputedStyle(doc.documentElement).scrollbarGutter.includes("stable"), "Firmware route must use the shared stable scrollbar policy");
    assert(near(beforeShell.left, afterShell.left) && near(beforeShell.width, afterShell.width), "Production Firmware shell geometry shifted after successful asynchronous target resolution");
    assert(near(beforeNav.left, afterNav.left) && near(beforeNav.width, afterNav.width), "Production Firmware top navigation geometry shifted after successful asynchronous target resolution");
    assert(
      near(beforeBuildSection.left, afterBuildSection.left) && near(beforeBuildSection.width, afterBuildSection.width),
      "Firmware Build information section shifted horizontally after asynchronous metadata resolution",
    );
  } finally {
    frame.remove();
  }
}

async function verifySharedRouteGeometryPolicy(): Promise<void> {
  const routes = ["index.html", "flash.html", "help.html"] as const;
  const frames: HTMLIFrameElement[] = [];
  try {
    for (const route of routes) frames.push(await loadRouteFrame(route, 6000));

    const geometries = frames.map((frame, index) => {
      const doc = requiredFrameDocument(frame);
      flushLayout(doc);
      assert(getComputedStyle(doc.documentElement).scrollbarGutter.includes("stable"), `${routes[index]} must use the shared stable scrollbar policy`);
      assert(doc.documentElement.scrollHeight <= requiredFrameWindow(frame).innerHeight, `${routes[index]} tall-viewport fixture must remain non-overflowing`);
      const nav = required<HTMLElement>(doc, ".site-nav-shell").getBoundingClientRect();
      const shell = required<HTMLElement>(doc, ".shell").getBoundingClientRect();
      return { nav, shell };
    });

    const provisioningDoc = requiredFrameDocument(frames[0]!);
    const provisioningShell = required<HTMLElement>(provisioningDoc, "#app > .shell");
    const productionBuildSection = required<HTMLElement>(provisioningDoc, "#web-build-info-section");
    const productionPanels = Array.from(provisioningShell.querySelectorAll<HTMLElement>(":scope > section.panel"));
    assert(productionPanels.length >= 7, "Production Provisioning route must keep all major peer sections on the shared panel contract");
    assert(provisioningShell.lastElementChild === productionBuildSection, "Production Web Build information section must remain the final Provisioning peer section");
    for (const [index, section] of productionPanels.entries()) {
      const style = getComputedStyle(section);
      assert(style.borderTopStyle !== "none" && parseFloat(style.borderTopWidth) >= 1, `Production Provisioning peer section ${index + 1} must retain a visible top divider`);
      assert(section.querySelector("h2") !== null, `Production Provisioning peer section ${index + 1} must retain a section heading`);
      assert(section.querySelector(":scope > hr") === null, `Production Provisioning peer section ${index + 1} must not duplicate the shared divider with an hr`);
    }

    const baseline = geometries[0]!;
    for (let index = 1; index < geometries.length; index += 1) {
      const current = geometries[index]!;
      assert(near(baseline.nav.left, current.nav.left) && near(baseline.nav.width, current.nav.width), `${routes[index]} top navigation must align with Provisioning on a non-overflowing desktop viewport`);
      assert(near(baseline.shell.left, current.shell.left) && near(baseline.shell.width, current.shell.width), `${routes[index]} content shell must align with Provisioning on a non-overflowing desktop viewport`);
    }
  } finally {
    for (const frame of frames) frame.remove();
  }
}

async function verifyStickyHeaderPolicy(): Promise<void> {
  const routes = ["index.html", "flash.html", "help.html"] as const;
  const frames: HTMLIFrameElement[] = [];
  try {
    for (const route of routes) frames.push(await loadRouteFrame(route, 360));

    for (let index = 0; index < frames.length; index += 1) {
      const frame = frames[index]!;
      const route = routes[index]!;
      const doc = requiredFrameDocument(frame);
      const win = requiredFrameWindow(frame);
      const header = required<HTMLElement>(doc, "#site-header");
      const nav = required<HTMLElement>(doc, ".site-nav-shell");
      const product = required<HTMLElement>(doc, ".product-mark");
      const tabs = required<HTMLElement>(doc, ".site-tabs");
      const language = required<HTMLElement>(doc, ".language-switcher");
      flushLayout(doc);

      const headerStyle = getComputedStyle(header);
      assert(headerStyle.position === "sticky", `${route} must use the shared sticky header contract`);
      assert(headerStyle.top === "0px", `${route} sticky header must pin to viewport top`);
      assert(Number.parseInt(headerStyle.zIndex, 10) > 0, `${route} sticky header needs positive stacking order`);
      assert(headerStyle.backgroundColor !== "rgba(0, 0, 0, 0)", `${route} sticky header background must be opaque/readable`);
      assert(header.contains(nav) && nav.contains(product) && nav.contains(tabs) && nav.contains(language), `${route} sticky header must retain product, tabs, and language switcher`);
      assert(doc.documentElement.scrollHeight > win.innerHeight, `${route} sticky-header fixture must be vertically scrollable`);

      const beforeNav = nav.getBoundingClientRect();
      const beforeShell = required<HTMLElement>(doc, ".shell").getBoundingClientRect();
      const beforeScrollWidth = doc.documentElement.scrollWidth;
      win.scrollTo(0, Math.min(480, doc.documentElement.scrollHeight - win.innerHeight));
      await new Promise<void>((resolve) => window.setTimeout(resolve, 20));
      flushLayout(doc);

      const afterHeader = header.getBoundingClientRect();
      const afterNav = nav.getBoundingClientRect();
      const afterShell = required<HTMLElement>(doc, ".shell").getBoundingClientRect();
      assert(near(afterHeader.top, 0), `${route} sticky header did not remain at viewport top while scrolling`);
      assert(near(beforeNav.left, afterNav.left) && near(beforeNav.width, afterNav.width), `${route} sticky navigation shifted horizontally while scrolling`);
      assert(near(beforeShell.left, afterShell.left) && near(beforeShell.width, afterShell.width), `${route} content shell shifted horizontally while scrolling`);
      assert(doc.documentElement.scrollWidth === beforeScrollWidth && doc.documentElement.scrollWidth <= win.innerWidth, `${route} sticky header introduced horizontal overflow or width jitter`);
    }

    const provisioningDoc = requiredFrameDocument(frames[0]!);
    const headerZ = Number.parseInt(getComputedStyle(required<HTMLElement>(provisioningDoc, "#site-header")).zIndex, 10);
    const presenceOverlay = required<HTMLElement>(provisioningDoc, ".presence-overlay");
    const overlayZ = Number.parseInt(getComputedStyle(presenceOverlay).zIndex, 10);
    assert(overlayZ > headerZ, "Security presence overlay must retain stacking priority over the sticky header");

    const responsiveFrame = await loadRouteFrame("help.html", 360, 540);
    frames.push(responsiveFrame);
    const responsiveDoc = requiredFrameDocument(responsiveFrame);
    const responsiveWin = requiredFrameWindow(responsiveFrame);
    flushLayout(responsiveDoc);
    const responsiveHeader = required<HTMLElement>(responsiveDoc, "#site-header");
    const responsiveNav = required<HTMLElement>(responsiveDoc, ".site-nav-shell");
    const responsiveTabs = required<HTMLElement>(responsiveDoc, ".site-tabs");
    const responsiveLanguage = required<HTMLElement>(responsiveDoc, ".language-switcher");
    const responsiveProduct = required<HTMLElement>(responsiveDoc, ".product-mark");
    assert(getComputedStyle(responsiveTabs).gridRowStart === "2", "Responsive top-level tabs must retain the shared second-row layout");
    for (const element of [responsiveProduct, responsiveTabs, responsiveLanguage]) {
      const rect = element.getBoundingClientRect();
      const headerRect = responsiveHeader.getBoundingClientRect();
      assert(rect.left >= headerRect.left - GEOMETRY_EPSILON_PX && rect.right <= headerRect.right + GEOMETRY_EPSILON_PX, "Responsive header controls must remain horizontally visible");
    }
    assert(responsiveDoc.documentElement.scrollWidth <= responsiveWin.innerWidth, "Responsive sticky header must not create a horizontal scrollbar");
    responsiveWin.scrollTo(0, 300);
    await new Promise<void>((resolve) => window.setTimeout(resolve, 20));
    assert(near(responsiveHeader.getBoundingClientRect().top, 0), "Responsive two-row header must remain sticky while scrolling");
    assert(responsiveNav.getBoundingClientRect().width > 0, "Responsive navigation must remain rendered after scrolling");
  } finally {
    for (const frame of frames) frame.remove();
  }
}

function createSnapshot(
  provisioned: boolean,
  factoryResetPresenceRequired = false,
  overrides: {
    state?: CanonicalDeviceSnapshot["hello"]["state"];
    ownership?: CanonicalDeviceSnapshot["browserOwnership"];
    readiness?: CanonicalDeviceSnapshot["time"]["readiness"];
  } = {},
): CanonicalDeviceSnapshot {
  const state = overrides.state ?? (provisioned ? "unlocked" : "unprovisioned");
  const ownership = overrides.ownership ?? (provisioned ? "active" : "none");
  const readiness = overrides.readiness ?? (provisioned ? "ready" : "not_synced");
  const ready = readiness === "ready";
  return {
    hello: {
      device: "M5StickS3",
      deviceId: "layout-smoke-device",
      firmware: "0.0.0-layout-smoke",
      protocol: 2,
      storageSchema: 2,
      vaultFormat: 2,
      supportedVaultFormats: [1, 2],
      buildCommit: "abcdef0123456789abcdef0123456789abcdef01",
      state,
      storageReady: true,
      recoveryResetRequired: false,
      factoryResetPresenceRequired,
      vaultPresent: provisioned,
      vaultId: provisioned ? new Uint8Array(16) : null,
      generation: provisioned ? 1n : 0n,
      registrationPresent: provisioned,
      registrationId: provisioned ? new Uint8Array(16) : null,
      registrationEpoch: provisioned ? 1 : 0,
      brkPublicKey: provisioned ? new Uint8Array(65) : null,
    },
    time: {
      readiness,
      source: ready ? "usb" : "none",
      sourceAuthenticity: ready ? "local_host_asserted" : "none",
      lastSyncUnixSeconds: ready ? 1n : 0n,
      ageSeconds: 0,
      resyncDue: readiness === "stale",
    },
    browserOwnership: ownership,
    unlockRequired: state === "locked" && ownership === "active",
    recoveryProvisioningAvailable: false,
    recoveryProvisioningCandidates: 0,
    accounts: [],
    wifi: { configured: false, ssid: "" },
    autoLock: { known: state === "unlocked" && ownership === "active", days: null, format2Writable: provisioned },
  };
}

async function loadRouteFrame(path: string, heightPx: number, widthPx = ROUTE_WIDTH_PX): Promise<HTMLIFrameElement> {
  const frame = document.createElement("iframe");
  frame.width = String(widthPx);
  frame.height = String(heightPx);
  frame.style.position = "fixed";
  frame.style.left = "-20000px";
  frame.style.top = "0";
  frame.style.border = "0";
  frame.src = new URL(path, new URL(import.meta.env.BASE_URL, window.location.origin)).toString();

  const loaded = new Promise<void>((resolve, reject) => {
    frame.addEventListener("load", () => resolve(), { once: true });
    frame.addEventListener("error", () => reject(new Error(`Failed to load production route ${path}`)), { once: true });
  });
  document.body.append(frame);
  await loaded;
  await waitUntil(
    () => frame.contentDocument?.querySelector(".shell") !== null && frame.contentDocument?.querySelector(".site-nav-shell") !== null,
    `Production route ${path} did not finish rendering its shared shell`,
  );
  return frame;
}

function required<T extends Element>(root: ParentNode, selector: string): T {
  const value = root.querySelector<T>(selector);
  if (!value) throw new Error(`Missing production layout element: ${selector}`);
  return value;
}

function requiredFrameDocument(frame: HTMLIFrameElement): Document {
  const doc = frame.contentDocument;
  if (!doc) throw new Error("Production route iframe document is unavailable");
  return doc;
}

function requiredFrameWindow(frame: HTMLIFrameElement): Window {
  const value = frame.contentWindow;
  if (!value) throw new Error("Production route iframe window is unavailable");
  return value;
}
