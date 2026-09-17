import "../../src/style.css";
import "../../src/post-provisioning-layout.css";
import { CanonicalDeviceManagement, type CanonicalDeviceSnapshot } from "../../src/canonical-management";
import { SerialSession } from "../../src/serial";
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

  SerialSession.connect = async () => ({
    session: {} as SerialSession,
    hello: currentSnapshot.hello,
  });
  CanonicalDeviceManagement.prototype.initialize = async function (): Promise<void> {};
  CanonicalDeviceManagement.prototype.refresh = async function (): Promise<CanonicalDeviceSnapshot> {
    return currentSnapshot;
  };

  try {
    await import("../../src/main");

    const connect = required<HTMLButtonElement>(document, "#connect");
    const refresh = required<HTMLButtonElement>(document, "#refresh-device");
    const connectionState = required<HTMLElement>(document, "#connection-state");
    const deviceStatus = required<HTMLElement>(document, "#device-status");
    const fields = required<HTMLElement>(document, "#initial-passphrase-fields");
    const passphrase = required<HTMLInputElement>(document, "#initial-recovery-passphrase");
    const passphraseConfirm = required<HTMLInputElement>(document, "#initial-recovery-passphrase-confirm");
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

    currentSnapshot = createSnapshot(true);
    refresh.click();
    await waitUntil(
      () => deviceStatus.textContent?.includes("unlocked") === true && passphrase.disabled,
      "Production Provisioning route did not reach the provisioned snapshot state",
    );
    flushLayout();
    assert(passphrase.disabled && passphraseConfirm.disabled, "Provisioned management UI must make initial Recovery Passphrase inputs inactive");
    assert(getComputedStyle(fields).display === "none", "Provisioned management UI must hide the non-actionable initial Recovery Passphrase block");

    const firstStyle = getComputedStyle(panels[0]!);
    const secondStyle = getComputedStyle(panels[1]!);
    assert(parseFloat(firstStyle.marginTop) < 32, "First Provisioning section must not gain the large subsequent-section margin");
    assert(parseFloat(secondStyle.marginTop) >= 32, "Subsequent Provisioning sections require at least 32px top separation");
    assert(parseFloat(secondStyle.paddingTop) >= 32, "Subsequent Provisioning headings require at least 32px boundary padding");

    installWebBuildInfo(shell);
    flushLayout();
    assert(shell.lastElementChild?.id === "web-build-identity", "Web build provenance must follow primary Provisioning content");
  } finally {
    SerialSession.connect = originalConnect;
    CanonicalDeviceManagement.prototype.initialize = originalInitialize;
    CanonicalDeviceManagement.prototype.refresh = originalRefresh;
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
    const buildIdentity = required<HTMLElement>(doc, "#firmware-build-identity");
    flushLayout(doc);

    assert(status.textContent?.includes("Loading and validating pinned firmware target") === true, "Production Firmware route must be measured while actual target resolution is pending");
    assert(shell.lastElementChild === buildIdentity, "Firmware build provenance must follow primary Flash/Update content");
    const beforeShell = shell.getBoundingClientRect();
    const beforeNav = nav.getBoundingClientRect();

    frameWindow.__m5authFirmwareLayoutSmoke!.resume();
    await waitUntil(
      () => status.querySelectorAll("button").length === 2 && buildIdentity.textContent?.includes(FIRMWARE_SMOKE_BUILD_COMMIT) === true,
      "Production Firmware route did not reach the ready Flash/Update UI through pinned target resolution",
    );
    flushLayout(doc);

    assert(status.textContent?.includes("Firmware target unavailable") !== true, "Firmware layout smoke must exercise the successful target-resolution path");
    assert(status.querySelectorAll("button").length === 2, "Successful Firmware resolution must render First install and Update controls");
    assert(buildIdentity.textContent?.includes(FIRMWARE_SMOKE_BUILD_COMMIT) === true, "Successful Firmware resolution must display the pinned fixture build identity");

    const afterShell = shell.getBoundingClientRect();
    const afterNav = nav.getBoundingClientRect();
    assert(getComputedStyle(doc.documentElement).scrollbarGutter.includes("stable"), "Firmware route must use the shared stable scrollbar policy");
    assert(near(beforeShell.left, afterShell.left) && near(beforeShell.width, afterShell.width), "Production Firmware shell geometry shifted after successful asynchronous target resolution");
    assert(near(beforeNav.left, afterNav.left) && near(beforeNav.width, afterNav.width), "Production Firmware top navigation geometry shifted after successful asynchronous target resolution");
  } finally {
    frame.remove();
  }
}

async function verifySharedRouteGeometryPolicy(): Promise<void> {
  const routes = ["index.html", "flash.html", "help.html"] as const;
  const frames: HTMLIFrameElement[] = [];
  try {
    for (const route of routes) frames.push(await loadRouteFrame(route, 5000));

    const geometries = frames.map((frame, index) => {
      const doc = requiredFrameDocument(frame);
      flushLayout(doc);
      assert(getComputedStyle(doc.documentElement).scrollbarGutter.includes("stable"), `${routes[index]} must use the shared stable scrollbar policy`);
      assert(doc.documentElement.scrollHeight <= requiredFrameWindow(frame).innerHeight, `${routes[index]} tall-viewport fixture must remain non-overflowing`);
      const nav = required<HTMLElement>(doc, ".site-nav-shell").getBoundingClientRect();
      const shell = required<HTMLElement>(doc, ".shell").getBoundingClientRect();
      return { nav, shell };
    });

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

function createSnapshot(provisioned: boolean): CanonicalDeviceSnapshot {
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
      state: provisioned ? "unlocked" : "unprovisioned",
      storageReady: true,
      recoveryResetRequired: false,
      vaultPresent: provisioned,
      vaultId: provisioned ? new Uint8Array(16) : null,
      generation: provisioned ? 1n : 0n,
      registrationPresent: provisioned,
      registrationId: provisioned ? new Uint8Array(16) : null,
      registrationEpoch: provisioned ? 1 : 0,
      brkPublicKey: provisioned ? new Uint8Array(65) : null,
    },
    time: {
      readiness: provisioned ? "ready" : "not_synced",
      source: provisioned ? "usb" : "none",
      lastSyncUnixSeconds: provisioned ? 1n : 0n,
      ageSeconds: 0,
      resyncDue: false,
    },
    browserOwnership: provisioned ? "active" : "none",
    unlockRequired: false,
    recoveryProvisioningAvailable: false,
    recoveryProvisioningCandidates: 0,
    accounts: [],
    wifi: { configured: false, ssid: "" },
    autoLock: { known: provisioned, days: null, format2Writable: provisioned },
  };
}

async function loadRouteFrame(path: string, heightPx: number): Promise<HTMLIFrameElement> {
  const frame = document.createElement("iframe");
  frame.width = String(ROUTE_WIDTH_PX);
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
