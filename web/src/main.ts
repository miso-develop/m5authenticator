import "./style.css";
import { decodeQrImage } from "./import/qr";
import { ImportSession, type ImportSessionUpdate } from "./import/session";
import { ImportError, type ImportedAccountPreview } from "./import/types";
import { DeviceManagement, type DeviceSnapshot } from "./management";
import { PRODUCTION_SECURITY_CONFIRMATION, type ProductionSecurityStatus } from "./protocol";
import { SerialSession } from "./serial";

const app = queryRequired<HTMLElement>("#app", "Application root is missing");

app.innerHTML = `
  <main class="shell">
    <p class="eyebrow">M5 Authenticator</p>
    <h1>Local provisioner</h1>
    <p class="description">All QR, secret, Wi-Fi, and device-management data stays between this browser and the connected M5StickS3.</p>

    <section class="panel" aria-labelledby="device-heading">
      <div class="panel-heading"><h2 id="device-heading">Device</h2><span id="connection-state" class="badge">Disconnected</span></div>
      <div class="actions">
        <button id="connect" type="button">Connect M5StickS3</button>
        <button id="disconnect" class="secondary" type="button" disabled>Disconnect</button>
        <button id="refresh-device" class="secondary" type="button" disabled>Refresh status</button>
        <button id="sync-time" class="secondary" type="button" disabled>Sync PC time</button>
      </div>
      <dl id="device-status" class="status" aria-live="polite"></dl>
      <p id="device-notice" class="notice" aria-live="polite"></p>
    </section>

    <section id="production-security" class="panel danger" aria-labelledby="production-security-heading" hidden>
      <h2 id="production-security-heading">Production Security Initialization</h2>
      <p class="hint"><strong>Irreversible.</strong> This can permanently program one device-specific HMAC key into eFuse and erases existing development auth_nvs data. It never exports the key.</p>
      <dl id="production-security-status" class="status" aria-live="polite"></dl>
      <div class="actions">
        <button id="prepare-security" type="button" disabled>Run non-destructive preflight</button>
        <button id="cancel-security" class="secondary" type="button" disabled>Cancel preparation</button>
      </div>
      <label for="security-confirmation">After preflight, type ${PRODUCTION_SECURITY_CONFIRMATION}</label>
      <input id="security-confirmation" type="text" autocomplete="off" spellcheck="false" disabled />
      <button id="initialize-security" class="danger-button" type="button" disabled>Initialize Production Security</button>
      <p class="hint">After clicking Initialize, the StickS3 itself will display a second irreversible-operation warning. Long-hold the physical button only after verifying the device message.</p>
    </section>

    <section class="panel" aria-labelledby="import-heading">
      <h2 id="import-heading">Import accounts</h2>
      <p class="hint">Supports standard TOTP QR codes and Google Authenticator exports. Images and secrets are not uploaded or persisted.</p>
      <label class="file-label" for="qr-file">QR screenshot image</label>
      <input id="qr-file" type="file" accept="image/*" />
      <p id="import-status" class="notice" aria-live="polite">No accounts imported.</p>
      <ol id="import-account-list" class="account-list"></ol>
      <div class="actions">
        <button id="provision-import" type="button" disabled>Provision imported accounts</button>
        <button id="clear-import" class="secondary" type="button" disabled>Clear import session</button>
      </div>
    </section>

    <section class="panel" aria-labelledby="accounts-heading">
      <h2 id="accounts-heading">Stored accounts</h2>
      <p class="hint">Only non-secret account metadata is read from the device.</p>
      <ol id="stored-account-list" class="account-list"></ol>
      <p id="accounts-empty" class="notice">Connect a device to manage stored accounts.</p>
    </section>

    <section class="panel" aria-labelledby="wifi-heading">
      <h2 id="wifi-heading">Wi-Fi for NTP</h2>
      <p id="wifi-status" class="notice">Connect a device to view Wi-Fi status.</p>
      <form id="wifi-form" autocomplete="off">
        <label for="wifi-ssid">SSID</label>
        <input id="wifi-ssid" name="ssid" type="text" maxlength="32" autocomplete="off" disabled required />
        <label for="wifi-password">Password</label>
        <input id="wifi-password" name="password" type="password" maxlength="64" autocomplete="new-password" disabled required />
        <div class="actions">
          <button id="save-wifi" type="submit" disabled>Save Wi-Fi</button>
          <button id="clear-wifi" class="secondary" type="button" disabled>Clear Wi-Fi</button>
        </div>
      </form>
    </section>

    <section class="panel danger" aria-labelledby="reset-heading">
      <h2 id="reset-heading">Factory Reset</h2>
      <p class="hint">Deletes accounts, TOTP secrets, Wi-Fi credentials, and user settings from auth_nvs. It does not erase device eFuse security material.</p>
      <label for="reset-confirmation">Type RESET to enable</label>
      <input id="reset-confirmation" type="text" autocomplete="off" disabled />
      <button id="factory-reset" class="danger-button" type="button" disabled>Factory Reset</button>
    </section>
  </main>
`;

const connectButton = queryRequired<HTMLButtonElement>("#connect", "Connect button is missing");
const disconnectButton = queryRequired<HTMLButtonElement>("#disconnect", "Disconnect button is missing");
const refreshButton = queryRequired<HTMLButtonElement>("#refresh-device", "Refresh button is missing");
const syncTimeButton = queryRequired<HTMLButtonElement>("#sync-time", "Time sync button is missing");
const connectionState = queryRequired<HTMLElement>("#connection-state", "Connection state is missing");
const deviceStatus = queryRequired<HTMLDListElement>("#device-status", "Device status is missing");
const deviceNotice = queryRequired<HTMLElement>("#device-notice", "Device notice is missing");
const productionSecuritySection = queryRequired<HTMLElement>("#production-security", "Production security section is missing");
const productionSecurityStatus = queryRequired<HTMLDListElement>("#production-security-status", "Production security status is missing");
const prepareSecurityButton = queryRequired<HTMLButtonElement>("#prepare-security", "Security preflight button is missing");
const cancelSecurityButton = queryRequired<HTMLButtonElement>("#cancel-security", "Security cancel button is missing");
const securityConfirmation = queryRequired<HTMLInputElement>("#security-confirmation", "Security confirmation input is missing");
const initializeSecurityButton = queryRequired<HTMLButtonElement>("#initialize-security", "Security initialize button is missing");
const qrFileInput = queryRequired<HTMLInputElement>("#qr-file", "QR file input is missing");
const importStatus = queryRequired<HTMLElement>("#import-status", "Import status is missing");
const importAccountList = queryRequired<HTMLOListElement>("#import-account-list", "Import list is missing");
const provisionButton = queryRequired<HTMLButtonElement>("#provision-import", "Provision button is missing");
const clearImportButton = queryRequired<HTMLButtonElement>("#clear-import", "Import clear button is missing");
const storedAccountList = queryRequired<HTMLOListElement>("#stored-account-list", "Stored account list is missing");
const accountsEmpty = queryRequired<HTMLElement>("#accounts-empty", "Stored account empty state is missing");
const wifiForm = queryRequired<HTMLFormElement>("#wifi-form", "Wi-Fi form is missing");
const wifiSsid = queryRequired<HTMLInputElement>("#wifi-ssid", "Wi-Fi SSID input is missing");
const wifiPassword = queryRequired<HTMLInputElement>("#wifi-password", "Wi-Fi password input is missing");
const saveWifiButton = queryRequired<HTMLButtonElement>("#save-wifi", "Wi-Fi save button is missing");
const clearWifiButton = queryRequired<HTMLButtonElement>("#clear-wifi", "Wi-Fi clear button is missing");
const wifiStatus = queryRequired<HTMLElement>("#wifi-status", "Wi-Fi status is missing");
const resetConfirmation = queryRequired<HTMLInputElement>("#reset-confirmation", "Reset confirmation is missing");
const factoryResetButton = queryRequired<HTMLButtonElement>("#factory-reset", "Factory reset button is missing");

const importSession = new ImportSession();
let serialSession: SerialSession | null = null;
let management: DeviceManagement | null = null;
let snapshot: DeviceSnapshot | null = null;
let deviceActionInProgress = false;

renderDevice();
renderImportedAccounts([]);

qrFileInput.addEventListener("change", async () => {
  const file = qrFileInput.files?.[0];
  if (!file) return;
  qrFileInput.disabled = true;
  importStatus.textContent = "Decoding QR image locally…";
  try {
    const decodedText = await decodeQrImage(file);
    renderImportUpdate(importSession.importDecodedText(decodedText));
  } catch (error) {
    importStatus.textContent = error instanceof ImportError ? error.message : "QR import failed.";
    renderImportedAccounts(importSession.preview());
  } finally {
    qrFileInput.value = "";
    qrFileInput.disabled = false;
    updateControls();
  }
});

clearImportButton.addEventListener("click", () => {
  importSession.clear();
  renderImportedAccounts([]);
  importStatus.textContent = "Import session cleared.";
  updateControls();
});

connectButton.addEventListener("click", async () => {
  if (deviceActionInProgress || management) return;
  setDeviceBusy(true, "Connecting…");
  try {
    const connected = await SerialSession.connect();
    serialSession = connected.session;
    management = new DeviceManagement(connected.session);
    deviceNotice.textContent = "Compatible protocol v1 device connected.";
    await refreshDevice();
  } catch (error) {
    const message = userFacingError(error, "Connection failed.");
    await disconnectDevice();
    deviceNotice.textContent = message;
  } finally {
    setDeviceBusy(false);
  }
});

disconnectButton.addEventListener("click", async () => {
  setDeviceBusy(true, "Disconnecting…");
  await disconnectDevice();
  deviceNotice.textContent = "Device disconnected.";
  setDeviceBusy(false);
});

refreshButton.addEventListener("click", () => runDeviceAction("Refreshing device…", refreshDevice));
syncTimeButton.addEventListener("click", () => runDeviceAction("Synchronizing PC time…", async () => {
  await requireManagement().syncTime();
  deviceNotice.textContent = "Trusted time synchronized from this PC.";
  await refreshDevice();
}));

prepareSecurityButton.addEventListener("click", () => runDeviceAction("Running non-destructive production-security preflight…", async () => {
  const security = await requireManagement().prepareProductionSecurity();
  updateSecuritySnapshot(security);
  deviceNotice.textContent = "Preflight prepared. Verify the status below, type the exact confirmation text, then initialize. No eFuse change has occurred.";
}));

cancelSecurityButton.addEventListener("click", () => runDeviceAction("Cancelling production-security preparation…", async () => {
  const security = await requireManagement().cancelProductionSecurity();
  securityConfirmation.value = "";
  updateSecuritySnapshot(security);
  deviceNotice.textContent = "Production-security preparation cancelled. No eFuse change was requested.";
}));

securityConfirmation.addEventListener("input", updateControls);
initializeSecurityButton.addEventListener("click", () => {
  if (securityConfirmation.value !== PRODUCTION_SECURITY_CONFIRMATION) return;
  if (!window.confirm("This operation can permanently program a device-specific HMAC key into eFuse and erases existing development authenticator data. Continue to the physical StickS3 confirmation?")) return;
  void runDeviceAction("Confirm on the StickS3 now: long-hold its physical button only if the on-device irreversible eFuse warning is correct.", async () => {
    await requireManagement().initializeProductionSecurity(securityConfirmation.value);
    securityConfirmation.value = "";
    await disconnectDevice();
    deviceNotice.textContent = "Production security initialized. The device is continuing normal startup; reconnect after startup completes.";
  });
});

provisionButton.addEventListener("click", () => runDeviceAction("Provisioning imported accounts…", async () => {
  const count = await requireManagement().provision(importSession);
  importSession.clear();
  renderImportedAccounts([]);
  importStatus.textContent = `${count} account${count === 1 ? "" : "s"} provisioned. Import secrets cleared from the browser session.`;
  await refreshDevice();
}));

wifiForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const ssid = wifiSsid.value;
  const password = wifiPassword.value;
  wifiPassword.value = "";
  void runDeviceAction("Saving Wi-Fi settings…", async () => {
    await requireManagement().setWifi(ssid, password);
    deviceNotice.textContent = "Wi-Fi settings saved to encrypted device storage.";
    await refreshDevice();
  });
});

clearWifiButton.addEventListener("click", () => runDeviceAction("Clearing Wi-Fi settings…", async () => {
  await requireManagement().clearWifi();
  wifiPassword.value = "";
  deviceNotice.textContent = "Wi-Fi settings cleared.";
  await refreshDevice();
}));

resetConfirmation.addEventListener("input", updateControls);
factoryResetButton.addEventListener("click", () => {
  if (resetConfirmation.value !== "RESET") return;
  if (!window.confirm("Factory Reset will permanently delete all user accounts, TOTP secrets, Wi-Fi credentials, and settings from this device. Continue?")) return;
  void runDeviceAction("Factory Reset in progress…", async () => {
    await requireManagement().factoryReset();
    resetConfirmation.value = "";
    wifiPassword.value = "";
    deviceNotice.textContent = "Factory Reset completed. Device user state was erased; eFuse security material was not modified.";
    await refreshDevice();
  });
});

window.addEventListener("pagehide", () => {
  importSession.clear();
  wifiPassword.value = "";
  securityConfirmation.value = "";
  if (management) void management.close();
});

async function refreshDevice(): Promise<void> {
  snapshot = await requireManagement().refresh();
  renderDevice();
}

async function disconnectDevice(): Promise<void> {
  const current = management;
  management = null;
  serialSession = null;
  snapshot = null;
  wifiPassword.value = "";
  securityConfirmation.value = "";
  if (current) {
    try {
      await current.close();
    } catch {
      // Disconnect cleanup must not expose transport internals or sensitive request state.
    }
  }
  renderDevice();
}

async function runDeviceAction(message: string, action: () => Promise<void>): Promise<void> {
  if (deviceActionInProgress || !management) return;
  setDeviceBusy(true, message);
  try {
    await action();
  } catch (error) {
    const errorMessage = userFacingError(error, "Device operation failed.");
    if (serialSession?.isClosed()) await disconnectDevice();
    deviceNotice.textContent = errorMessage;
  } finally {
    setDeviceBusy(false);
  }
}

function setDeviceBusy(busy: boolean, message?: string): void {
  deviceActionInProgress = busy;
  if (message) deviceNotice.textContent = message;
  updateControls();
}

function updateControls(): void {
  const connected = management !== null;
  const storageReady = snapshot?.hello.storage_ready === true;
  const security = snapshot?.security ?? null;
  connectButton.disabled = deviceActionInProgress || connected;
  disconnectButton.disabled = deviceActionInProgress || !connected;
  refreshButton.disabled = deviceActionInProgress || !connected;
  syncTimeButton.disabled = deviceActionInProgress || !connected || !storageReady;
  provisionButton.disabled = deviceActionInProgress || !connected || !storageReady || !importSession.hasCompleteAccounts();
  clearImportButton.disabled = !importSession.hasSensitiveState();
  wifiSsid.disabled = deviceActionInProgress || !connected || !storageReady;
  wifiPassword.disabled = deviceActionInProgress || !connected || !storageReady;
  saveWifiButton.disabled = deviceActionInProgress || !connected || !storageReady;
  clearWifiButton.disabled = deviceActionInProgress || !connected || !storageReady || snapshot?.wifi.configured !== true;
  resetConfirmation.disabled = deviceActionInProgress || !connected || !storageReady;
  factoryResetButton.disabled = deviceActionInProgress || !connected || !storageReady || resetConfirmation.value !== "RESET";

  prepareSecurityButton.disabled = deviceActionInProgress || !connected || security === null || !security.preflight_ok || security.prepared;
  cancelSecurityButton.disabled = deviceActionInProgress || !connected || security === null || !security.prepared;
  securityConfirmation.disabled = deviceActionInProgress || !connected || security === null || !security.prepared;
  initializeSecurityButton.disabled = deviceActionInProgress || !connected || security === null || !security.prepared || securityConfirmation.value !== PRODUCTION_SECURITY_CONFIRMATION;
}

function renderDevice(): void {
  const connected = management !== null;
  connectionState.textContent = connected ? "Connected" : "Disconnected";
  deviceStatus.replaceChildren();

  if (!snapshot) {
    appendStatus("Status", connected ? "Connected; status not loaded" : "Not connected");
    productionSecuritySection.hidden = true;
    productionSecurityStatus.replaceChildren();
    storedAccountList.replaceChildren();
    accountsEmpty.textContent = connected ? "Refresh device status to load accounts." : "Connect a device to manage stored accounts.";
    wifiStatus.textContent = connected ? "Refresh device status to load Wi-Fi status." : "Connect a device to view Wi-Fi status.";
    wifiSsid.value = "";
    updateControls();
    return;
  }

  const hello = snapshot.hello;
  appendStatus("Device", hello.device);
  appendStatus("Firmware", hello.firmware);
  appendStatus("Protocol", String(hello.protocol));
  appendStatus("Storage schema", String(hello.storage_schema));
  appendStatus("Build", hello.build_commit);
  appendStatus("Security profile", hello.security_profile);
  appendStatus("Storage", hello.storage_ready ? "Ready" : (hello.storage_status ?? "Unavailable"));
  appendStatus("Production backend", hello.production_release_allowed ? "Yes" : "No");
  appendStatus("Time", `${hello.time_state} (${hello.time_source})`);
  appendStatus("Accounts", String(snapshot.accounts.length));

  renderProductionSecurity(snapshot.security);
  renderStoredAccounts(snapshot.accounts);
  wifiStatus.textContent = hello.storage_ready
    ? (snapshot.wifi.configured ? `Configured SSID: ${snapshot.wifi.ssid}` : "Wi-Fi is not configured.")
    : "Storage management is blocked until Production Security Initialization completes.";
  wifiSsid.value = hello.storage_ready ? snapshot.wifi.ssid : "";
  updateControls();
}

function renderProductionSecurity(security: ProductionSecurityStatus | null): void {
  productionSecuritySection.hidden = security === null;
  productionSecurityStatus.replaceChildren();
  if (!security) return;
  appendDefinition(productionSecurityStatus, "Configured HMAC slot", `KEY${security.hmac_key_id}`);
  appendDefinition(productionSecurityStatus, "Key state", security.key_state);
  appendDefinition(productionSecurityStatus, "Read protected", security.read_protected ? "Yes" : "No");
  appendDefinition(productionSecurityStatus, "Key write protected", security.write_protected ? "Yes" : "No");
  appendDefinition(productionSecurityStatus, "Purpose write protected", security.purpose_write_protected ? "Yes" : "No");
  appendDefinition(productionSecurityStatus, "Unused key blocks", String(security.unused_key_blocks));
  appendDefinition(productionSecurityStatus, "Burn attempted this boot", security.burn_attempted ? "Yes — do not retry" : "No");
  appendDefinition(productionSecurityStatus, "Preflight", security.preflight_ok ? "Eligible" : "Blocked");
  appendDefinition(productionSecurityStatus, "Prepared", security.prepared ? "Yes" : "No");
}

function updateSecuritySnapshot(security: ProductionSecurityStatus): void {
  if (!snapshot) return;
  snapshot = { ...snapshot, security };
  renderDevice();
}

function renderStoredAccounts(accounts: DeviceSnapshot["accounts"]): void {
  storedAccountList.replaceChildren();
  accountsEmpty.textContent = accounts.length === 0 ? "No accounts stored on the device." : "";

  accounts.forEach((account, index) => {
    const item = document.createElement("li");
    item.className = "managed-account";
    const identity = document.createElement("strong");
    identity.textContent = account.issuer ? `${account.issuer} — ${account.account}` : account.account;
    const input = document.createElement("input");
    input.type = "text";
    input.maxLength = 96;
    input.value = account.display_name;
    input.setAttribute("aria-label", `Display name for ${account.account}`);

    const actions = document.createElement("div");
    actions.className = "actions compact";
    const rename = actionButton("Rename", () => runDeviceAction("Renaming account…", async () => {
      await requireManagement().renameAccount(account.id, input.value);
      await refreshDevice();
    }));
    const up = actionButton("↑", () => reorderStoredAccount(index, -1));
    const down = actionButton("↓", () => reorderStoredAccount(index, 1));
    const remove = actionButton("Delete", () => {
      if (!window.confirm(`Delete ${account.account} from the device?`)) return Promise.resolve();
      return runDeviceAction("Deleting account…", async () => {
        await requireManagement().deleteAccount(account.id);
        await refreshDevice();
      });
    });
    up.disabled = index === 0;
    down.disabled = index === accounts.length - 1;
    actions.append(rename, up, down, remove);
    item.append(identity, input, actions);
    storedAccountList.append(item);
  });
}

async function reorderStoredAccount(index: number, offset: -1 | 1): Promise<void> {
  if (!snapshot) return;
  const target = index + offset;
  if (target < 0 || target >= snapshot.accounts.length) return;
  const ids = snapshot.accounts.map((account) => account.id);
  [ids[index], ids[target]] = [ids[target]!, ids[index]!];
  await runDeviceAction("Reordering accounts…", async () => {
    await requireManagement().reorderAccounts(ids);
    await refreshDevice();
  });
}

function actionButton(label: string, action: () => Promise<void>): HTMLButtonElement {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "secondary small";
  button.textContent = label;
  button.addEventListener("click", () => void action());
  return button;
}

function appendStatus(label: string, value: string): void {
  appendDefinition(deviceStatus, label, value);
}

function appendDefinition(list: HTMLDListElement, label: string, value: string): void {
  const row = document.createElement("div");
  const term = document.createElement("dt");
  const description = document.createElement("dd");
  term.textContent = label;
  description.textContent = value;
  row.append(term, description);
  list.append(row);
}

function renderImportUpdate(update: ImportSessionUpdate): void {
  renderImportedAccounts(update.accounts);
  if (update.batch) {
    importStatus.textContent = `Google Authenticator export: ${update.batch.received} of ${update.batch.total} QR codes received.`;
  } else {
    importStatus.textContent = `${update.accounts.length} account${update.accounts.length === 1 ? "" : "s"} ready for review.`;
  }
  updateControls();
}

function renderImportedAccounts(accounts: ImportedAccountPreview[]): void {
  importAccountList.replaceChildren();
  for (const account of accounts) {
    const item = document.createElement("li");
    const title = document.createElement("strong");
    const details = document.createElement("span");
    title.textContent = account.issuer ? `${account.issuer} — ${account.account}` : account.account;
    details.textContent = `${account.algorithm} · ${account.digits} digits · ${account.period}s`;
    item.append(title, details);
    importAccountList.append(item);
  }
}

function requireManagement(): DeviceManagement {
  if (!management) throw new Error("Device is not connected");
  return management;
}

function userFacingError(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.length > 0) return error.message;
  return fallback;
}

function queryRequired<T extends Element>(selector: string, message: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error(message);
  return element;
}
