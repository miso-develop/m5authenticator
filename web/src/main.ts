import "./style.css";
import { decodeQrImage } from "./import/qr";
import { ImportSession, type ImportSessionUpdate } from "./import/session";
import { ImportError, type ImportedAccountPreview } from "./import/types";
import { DeviceManagement, type DeviceSnapshot } from "./management";
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
  connectButton.disabled = deviceActionInProgress || connected;
  disconnectButton.disabled = deviceActionInProgress || !connected;
  refreshButton.disabled = deviceActionInProgress || !connected;
  syncTimeButton.disabled = deviceActionInProgress || !connected;
  provisionButton.disabled = deviceActionInProgress || !connected || !importSession.hasCompleteAccounts();
  clearImportButton.disabled = !importSession.hasSensitiveState();
  wifiSsid.disabled = deviceActionInProgress || !connected;
  wifiPassword.disabled = deviceActionInProgress || !connected;
  saveWifiButton.disabled = deviceActionInProgress || !connected;
  clearWifiButton.disabled = deviceActionInProgress || !connected || snapshot?.wifi.configured !== true;
  resetConfirmation.disabled = deviceActionInProgress || !connected;
  factoryResetButton.disabled = deviceActionInProgress || !connected || resetConfirmation.value !== "RESET";
}

function renderDevice(): void {
  const connected = management !== null;
  connectionState.textContent = connected ? "Connected" : "Disconnected";
  deviceStatus.replaceChildren();

  if (!snapshot) {
    appendStatus("Status", connected ? "Connected; status not loaded" : "Not connected");
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
  appendStatus("Production eligible", hello.production_release_allowed ? "Yes" : "No");
  appendStatus("Time", `${hello.time_state} (${hello.time_source})`);
  appendStatus("Accounts", String(snapshot.accounts.length));

  renderStoredAccounts(snapshot.accounts);
  wifiStatus.textContent = snapshot.wifi.configured ? `Configured SSID: ${snapshot.wifi.ssid}` : "Wi-Fi is not configured.";
  wifiSsid.value = snapshot.wifi.ssid;
  updateControls();
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
  const row = document.createElement("div");
  const term = document.createElement("dt");
  const description = document.createElement("dd");
  term.textContent = label;
  description.textContent = value;
  row.append(term, description);
  deviceStatus.append(row);
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
