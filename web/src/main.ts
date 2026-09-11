import "./style.css";
import { CanonicalDeviceManagement, type CanonicalDeviceSnapshot } from "./canonical-management";
import { decodeQrImage } from "./import/qr";
import { ImportSession, type ImportSessionUpdate } from "./import/session";
import { ImportError, type ImportedAccountPreview } from "./import/types";
import { SerialSession } from "./serial";

const app = queryRequired<HTMLElement>("#app", "Application root is missing");

app.innerHTML = `
  <main class="shell">
    <p class="eyebrow">M5 Authenticator</p>
    <h1>Local canonical Vault manager</h1>
    <p class="description">All QR, secret, Wi-Fi, recovery, and device-management data stays between this browser and the connected M5StickS3. Protocol 2 writes only authenticated encrypted Vault generations to the Device.</p>

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
      <p class="hint">Supports standard TOTP QR codes and Google Authenticator exports. Images and secrets are processed locally and are cleared from the import session after a successful canonical Vault update.</p>
      <label class="file-label" for="qr-file">QR screenshot image</label>
      <input id="qr-file" type="file" accept="image/*" />
      <p id="import-status" class="notice" aria-live="polite">No accounts imported.</p>
      <ol id="import-account-list" class="account-list"></ol>
      <div id="initial-passphrase-fields">
        <p class="hint">Initial provisioning only: choose a Recovery Passphrase (15–128 Unicode code points). It is used to wrap the VMK for Recovery Package use and is never sent to the Device.</p>
        <label for="initial-recovery-passphrase">Recovery Passphrase</label>
        <input id="initial-recovery-passphrase" type="password" autocomplete="new-password" />
        <label for="initial-recovery-passphrase-confirm">Confirm Recovery Passphrase</label>
        <input id="initial-recovery-passphrase-confirm" type="password" autocomplete="new-password" />
      </div>
      <div class="actions">
        <button id="provision-import" type="button" disabled>Apply imported accounts</button>
        <button id="clear-import" class="secondary" type="button" disabled>Clear import session</button>
      </div>
    </section>

    <section class="panel" aria-labelledby="accounts-heading">
      <h2 id="accounts-heading">Canonical accounts</h2>
      <p class="hint">Account metadata is decrypted from this Trusted Browser's canonical Vault. TOTP secrets remain inside transient Vault plaintext and are never returned by Device status.</p>
      <ol id="stored-account-list" class="account-list"></ol>
      <p id="accounts-empty" class="notice">Connect a device to load canonical Vault state.</p>
    </section>

    <section class="panel" aria-labelledby="wifi-heading">
      <h2 id="wifi-heading">Wi-Fi for NTP</h2>
      <p id="wifi-status" class="notice">Connect and unlock a Trusted Browser to view Wi-Fi status.</p>
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
      <p class="hint">Deletes the encrypted canonical Vault and active Trusted Browser registration from the Device and removes this browser's matching canonical state. The stable non-secret Device ID is preserved.</p>
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
const initialPassphrase = queryRequired<HTMLInputElement>("#initial-recovery-passphrase", "Initial Recovery Passphrase is missing");
const initialPassphraseConfirm = queryRequired<HTMLInputElement>("#initial-recovery-passphrase-confirm", "Initial Recovery Passphrase confirmation is missing");
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
let management: CanonicalDeviceManagement | null = null;
let snapshot: CanonicalDeviceSnapshot | null = null;
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
  clearInitialPassphrase();
  importStatus.textContent = "Import session cleared.";
  updateControls();
});

connectButton.addEventListener("click", async () => {
  if (deviceActionInProgress || management) return;
  setDeviceBusy(true, "Connecting…");
  try {
    const connected = await SerialSession.connect();
    serialSession = connected.session;
    management = new CanonicalDeviceManagement(connected.session, connected.hello);
    deviceNotice.textContent = connected.hello.vaultPresent
      ? "Canonical Device found. Confirm the Trusted Browser request on M5StickS3 if prompted."
      : "Unprovisioned canonical Protocol 2 Device connected.";
    await management.initialize();
    await refreshDevice();
    if (snapshot?.browserOwnership === "conflict") {
      deviceNotice.textContent = "This browser is not the active Device writer. Import a Recovery Package for explicit Browser replacement, then reconnect.";
    } else if (snapshot?.hello.state === "unlocked") {
      deviceNotice.textContent = "Trusted Browser active; Device is UNLOCKED for this USB session.";
    }
  } catch (error) {
    const message = userFacingError(error, "Connection failed.");
    await disconnectDevice();
    deviceNotice.textContent = message;
  } finally {
    setDeviceBusy(false);
  }
});

disconnectButton.addEventListener("click", async () => {
  setDeviceBusy(true, "Locking and disconnecting…");
  await disconnectDevice();
  deviceNotice.textContent = "Device locked and disconnected.";
  setDeviceBusy(false);
});

refreshButton.addEventListener("click", () => runDeviceAction("Refreshing canonical status…", refreshDevice));
syncTimeButton.addEventListener("click", () => runDeviceAction("Synchronizing PC time…", async () => {
  await requireManagement().syncTime();
  deviceNotice.textContent = "Trusted time synchronized from this PC while Device was UNLOCKED.";
  await refreshDevice();
}));

provisionButton.addEventListener("click", () => runDeviceAction("Updating canonical Vault…", async () => {
  let passphrase: string | undefined;
  if (snapshot && !snapshot.hello.vaultPresent) {
    if (initialPassphrase.value !== initialPassphraseConfirm.value) {
      throw new Error("Recovery Passphrase confirmation does not match");
    }
    passphrase = initialPassphrase.value;
  }
  const count = await requireManagement().importAccounts(importSession, passphrase);
  importSession.clear();
  renderImportedAccounts([]);
  clearInitialPassphrase();
  importStatus.textContent = `${count} account${count === 1 ? "" : "s"} committed to the encrypted canonical Vault. Import secrets cleared from the browser session.`;
  await refreshDevice();
}));

wifiForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const ssid = wifiSsid.value;
  const password = wifiPassword.value;
  wifiPassword.value = "";
  void runDeviceAction("Updating encrypted Wi-Fi state…", async () => {
    await requireManagement().setWifi(ssid, password);
    deviceNotice.textContent = "Wi-Fi credentials committed inside the next encrypted Vault generation.";
    await refreshDevice();
  });
});

clearWifiButton.addEventListener("click", () => runDeviceAction("Clearing Wi-Fi from canonical Vault…", async () => {
  await requireManagement().clearWifi();
  wifiPassword.value = "";
  deviceNotice.textContent = "Wi-Fi credentials removed in the next encrypted Vault generation.";
  await refreshDevice();
}));

resetConfirmation.addEventListener("input", updateControls);
factoryResetButton.addEventListener("click", () => {
  if (resetConfirmation.value !== "RESET") return;
  if (!window.confirm("Factory Reset will permanently delete the Device encrypted Vault, active Browser registration, and this browser's matching canonical state. Continue?")) return;
  void runDeviceAction("Factory Reset in progress…", async () => {
    await requireManagement().factoryReset();
    resetConfirmation.value = "";
    wifiPassword.value = "";
    deviceNotice.textContent = "Factory Reset completed. Encrypted user state and active registration were removed; stable Device ID was preserved.";
    await refreshDevice();
  });
});

window.addEventListener("pagehide", () => {
  importSession.clear();
  wifiPassword.value = "";
  clearInitialPassphrase();
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
  clearInitialPassphrase();
  if (current) {
    try {
      await current.close();
    } catch {
      // Physical transport close is a Device-side lock boundary. Do not expose
      // transport internals or retain sensitive browser inputs on failure.
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

function canWriteCanonical(): boolean {
  return snapshot?.browserOwnership === "active" && snapshot.hello.state === "unlocked";
}

function updateControls(): void {
  const connected = management !== null;
  const writable = connected && canWriteCanonical();
  const initial = connected && snapshot !== null && !snapshot.hello.vaultPresent;
  connectButton.disabled = deviceActionInProgress || connected;
  disconnectButton.disabled = deviceActionInProgress || !connected;
  refreshButton.disabled = deviceActionInProgress || !connected;
  syncTimeButton.disabled = deviceActionInProgress || !writable;
  provisionButton.disabled = deviceActionInProgress || !connected || !importSession.hasCompleteAccounts() || (!initial && !writable);
  clearImportButton.disabled = !importSession.hasSensitiveState();
  initialPassphrase.disabled = deviceActionInProgress || !initial;
  initialPassphraseConfirm.disabled = deviceActionInProgress || !initial;
  wifiSsid.disabled = deviceActionInProgress || !writable;
  wifiPassword.disabled = deviceActionInProgress || !writable;
  saveWifiButton.disabled = deviceActionInProgress || !writable;
  clearWifiButton.disabled = deviceActionInProgress || !writable || snapshot?.wifi.configured !== true;
  resetConfirmation.disabled = deviceActionInProgress || !writable;
  factoryResetButton.disabled = deviceActionInProgress || !writable || resetConfirmation.value !== "RESET";
}

function renderDevice(): void {
  const connected = management !== null;
  connectionState.textContent = connected ? "Connected" : "Disconnected";
  deviceStatus.replaceChildren();

  if (!snapshot) {
    appendStatus("Status", connected ? "Connected; canonical status not loaded" : "Not connected");
    storedAccountList.replaceChildren();
    accountsEmpty.textContent = connected ? "Refresh canonical status to load Browser Vault metadata." : "Connect a device to load canonical Vault state.";
    wifiStatus.textContent = connected ? "Canonical status not loaded." : "Connect and unlock a Trusted Browser to view Wi-Fi status.";
    wifiSsid.value = "";
    updateControls();
    return;
  }

  const hello = snapshot.hello;
  appendStatus("Device", hello.device);
  appendStatus("Device ID", hello.deviceId);
  appendStatus("Firmware", hello.firmware);
  appendStatus("Protocol", String(hello.protocol));
  appendStatus("Storage schema", String(hello.storageSchema));
  appendStatus("Vault format", String(hello.vaultFormat));
  appendStatus("Build", hello.buildCommit);
  appendStatus("Runtime", hello.state);
  appendStatus("Browser ownership", snapshot.browserOwnership);
  appendStatus("Generation", hello.generation.toString(10));
  appendStatus("Time", `${snapshot.time.readiness} (${snapshot.time.source})`);
  appendStatus("Accounts", String(snapshot.accounts.length));

  renderStoredAccounts(snapshot.accounts);
  wifiStatus.textContent = snapshot.wifi.configured ? `Configured SSID: ${snapshot.wifi.ssid}` : "Wi-Fi is not configured in the canonical Vault.";
  wifiSsid.value = snapshot.wifi.ssid;
  updateControls();
}

function renderStoredAccounts(accounts: CanonicalDeviceSnapshot["accounts"]): void {
  storedAccountList.replaceChildren();
  accountsEmpty.textContent = accounts.length === 0 ? "No accounts in this browser's canonical Vault." : "";

  accounts.forEach((account, index) => {
    const item = document.createElement("li");
    item.className = "managed-account";
    const identity = document.createElement("strong");
    identity.textContent = account.issuer ? `${account.issuer} — ${account.account}` : account.account;
    const input = document.createElement("input");
    input.type = "text";
    input.maxLength = 96;
    input.value = account.displayName;
    input.setAttribute("aria-label", `Display name for ${account.account}`);

    const actions = document.createElement("div");
    actions.className = "actions compact";
    const rename = actionButton("Rename", () => runDeviceAction("Renaming account in canonical Vault…", async () => {
      await requireManagement().renameAccount(account.id, input.value);
      await refreshDevice();
    }));
    const up = actionButton("↑", () => reorderStoredAccount(index, -1));
    const down = actionButton("↓", () => reorderStoredAccount(index, 1));
    const remove = actionButton("Delete", () => {
      if (!window.confirm(`Delete ${account.account} from the canonical Vault?`)) return Promise.resolve();
      return runDeviceAction("Deleting account from canonical Vault…", async () => {
        await requireManagement().deleteAccount(account.id);
        await refreshDevice();
      });
    });
    const writable = canWriteCanonical();
    rename.disabled = !writable;
    up.disabled = !writable || index === 0;
    down.disabled = !writable || index === accounts.length - 1;
    remove.disabled = !writable;
    input.disabled = !writable;
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
  await runDeviceAction("Reordering canonical accounts…", async () => {
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

function clearInitialPassphrase(): void {
  initialPassphrase.value = "";
  initialPassphraseConfirm.value = "";
}

function requireManagement(): CanonicalDeviceManagement {
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
