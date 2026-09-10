import "./style.css";
import { decodeQrImage } from "./import/qr";
import { ImportSession, type ImportSessionUpdate } from "./import/session";
import { ImportError, type ImportedAccountPreview } from "./import/types";
import { requestHello } from "./serial";

const app = document.querySelector<HTMLElement>("#app");
if (!app) {
  throw new Error("Application root is missing");
}

app.innerHTML = `
  <section class="shell">
    <p class="eyebrow">M5 Authenticator</p>
    <h1>Local provisioner</h1>
    <p class="description">
      Import authenticator QR screenshots locally in this browser, review the accounts, and connect an M5StickS3 over USB.
    </p>

    <section class="panel" aria-labelledby="import-heading">
      <h2 id="import-heading">Import accounts</h2>
      <p class="hint">
        Supports standard TOTP QR codes and Google Authenticator exports. Images and secrets are not uploaded or persisted.
      </p>
      <label class="file-label" for="qr-file">QR screenshot image</label>
      <input id="qr-file" type="file" accept="image/*" />
      <p id="import-status" class="notice" aria-live="polite">No accounts imported.</p>
      <ol id="account-list" class="account-list"></ol>
      <button id="clear-import" class="secondary" type="button" disabled>Clear import session</button>
    </section>

    <section class="panel" aria-labelledby="device-heading">
      <h2 id="device-heading">Device</h2>
      <button id="connect" type="button">Connect M5StickS3</button>
      <dl id="status" class="status" aria-live="polite">
        <div><dt>Status</dt><dd>Not connected</dd></div>
      </dl>
    </section>
  </section>
`;

const connectButton = document.querySelector<HTMLButtonElement>("#connect");
const deviceStatus = document.querySelector<HTMLElement>("#status");
const qrFileInput = document.querySelector<HTMLInputElement>("#qr-file");
const importStatus = document.querySelector<HTMLElement>("#import-status");
const accountList = document.querySelector<HTMLOListElement>("#account-list");
const clearImportButton = document.querySelector<HTMLButtonElement>("#clear-import");

if (!connectButton || !deviceStatus || !qrFileInput || !importStatus || !accountList || !clearImportButton) {
  throw new Error("Provisioner UI failed to initialize");
}

const importSession = new ImportSession();

qrFileInput.addEventListener("change", async () => {
  const file = qrFileInput.files?.[0];
  if (!file) {
    return;
  }

  qrFileInput.disabled = true;
  importStatus.textContent = "Decoding QR image locally…";

  try {
    const decodedText = await decodeQrImage(file);
    const update = importSession.importDecodedText(decodedText);
    renderImportUpdate(update);
  } catch (error) {
    importStatus.textContent = error instanceof ImportError ? error.message : "QR import failed.";
    renderAccountList(importSession.preview());
  } finally {
    qrFileInput.value = "";
    qrFileInput.disabled = false;
    clearImportButton.disabled = !importSession.hasSensitiveState();
  }
});

clearImportButton.addEventListener("click", () => {
  importSession.clear();
  renderAccountList([]);
  importStatus.textContent = "Import session cleared.";
  clearImportButton.disabled = true;
});

window.addEventListener("pagehide", () => {
  importSession.clear();
});

connectButton.addEventListener("click", async () => {
  connectButton.disabled = true;
  deviceStatus.innerHTML = "<div><dt>Status</dt><dd>Connecting…</dd></div>";

  try {
    const hello = await requestHello();
    deviceStatus.innerHTML = `
      <div><dt>Status</dt><dd>Compatible device</dd></div>
      <div><dt>Device</dt><dd>${escapeText(hello.device)}</dd></div>
      <div><dt>Firmware</dt><dd>${escapeText(hello.firmware)}</dd></div>
      <div><dt>Protocol</dt><dd>${hello.protocol}</dd></div>
      <div><dt>Storage schema</dt><dd>${hello.storage_schema}</dd></div>
      <div><dt>Build</dt><dd>${escapeText(hello.build_commit)}</dd></div>
    `;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Connection failed";
    deviceStatus.innerHTML = `<div><dt>Status</dt><dd>${escapeText(message)}</dd></div>`;
  } finally {
    connectButton.disabled = false;
  }
});

function renderImportUpdate(update: ImportSessionUpdate): void {
  renderAccountList(update.accounts);
  if (update.batch) {
    importStatus.textContent = `Google Authenticator export: ${update.batch.received} of ${update.batch.total} QR codes received.`;
    return;
  }

  importStatus.textContent = `${update.accounts.length} account${update.accounts.length === 1 ? "" : "s"} ready for review.`;
}

function renderAccountList(accounts: ImportedAccountPreview[]): void {
  accountList.replaceChildren();
  for (const account of accounts) {
    const item = document.createElement("li");
    const title = document.createElement("strong");
    const details = document.createElement("span");
    title.textContent = account.issuer ? `${account.issuer} — ${account.account}` : account.account;
    details.textContent = `${account.algorithm} · ${account.digits} digits · ${account.period}s`;
    item.append(title, details);
    accountList.append(item);
  }
}

function escapeText(value: string): string {
  const element = document.createElement("span");
  element.textContent = value;
  return element.innerHTML;
}
