import {
  GenerationConflictError,
  IndexedDbBrowserVaultStore,
  RECOVERY_PASSPHRASE_CHANGE_NOTICE,
  changeRecoveryPassphrase,
  displayVaultId,
  exportRecoveryPackage,
  importRecoveryPackage,
  type BrowserCanonicalState,
} from "./browser-vault";

const shell = document.querySelector<HTMLElement>(".shell");
if (!shell) throw new Error("Security panel requires the main application shell");

const section = document.createElement("section");
section.className = "panel";
section.setAttribute("aria-labelledby", "browser-security-heading");
section.innerHTML = `
  <div class="panel-heading">
    <h2 id="browser-security-heading">Security &amp; Recovery</h2>
    <span id="browser-trust-state" class="badge">No canonical Vault</span>
  </div>
  <p class="hint">The browser canonical state is encrypted locally in IndexedDB. Plaintext credentials, Passphrases, VMKs, BUKs, and BRK private key material are never exported in a Recovery Package.</p>
  <label for="browser-vault-select">Browser Vault</label>
  <select id="browser-vault-select"></select>
  <dl id="browser-security-status" class="status" aria-live="polite"></dl>
  <p id="browser-security-notice" class="notice" aria-live="polite"></p>

  <h3>Recovery Package</h3>
  <p class="hint">Recovery Packages are encrypted but security-sensitive offline Passphrase-guessing targets. Do not upload them, attach them to Issues/PRs, or commit them to a repository.</p>
  <div class="actions">
    <button id="browser-recovery-export" type="button" disabled>Export Recovery Package</button>
  </div>
  <label class="file-label" for="browser-recovery-file">Import Recovery Package</label>
  <input id="browser-recovery-file" type="file" accept="application/json,.json" />
  <label for="browser-recovery-passphrase">Recovery Passphrase</label>
  <input id="browser-recovery-passphrase" type="password" autocomplete="current-password" />
  <div class="actions">
    <button id="browser-recovery-import" type="button">Import for browser replacement</button>
    <button id="browser-recovery-cancel" class="secondary" type="button">Clear recovery inputs</button>
  </div>

  <h3>Change Recovery Passphrase</h3>
  <p class="hint">${RECOVERY_PASSPHRASE_CHANGE_NOTICE}</p>
  <label for="browser-current-passphrase">Current Passphrase</label>
  <input id="browser-current-passphrase" type="password" autocomplete="current-password" disabled />
  <label for="browser-new-passphrase">New Passphrase</label>
  <input id="browser-new-passphrase" type="password" autocomplete="new-password" disabled />
  <label for="browser-confirm-passphrase">Confirm new Passphrase</label>
  <input id="browser-confirm-passphrase" type="password" autocomplete="new-password" disabled />
  <div class="actions">
    <button id="browser-change-passphrase" type="button" disabled>Change Passphrase</button>
    <button id="browser-passphrase-cancel" class="secondary" type="button">Clear Passphrase inputs</button>
  </div>
`;

const dangerPanel = shell.querySelector<HTMLElement>(".danger");
if (dangerPanel) dangerPanel.before(section);
else shell.append(section);

const trustState = queryRequired<HTMLElement>("#browser-trust-state");
const vaultSelect = queryRequired<HTMLSelectElement>("#browser-vault-select");
const status = queryRequired<HTMLDListElement>("#browser-security-status");
const notice = queryRequired<HTMLElement>("#browser-security-notice");
const exportButton = queryRequired<HTMLButtonElement>("#browser-recovery-export");
const recoveryFile = queryRequired<HTMLInputElement>("#browser-recovery-file");
const recoveryPassphrase = queryRequired<HTMLInputElement>("#browser-recovery-passphrase");
const importButton = queryRequired<HTMLButtonElement>("#browser-recovery-import");
const recoveryCancel = queryRequired<HTMLButtonElement>("#browser-recovery-cancel");
const currentPassphrase = queryRequired<HTMLInputElement>("#browser-current-passphrase");
const newPassphrase = queryRequired<HTMLInputElement>("#browser-new-passphrase");
const confirmPassphrase = queryRequired<HTMLInputElement>("#browser-confirm-passphrase");
const changePassphraseButton = queryRequired<HTMLButtonElement>("#browser-change-passphrase");
const passphraseCancel = queryRequired<HTMLButtonElement>("#browser-passphrase-cancel");

const store = new IndexedDbBrowserVaultStore();
let states: BrowserCanonicalState[] = [];
let current: BrowserCanonicalState | null = null;
let conflictMessage: string | null = null;
let busy = false;

vaultSelect.addEventListener("change", () => {
  current = states.find((state) => displayVaultId(state.vault.vaultId) === vaultSelect.value) ?? null;
  conflictMessage = null;
  render();
});

exportButton.addEventListener("click", () => {
  if (!current || busy) return;
  const serialized = exportRecoveryPackage(current);
  const blob = new Blob([serialized], { type: "application/vnd.m5authenticator.recovery+json" });
  const url = URL.createObjectURL(blob);
  try {
    const link = document.createElement("a");
    link.href = url;
    link.download = `m5authenticator-recovery-${displayVaultId(current.vault.vaultId).slice(0, 12)}.json`;
    link.click();
    notice.textContent = "Recovery Package exported. Store it as a security-sensitive offline file.";
  } finally {
    URL.revokeObjectURL(url);
  }
});

importButton.addEventListener("click", () => void run(async () => {
  const file = recoveryFile.files?.[0];
  if (!file) throw new Error("Choose a Recovery Package file first");
  if (recoveryPassphrase.value.length === 0) throw new Error("Enter the Recovery Passphrase");

  let serialized = await file.text();
  const passphrase = recoveryPassphrase.value;
  try {
    const imported = await importRecoveryPackage(serialized, passphrase);
    const existing = await store.get(imported.vault.vaultId);
    if (existing) {
      throw new Error("This browser already has canonical state for that Vault. Import will not overwrite an active or pending Trusted Browser implicitly.");
    }
    await store.put(imported);
    conflictMessage = null;
    notice.textContent = "Recovery Package imported. Fresh local BUK/BRK keys were created, but this browser is replacement-pending and is not yet an active Device writer.";
    await refresh();
  } finally {
    serialized = "";
    clearRecoveryInputs();
  }
}));

recoveryCancel.addEventListener("click", clearRecoveryInputs);

changePassphraseButton.addEventListener("click", () => void run(async () => {
  if (!current) throw new Error("No browser canonical Vault is selected");
  if (newPassphrase.value !== confirmPassphrase.value) throw new Error("New Passphrase confirmation does not match");
  const expectedGeneration = current.vault.generation;
  const updated = await changeRecoveryPassphrase(current, currentPassphrase.value, newPassphrase.value);
  await store.put(updated, expectedGeneration);
  conflictMessage = null;
  notice.textContent = RECOVERY_PASSPHRASE_CHANGE_NOTICE;
  clearPassphraseInputs();
  await refresh();
}));

passphraseCancel.addEventListener("click", clearPassphraseInputs);
window.addEventListener("pagehide", () => {
  clearRecoveryInputs();
  clearPassphraseInputs();
});

void refresh().catch((error: unknown) => {
  notice.textContent = userFacingError(error, "Browser security state could not be loaded.");
});

async function refresh(): Promise<void> {
  states = await store.list();
  const selectedKey = current ? displayVaultId(current.vault.vaultId) : vaultSelect.value;
  vaultSelect.replaceChildren();
  for (const state of states) {
    const option = document.createElement("option");
    option.value = displayVaultId(state.vault.vaultId);
    option.textContent = state.deviceMetadata?.deviceId
      ? `${state.deviceMetadata.deviceId} · ${option.value.slice(0, 12)}…`
      : `${option.value.slice(0, 12)}…`;
    vaultSelect.append(option);
  }
  current = states.find((state) => displayVaultId(state.vault.vaultId) === selectedKey) ?? states[0] ?? null;
  if (current) vaultSelect.value = displayVaultId(current.vault.vaultId);
  render();
}

function render(): void {
  status.replaceChildren();
  const hasState = current !== null;
  const conflict = conflictMessage !== null;
  vaultSelect.disabled = busy || states.length <= 1;
  exportButton.disabled = busy || !hasState;
  currentPassphrase.disabled = busy || !hasState || conflict;
  newPassphrase.disabled = busy || !hasState || conflict;
  confirmPassphrase.disabled = busy || !hasState || conflict;
  changePassphraseButton.disabled = busy || !hasState || conflict;
  recoveryFile.disabled = busy;
  recoveryPassphrase.disabled = busy;
  importButton.disabled = busy;

  if (!current) {
    trustState.textContent = "No canonical Vault";
    appendStatus("Browser state", "None");
    appendStatus("Initial setup", "Created by the V1 canonical provisioning flow; Protocol 2 is not activated by this screen");
    return;
  }

  if (conflict) {
    trustState.textContent = "Conflict / recovery required";
  } else {
    trustState.textContent = current.trustedBrowser.status === "active" ? "Trusted Browser active" : "Replacement pending";
  }
  appendStatus("Vault ID", displayVaultId(current.vault.vaultId));
  appendStatus("Generation", current.vault.generation.toString(10));
  appendStatus("Registration ID", displayVaultId(current.trustedBrowser.registrationId));
  appendStatus("Registration epoch", String(current.trustedBrowser.epoch));
  appendStatus(
    "Browser ownership",
    conflict
      ? "Writes blocked pending explicit recovery/reconciliation"
      : current.trustedBrowser.status === "active"
        ? "Active writer"
        : "Pending explicit Device replacement",
  );
  if (conflictMessage) appendStatus("Conflict", conflictMessage);
  appendStatus("BUK", "Local non-extractable AES-256-GCM key");
  appendStatus("BRK", "Local non-extractable ECDSA P-256 private key; only public registration material is shareable");
}

function appendStatus(label: string, value: string): void {
  const row = document.createElement("div");
  const term = document.createElement("dt");
  const description = document.createElement("dd");
  term.textContent = label;
  description.textContent = value;
  row.append(term, description);
  status.append(row);
}

async function run(action: () => Promise<void>): Promise<void> {
  if (busy) return;
  busy = true;
  render();
  try {
    await action();
  } catch (error) {
    if (error instanceof GenerationConflictError) conflictMessage = error.message;
    notice.textContent = userFacingError(error, "Security operation failed.");
    clearRecoveryInputs();
    clearPassphraseInputs();
  } finally {
    busy = false;
    render();
  }
}

function clearRecoveryInputs(): void {
  recoveryPassphrase.value = "";
  recoveryFile.value = "";
}

function clearPassphraseInputs(): void {
  currentPassphrase.value = "";
  newPassphrase.value = "";
  confirmPassphrase.value = "";
}

function queryRequired<T extends Element>(selector: string): T {
  const element = section.querySelector<T>(selector);
  if (!element) throw new Error(`Security panel element is missing: ${selector}`);
  return element;
}

function userFacingError(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.length > 0) return error.message;
  return fallback;
}
