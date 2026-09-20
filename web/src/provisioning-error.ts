import { sourceTextOf } from "./ui-localization";

const PROVISIONING_PROGRESS = "Updating accounts…";
const PROVISIONING_SUCCESS_MARKER = "committed to the encrypted Vault";

export function installProvisioningErrorUi(root: Document = document): HTMLElement | null {
  const provisionButton = root.querySelector<HTMLButtonElement>("#provision-import");
  const clearImportButton = root.querySelector<HTMLButtonElement>("#clear-import");
  const qrFileInput = root.querySelector<HTMLInputElement>("#qr-file");
  const deviceNotice = root.querySelector<HTMLElement>("#device-notice");
  const importStatus = root.querySelector<HTMLElement>("#import-status");
  const actionRow = provisionButton?.closest<HTMLElement>(".actions");
  if (!provisionButton || !clearImportButton || !deviceNotice || !importStatus || !actionRow) return null;

  const existing = root.querySelector<HTMLElement>("#provision-error");
  if (existing) return existing;

  const error = root.createElement("p");
  error.id = "provision-error";
  error.className = "notice error";
  error.setAttribute("aria-live", "assertive");
  error.setAttribute("role", "alert");
  actionRow.insertAdjacentElement("afterend", error);

  let provisioning = false;

  const clearError = (): void => {
    error.textContent = "";
  };

  provisionButton.addEventListener("click", () => {
    provisioning = true;
    clearError();
  });

  clearImportButton.addEventListener("click", () => {
    provisioning = false;
    clearError();
  });

  qrFileInput?.addEventListener("change", clearError);

  const deviceNoticeObserver = new MutationObserver(() => {
    if (!provisioning) return;
    const canonicalMessage = sourceTextOf(deviceNotice);
    if (canonicalMessage.length === 0 || canonicalMessage === PROVISIONING_PROGRESS) return;
    // Copy the rendered message for accessibility. If localization has not yet
    // run for this mutation, the document-level localization observer will
    // translate this application-owned error node immediately afterwards.
    error.textContent = deviceNotice.textContent?.trim() || canonicalMessage;
    provisioning = false;
  });
  deviceNoticeObserver.observe(deviceNotice, { childList: true, characterData: true, subtree: true });

  const importStatusObserver = new MutationObserver(() => {
    if (!provisioning) return;
    if (!sourceTextOf(importStatus).includes(PROVISIONING_SUCCESS_MARKER)) return;
    provisioning = false;
    clearError();
  });
  importStatusObserver.observe(importStatus, { childList: true, characterData: true, subtree: true });

  return error;
}

function installWhenReady(): void {
  installProvisioningErrorUi();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", installWhenReady, { once: true });
} else {
  installWhenReady();
}
