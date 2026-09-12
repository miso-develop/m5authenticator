const PROVISIONING_PROGRESS = "Updating canonical Vault…";
const PROVISIONING_SUCCESS_MARKER = "committed to the encrypted canonical Vault";

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
    const message = deviceNotice.textContent?.trim() ?? "";
    if (message.length === 0 || message === PROVISIONING_PROGRESS) return;
    error.textContent = message;
    provisioning = false;
  });
  deviceNoticeObserver.observe(deviceNotice, { childList: true, characterData: true, subtree: true });

  const importStatusObserver = new MutationObserver(() => {
    if (!provisioning) return;
    if (!(importStatus.textContent ?? "").includes(PROVISIONING_SUCCESS_MARKER)) return;
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
