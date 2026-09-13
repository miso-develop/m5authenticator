import "./presence-overlay.css";

const APPLY_SELECTOR = "#provision-import";
const INITIAL_PASSPHRASE_SELECTOR = "#initial-recovery-passphrase";
const DEVICE_NOTICE_SELECTOR = "#device-notice";
const IMPORT_STATUS_SELECTOR = "#import-status";
const CONNECTION_STATE_SELECTOR = "#connection-state";

export interface PresenceOverlayObservation {
  connectionState: string;
  deviceNotice: string;
  importStatus: string;
}

export function shouldShowInitialProvisioningPresenceOverlay(
  applyDisabled: boolean,
  initialPassphraseDisabled: boolean,
): boolean {
  return !applyDisabled && !initialPassphraseDisabled;
}

export function shouldDismissInitialProvisioningPresenceOverlay(
  observation: PresenceOverlayObservation,
): boolean {
  if (observation.connectionState === "Disconnected") return true;
  if (observation.importStatus.includes("committed to the encrypted canonical Vault")) return true;
  return observation.deviceNotice.length > 0 && observation.deviceNotice !== "Updating canonical Vault…";
}

function installInitialProvisioningPresenceOverlay(): void {
  const apply = document.querySelector<HTMLButtonElement>(APPLY_SELECTOR);
  const initialPassphrase = document.querySelector<HTMLInputElement>(INITIAL_PASSPHRASE_SELECTOR);
  const deviceNotice = document.querySelector<HTMLElement>(DEVICE_NOTICE_SELECTOR);
  const importStatus = document.querySelector<HTMLElement>(IMPORT_STATUS_SELECTOR);
  const connectionState = document.querySelector<HTMLElement>(CONNECTION_STATE_SELECTOR);
  if (!apply || !initialPassphrase || !deviceNotice || !importStatus || !connectionState) return;

  const overlay = document.createElement("div");
  overlay.className = "presence-overlay";
  overlay.hidden = true;
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-labelledby", "presence-overlay-title");
  overlay.setAttribute("aria-describedby", "presence-overlay-description");
  overlay.innerHTML = `
    <div class="presence-dialog">
      <div class="presence-spinner" aria-hidden="true"></div>
      <p class="presence-kicker">M5StickS3 confirmation required</p>
      <h2 id="presence-overlay-title">Press the A button on M5StickS3</h2>
      <p id="presence-overlay-description" class="presence-copy">
        Check the M5StickS3 screen. When it shows <strong>UNLOCK REQUEST</strong>,
        <strong>Initial setup</strong>, and <strong>Press A to confirm</strong>, press the A button once.
      </p>
      <p class="presence-copy presence-warning">
        Keep the Device connected. Do not press Apply again while this confirmation is in progress.
      </p>
      <p class="presence-wait">Waiting for Device confirmation…</p>
    </div>
  `;
  document.body.append(overlay);

  let active = false;

  const hide = () => {
    if (!active) return;
    active = false;
    overlay.hidden = true;
    document.body.classList.remove("presence-overlay-open");
  };

  const currentObservation = (): PresenceOverlayObservation => ({
    connectionState: connectionState.textContent?.trim() ?? "",
    deviceNotice: deviceNotice.textContent?.trim() ?? "",
    importStatus: importStatus.textContent?.trim() ?? "",
  });

  const observer = new MutationObserver(() => {
    if (active && shouldDismissInitialProvisioningPresenceOverlay(currentObservation())) hide();
  });
  observer.observe(deviceNotice, { childList: true, subtree: true, characterData: true });
  observer.observe(importStatus, { childList: true, subtree: true, characterData: true });
  observer.observe(connectionState, { childList: true, subtree: true, characterData: true });

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest<HTMLButtonElement>(APPLY_SELECTOR);
    if (button !== apply) return;
    if (!shouldShowInitialProvisioningPresenceOverlay(apply.disabled, initialPassphrase.disabled)) return;

    active = true;
    overlay.hidden = false;
    document.body.classList.add("presence-overlay-open");
  }, true);

  window.addEventListener("pagehide", () => {
    hide();
    observer.disconnect();
  });
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", installInitialProvisioningPresenceOverlay, { once: true });
  } else {
    installInitialProvisioningPresenceOverlay();
  }
}
