import "./presence-overlay.css";
import { sourceTextOf } from "./ui-localization";

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
  if (observation.importStatus.includes("committed to the encrypted Vault")) return true;
  return observation.deviceNotice.length > 0 && observation.deviceNotice !== "Updating accounts…";
}

export function installInitialProvisioningPresenceOverlay(root: Document = document): HTMLElement | null {
  const existing = root.querySelector<HTMLElement>(".presence-overlay");
  if (existing) return existing;

  const apply = root.querySelector<HTMLButtonElement>(APPLY_SELECTOR);
  const initialPassphrase = root.querySelector<HTMLInputElement>(INITIAL_PASSPHRASE_SELECTOR);
  const deviceNotice = root.querySelector<HTMLElement>(DEVICE_NOTICE_SELECTOR);
  const importStatus = root.querySelector<HTMLElement>(IMPORT_STATUS_SELECTOR);
  const connectionState = root.querySelector<HTMLElement>(CONNECTION_STATE_SELECTOR);
  if (!apply || !initialPassphrase || !deviceNotice || !importStatus || !connectionState) return null;

  const overlay = root.createElement("div");
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
  root.body.append(overlay);

  let active = false;

  const hide = () => {
    if (!active) return;
    active = false;
    overlay.hidden = true;
    root.body.classList.remove("presence-overlay-open");
  };

  // Internal flow decisions always use canonical application source copy, never
  // the currently rendered/localized text. This keeps the state machine stable
  // when the visible language changes while provisioning is in progress.
  const currentObservation = (): PresenceOverlayObservation => ({
    connectionState: sourceTextOf(connectionState),
    deviceNotice: sourceTextOf(deviceNotice),
    importStatus: sourceTextOf(importStatus),
  });

  const observer = new MutationObserver(() => {
    if (active && shouldDismissInitialProvisioningPresenceOverlay(currentObservation())) hide();
  });
  observer.observe(deviceNotice, { childList: true, subtree: true, characterData: true });
  observer.observe(importStatus, { childList: true, subtree: true, characterData: true });
  observer.observe(connectionState, { childList: true, subtree: true, characterData: true });

  root.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest<HTMLButtonElement>(APPLY_SELECTOR);
    if (button !== apply) return;
    if (!shouldShowInitialProvisioningPresenceOverlay(apply.disabled, initialPassphrase.disabled)) return;

    active = true;
    overlay.hidden = false;
    root.body.classList.add("presence-overlay-open");
  }, true);

  window.addEventListener("pagehide", () => {
    hide();
    observer.disconnect();
  });

  return overlay;
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => installInitialProvisioningPresenceOverlay(), { once: true });
  } else {
    installInitialProvisioningPresenceOverlay();
  }
}
