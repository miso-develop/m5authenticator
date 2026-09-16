import "./style.css";
import { installFirmwareBuildInfo } from "./firmware-build-info";
import {
  loadPinnedFirmwareTarget,
  runFactoryInstall,
  runStatePreservingUpdate,
  type PinnedFirmwareTarget,
} from "./firmware-update";

const app = document.querySelector<HTMLElement>("#flash-app");
if (!app) throw new Error("Firmware flash root is missing");

const flashEnabled = import.meta.env.VITE_M5AUTH_FLASH_ENABLED === "true";
const base = import.meta.env.BASE_URL;
const targetMetadataPath = `${base}firmware/firmware-target.json`;

app.innerHTML = `
  <section class="shell">
    <p class="eyebrow">M5Authenticator</p>
    <h1>Firmware Flash</h1>
    <p class="description">
      Flash the CI-built M5StickS3 firmware directly from this site. Firmware images are same-origin static files; authenticator credentials are never part of a firmware package.
    </p>
    <section id="flash-status" class="panel"></section>
  </section>
`;

const shell = document.querySelector<HTMLElement>("#flash-app > .shell");
const status = document.querySelector<HTMLElement>("#flash-status");
if (!shell || !status) throw new Error("Firmware flash UI is incomplete");

const updateBuildInfo = installFirmwareBuildInfo(shell);

if (!flashEnabled) {
  updateBuildInfo({ status: "unavailable" });
  const heading = document.createElement("h2");
  heading.textContent = "Production flashing is not enabled yet";
  const explanation = document.createElement("p");
  explanation.className = "hint";
  explanation.textContent = "The V1 Encrypted Vault / RAM-only VMK release contract is active, but production firmware publishing remains fail-closed until the final V1 security closeout explicitly enables release eligibility.";
  status.append(heading, explanation);
} else {
  const loading = document.createElement("p");
  loading.className = "notice";
  loading.textContent = "Loading and validating pinned firmware target…";
  status.append(loading);

  void loadPinnedFirmwareTarget(targetMetadataPath)
    .then((target) => {
      updateBuildInfo({ status: "ready", identity: target.identity });
      status.replaceChildren(
        firstInstallChoice(
          "First install — erase device",
          "Use only for a new device or an intentional clean installation. This path erases flash user state before installing the displayed firmware build.",
          target,
        ),
        updateChoice(
          "Update — keep authenticator data",
          "Normal Update writes only the bootloader, partition table, and ota_0 application ranges for the displayed firmware build and never requests a full-flash erase. Registration and Device identity in ordinary nvs, plus the encrypted Vault in auth_nvs, remain outside those write ranges. The RAM-only VMK is lost on reboot, so a provisioned device returns LOCKED after the update.",
          target,
        ),
      );
    })
    .catch((error) => {
      updateBuildInfo({ status: "unavailable" });
      const heading = document.createElement("h2");
      heading.textContent = "Firmware target unavailable";
      const explanation = document.createElement("p");
      explanation.className = "notice";
      explanation.textContent = error instanceof Error ? error.message : "Firmware target validation failed";
      status.replaceChildren(heading, explanation);
    });
}

function firstInstallChoice(title: string, description: string, target: PinnedFirmwareTarget): HTMLElement {
  const section = flashPanel(title, description);
  const action = document.createElement("button");
  action.type = "button";
  action.textContent = "First install — erase device";
  const progress = document.createElement("p");
  progress.className = "notice";

  action.addEventListener("click", async () => {
    action.disabled = true;
    progress.textContent = "Validating pinned factory firmware package...";
    try {
      await runFactoryInstall(target, (state) => {
        progress.textContent = state.message;
      });
    } catch (error) {
      progress.textContent = error instanceof Error ? error.message : "Firmware install failed";
    } finally {
      action.disabled = false;
    }
  });

  section.append(action, progress);
  return section;
}

function updateChoice(title: string, description: string, target: PinnedFirmwareTarget): HTMLElement {
  const section = flashPanel(title, description);
  const action = document.createElement("button");
  action.type = "button";
  action.textContent = "Update without erasing user data";
  const progress = document.createElement("p");
  progress.className = "notice";

  action.addEventListener("click", async () => {
    action.disabled = true;
    progress.textContent = "Validating pinned state-preserving firmware package...";
    try {
      await runStatePreservingUpdate(target, (state) => {
        progress.textContent = state.message;
      });
    } catch (error) {
      progress.textContent = error instanceof Error ? error.message : "Firmware update failed";
    } finally {
      action.disabled = false;
    }
  });

  section.append(action, progress);
  return section;
}

function flashPanel(title: string, description: string): HTMLElement {
  const section = document.createElement("section");
  section.className = "panel";
  const heading = document.createElement("h2");
  heading.textContent = title;
  const copy = document.createElement("p");
  copy.className = "hint";
  copy.textContent = description;
  section.append(heading, copy);
  return section;
}
