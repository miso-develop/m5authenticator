import "./style.css";
import "esp-web-tools";
import { runStatePreservingUpdate } from "./firmware-update";

const app = document.querySelector<HTMLElement>("#flash-app");
if (!app) throw new Error("Firmware flash root is missing");

const flashEnabled = import.meta.env.VITE_M5AUTH_FLASH_ENABLED === "true";
const base = import.meta.env.BASE_URL;

app.innerHTML = `
  <section class="shell">
    <p class="eyebrow">M5 Authenticator</p>
    <h1>Firmware Flash</h1>
    <p class="description">
      Flash the CI-built M5StickS3 firmware directly from this site. Firmware images are same-origin static files; authenticator credentials are never part of a firmware package.
    </p>
    <section id="flash-status" class="panel"></section>
  </section>
`;

const status = document.querySelector<HTMLElement>("#flash-status");
if (!status) throw new Error("Firmware flash status area is missing");

if (!flashEnabled) {
  const heading = document.createElement("h2");
  heading.textContent = "Production flashing is not enabled yet";
  const explanation = document.createElement("p");
  explanation.className = "hint";
  explanation.textContent = "This build still uses the development-only synthetic storage security backend. Production firmware publishing stays fail-closed until the dedicated production eFuse-backed security task is complete.";
  status.append(heading, explanation);
} else {
  status.append(
    firstInstallChoice(
      "First install — erase device",
      "Use only for a new device or an intentional clean installation. This path erases flash user state before installing firmware.",
      `${base}firmware/factory-manifest.json`,
    ),
    updateChoice(
      "Update — keep authenticator data",
      "Normal updates never request a full-flash erase. Accounts, TOTP secrets, Wi-Fi settings, and UI settings in auth_nvs stay outside the firmware write range. Use the Provisioner Factory Reset action when you intentionally need to erase user state.",
      `${base}firmware/update-manifest.json`,
    ),
  );
}

function firstInstallChoice(title: string, description: string, manifest: string): HTMLElement {
  const section = flashPanel(title, description);
  const installButton = document.createElement("esp-web-install-button");
  installButton.setAttribute("manifest", manifest);
  section.append(installButton);
  return section;
}

function updateChoice(title: string, description: string, manifest: string): HTMLElement {
  const section = flashPanel(title, description);
  const action = document.createElement("button");
  action.type = "button";
  action.textContent = "Update without erasing user data";
  const progress = document.createElement("p");
  progress.className = "notice";

  action.addEventListener("click", async () => {
    action.disabled = true;
    progress.textContent = "Waiting for device selection...";
    try {
      await runStatePreservingUpdate(manifest, (state) => {
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
