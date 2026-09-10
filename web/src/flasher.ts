import "./style.css";
import "esp-web-tools";

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
    flashChoice(
      "First install — erase device",
      "Use for a new device or an intentional clean installation. This path erases flash user state before installing firmware.",
      `${base}firmware/factory-manifest.json`,
    ),
    flashChoice(
      "Update — keep authenticator data",
      "Use for a normal firmware update. When prompted, choose NOT to erase the device so accounts, Wi-Fi settings, and other auth_nvs state are preserved.",
      `${base}firmware/update-manifest.json`,
    ),
  );
}

function flashChoice(title: string, description: string, manifest: string): HTMLElement {
  const section = document.createElement("section");
  section.className = "panel";
  const heading = document.createElement("h2");
  heading.textContent = title;
  const copy = document.createElement("p");
  copy.className = "hint";
  copy.textContent = description;
  const installButton = document.createElement("esp-web-install-button");
  installButton.setAttribute("manifest", manifest);
  section.append(heading, copy, installButton);
  return section;
}
