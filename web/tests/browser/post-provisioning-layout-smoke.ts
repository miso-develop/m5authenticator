import "../../src/style.css";
import "../../src/post-provisioning-layout.css";
import { installFirmwareBuildInfo } from "../../src/firmware-build-info";
import { installWebBuildInfo } from "../../src/web-build-info";

const GEOMETRY_EPSILON_PX = 0.5;

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function near(left: number, right: number): boolean {
  return Math.abs(left - right) <= GEOMETRY_EPSILON_PX;
}

function afterLayout(): Promise<void> {
  return new Promise((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  });
}

export async function runPostProvisioningLayoutSmoke(): Promise<void> {
  const saved = document.createDocumentFragment();
  for (const node of Array.from(document.body.childNodes)) saved.append(node);

  try {
    await verifyProvisioningPresentation();
    await verifyFirmwareGeometry();
    document.body.dataset.postProvisioningLayoutStatus = "pass";
  } catch (error) {
    document.body.dataset.postProvisioningLayoutError = error instanceof Error ? error.message : "Unknown layout smoke failure";
    throw error;
  } finally {
    document.body.replaceChildren();
    document.body.append(saved);
  }
}

async function verifyProvisioningPresentation(): Promise<void> {
  const root = document.createElement("main");
  root.id = "app";
  root.innerHTML = `
    <main class="shell">
      <p class="eyebrow">M5Authenticator</p>
      <h1>Provisioning</h1>
      <p class="description">Synthetic production-layout fixture.</p>
      <section class="panel" id="first-panel"><h2>Device</h2></section>
      <section class="panel" id="import-panel">
        <h2>Import accounts</h2>
        <div id="initial-passphrase-fields">
          <label for="initial-recovery-passphrase">Recovery Passphrase</label>
          <input id="initial-recovery-passphrase" type="password" disabled />
          <label for="initial-recovery-passphrase-confirm">Confirm Recovery Passphrase</label>
          <input id="initial-recovery-passphrase-confirm" type="password" disabled />
        </div>
      </section>
      <section class="panel" id="last-operational-panel"><h2>Factory Reset</h2></section>
    </main>
  `;
  document.body.append(root);
  await afterLayout();

  const shell = root.querySelector<HTMLElement>(".shell");
  const firstPanel = root.querySelector<HTMLElement>("#first-panel");
  const importPanel = root.querySelector<HTMLElement>("#import-panel");
  const passphraseFields = root.querySelector<HTMLElement>("#initial-passphrase-fields");
  const passphrase = root.querySelector<HTMLInputElement>("#initial-recovery-passphrase");
  const passphraseConfirm = root.querySelector<HTMLInputElement>("#initial-recovery-passphrase-confirm");
  assert(shell && firstPanel && importPanel && passphraseFields && passphrase && passphraseConfirm, "Provisioning layout fixture is incomplete");

  assert(getComputedStyle(passphraseFields).display === "none", "Inactive initial Recovery Passphrase fields must be hidden");
  passphrase.disabled = false;
  passphraseConfirm.disabled = false;
  await afterLayout();
  assert(getComputedStyle(passphraseFields).display !== "none", "Initial provisioning must expose Recovery Passphrase fields");

  const firstStyle = getComputedStyle(firstPanel);
  const subsequentStyle = getComputedStyle(importPanel);
  assert(parseFloat(firstStyle.marginTop) < 32, "First Provisioning section must not gain the large subsequent-section margin");
  assert(parseFloat(subsequentStyle.marginTop) >= 32, "Subsequent Provisioning sections require at least 32px top separation");
  assert(parseFloat(subsequentStyle.paddingTop) >= 32, "Subsequent Provisioning headings require at least 32px boundary padding");

  installWebBuildInfo(shell);
  await afterLayout();
  assert(shell.lastElementChild?.id === "web-build-identity", "Web build provenance must follow primary Provisioning content");

  root.remove();
}

async function verifyFirmwareGeometry(): Promise<void> {
  assert(window.innerWidth >= 720, "Firmware geometry smoke requires a supported desktop viewport");

  const header = document.createElement("header");
  header.id = "site-header";
  header.innerHTML = `
    <div class="site-nav-shell">
      <span class="product-mark">M5Authenticator</span>
      <nav class="site-tabs"><a href="#">Provisioning</a><a href="#" aria-current="page">Firmware</a><a href="#">Usage</a></nav>
      <div class="language-switcher"><button class="language-button" type="button">EN</button></div>
    </div>
  `;

  const root = document.createElement("main");
  root.id = "flash-app";
  root.innerHTML = `
    <section class="shell">
      <p class="eyebrow">M5Authenticator</p>
      <h1>Firmware Flash</h1>
      <p class="description">Synthetic asynchronous firmware-layout fixture.</p>
      <section id="flash-status" class="panel"><p class="notice">Loading firmware metadata…</p></section>
    </section>
  `;
  document.body.append(header, root);

  const nav = header.querySelector<HTMLElement>(".site-nav-shell");
  const shell = root.querySelector<HTMLElement>(".shell");
  const status = root.querySelector<HTMLElement>("#flash-status");
  assert(nav && shell && status, "Firmware layout fixture is incomplete");

  const updateBuildInfo = installFirmwareBuildInfo(shell);
  await afterLayout();
  assert(shell.lastElementChild?.id === "firmware-build-identity", "Firmware build provenance must follow Flash/Update content");

  const beforeShell = shell.getBoundingClientRect();
  const beforeNav = nav.getBoundingClientRect();

  const resolvedContent = document.createDocumentFragment();
  for (let index = 0; index < 80; index += 1) {
    const paragraph = document.createElement("p");
    paragraph.className = "hint";
    paragraph.textContent = `Resolved firmware guidance ${index + 1}`;
    resolvedContent.append(paragraph);
  }
  status.replaceChildren(resolvedContent);
  await Promise.resolve();
  updateBuildInfo({
    status: "ready",
    identity: {
      version: "0.1.0",
      buildCommit: "abcdef0123456789abcdef0123456789abcdef01",
      exactRelease: false,
    },
  });
  await afterLayout();

  const afterShell = shell.getBoundingClientRect();
  const afterNav = nav.getBoundingClientRect();
  assert(document.documentElement.scrollHeight > window.innerHeight, "Resolved firmware fixture must exercise vertical overflow");
  assert(getComputedStyle(document.documentElement).getPropertyValue("scrollbar-gutter").includes("stable"), "Desktop shell must reserve a stable scrollbar gutter");
  assert(near(beforeShell.left, afterShell.left) && near(beforeShell.width, afterShell.width), "Firmware shell geometry shifted after asynchronous metadata resolution");
  assert(near(beforeNav.left, afterNav.left) && near(beforeNav.width, afterNav.width), "Top navigation geometry shifted after asynchronous metadata resolution");

  header.remove();
  root.remove();
}
