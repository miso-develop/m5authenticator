import "./style.css";
import { requestHello } from "./serial";

const app = document.querySelector<HTMLElement>("#app");
if (!app) {
  throw new Error("Application root is missing");
}

app.innerHTML = `
  <section class="shell">
    <p class="eyebrow">M5 Authenticator</p>
    <h1>Device foundation</h1>
    <p class="description">
      Connect an M5StickS3 over USB to verify the versioned local Web Serial handshake.
    </p>
    <button id="connect" type="button">Connect M5StickS3</button>
    <dl id="status" class="status" aria-live="polite">
      <div><dt>Status</dt><dd>Not connected</dd></div>
    </dl>
  </section>
`;

const button = document.querySelector<HTMLButtonElement>("#connect");
const status = document.querySelector<HTMLElement>("#status");

if (!button || !status) {
  throw new Error("Foundation UI failed to initialize");
}

button.addEventListener("click", async () => {
  button.disabled = true;
  status.innerHTML = "<div><dt>Status</dt><dd>Connecting…</dd></div>";

  try {
    const hello = await requestHello();
    status.innerHTML = `
      <div><dt>Status</dt><dd>Compatible device</dd></div>
      <div><dt>Device</dt><dd>${escapeText(hello.device)}</dd></div>
      <div><dt>Firmware</dt><dd>${escapeText(hello.firmware)}</dd></div>
      <div><dt>Protocol</dt><dd>${hello.protocol}</dd></div>
      <div><dt>Storage schema</dt><dd>${hello.storage_schema}</dd></div>
      <div><dt>Build</dt><dd>${escapeText(hello.build_commit)}</dd></div>
    `;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Connection failed";
    status.innerHTML = `<div><dt>Status</dt><dd>${escapeText(message)}</dd></div>`;
  } finally {
    button.disabled = false;
  }
});

function escapeText(value: string): string {
  const element = document.createElement("span");
  element.textContent = value;
  return element.innerHTML;
}
