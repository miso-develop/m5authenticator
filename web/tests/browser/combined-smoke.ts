import { runArgon2CspSmoke, runProductionArgon2Smoke } from "./argon2-csp-smoke";
import { runAutoLockContextSmoke } from "./auto-lock-context-smoke";
import { runLocalizationReworkSmoke } from "./localization-rework-smoke";
import { runPostProvisioningLayoutSmoke } from "./post-provisioning-layout-smoke";
import { runDenseMigrationQrSmoke } from "./qr-dense-migration-smoke";

async function run(): Promise<void> {
  document.body.dataset.stage = "csp-ui";
  await runArgon2CspSmoke();
  document.body.dataset.securityStatus = "pass";

  document.body.dataset.stage = "localization-rework";
  await runLocalizationReworkSmoke();
  if (document.body.dataset.localizationReworkStatus !== "pass") {
    throw new Error("Localization rework DOM smoke did not complete successfully");
  }

  document.body.dataset.stage = "auto-lock-context";
  await runAutoLockContextSmoke();
  if (document.body.dataset.autoLockContextStatus !== "pass") {
    throw new Error("Automatic LOCK context DOM smoke did not complete successfully");
  }

  document.body.dataset.stage = "post-provisioning-layout";
  await runPostProvisioningLayoutSmoke();
  if (document.body.dataset.postProvisioningLayoutStatus !== "pass") {
    throw new Error("Post-provisioning layout DOM smoke did not complete successfully");
  }

  document.body.dataset.stage = "qr-decode";
  await import("./qr-smoke");
  if (document.body.dataset.status !== "pass") {
    throw new Error("QR smoke did not complete successfully after CSP/UI gate");
  }
  document.body.dataset.qrStatus = "pass";

  document.body.dataset.status = "running";
  document.body.dataset.stage = "qr-dense-migration";
  document.body.dataset.denseQrStatus = await runDenseMigrationQrSmoke();

  document.body.dataset.stage = "argon2-kdf";
  await runProductionArgon2Smoke();
  const windows = navigator.userAgent.includes("Windows");
  const expectedArgon2Status = windows ? "pass" : "skipped-non-windows";
  if (document.body.dataset.argon2Status !== expectedArgon2Status) {
    throw new Error("Argon2 browser smoke did not reach the expected platform result");
  }

  document.body.dataset.status = "pass";
  document.body.dataset.stage = "complete";
  document.body.textContent = "QR_ARGON2_CSP_SMOKE_PASS";
}

void run().catch(() => {
  document.body.dataset.status = "fail";
  document.body.dataset.securityStatus = "fail";
  document.body.textContent = "QR_ARGON2_CSP_SMOKE_FAIL";
});
