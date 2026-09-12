import { runArgon2CspSmoke } from "./argon2-csp-smoke";

async function run(): Promise<void> {
  document.body.dataset.stage = "argon2-csp";
  await runArgon2CspSmoke();
  document.body.dataset.securityStatus = "pass";
  document.body.dataset.stage = "qr-decode";
  await import("./qr-smoke");
  if (document.body.dataset.status !== "pass") {
    throw new Error("QR smoke did not complete successfully after Argon2 CSP gate");
  }
}

void run().catch(() => {
  document.body.dataset.status = "fail";
  document.body.dataset.securityStatus = "fail";
  document.body.textContent = "QR_ARGON2_CSP_SMOKE_FAIL";
});
