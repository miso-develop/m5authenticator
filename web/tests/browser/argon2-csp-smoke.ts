import "../../src/style.css";
import { installProvisioningErrorUi } from "../../src/provisioning-error";
import {
  ARGON2ID_ITERATIONS,
  ARGON2ID_MEMORY_KIB,
  ARGON2ID_OUTPUT_BYTES,
  ARGON2ID_PARALLELISM,
  ARGON2ID_VERSION,
  wrapVmkWithPassphrase,
} from "../../src/security/vault-crypto";

function assertCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function directiveTokens(policy: string, directiveName: string): string[] {
  const directive = policy
    .split(";")
    .map((part) => part.trim())
    .find((part) => part === directiveName || part.startsWith(`${directiveName} `));
  return directive?.split(/\s+/).slice(1) ?? [];
}

async function flushMutations(): Promise<void> {
  await Promise.resolve();
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

export async function runArgon2CspSmoke(): Promise<void> {
  const csp = document
    .querySelector<HTMLMetaElement>('meta[http-equiv="Content-Security-Policy"]')
    ?.getAttribute("content");
  assertCondition(csp, "Production-equivalent CSP is missing from browser smoke page");

  const scriptTokens = directiveTokens(csp, "script-src");
  assertCondition(scriptTokens.includes("'self'"), "CSP script-src no longer permits self-hosted modules");
  assertCondition(
    scriptTokens.includes("'wasm-unsafe-eval'"),
    "CSP does not narrowly permit the bundled Argon2 WebAssembly module",
  );
  assertCondition(
    !scriptTokens.includes("'unsafe-eval'"),
    "CSP unexpectedly permits general JavaScript eval",
  );
  assertCondition(csp.includes("connect-src 'none'"), "CSP no-network boundary regressed");

  let javascriptEvalBlocked = false;
  try {
    globalThis.eval("1 + 1");
  } catch {
    javascriptEvalBlocked = true;
  }
  assertCondition(javascriptEvalBlocked, "JavaScript eval unexpectedly executed under production CSP");

  const actionRow = document.querySelector<HTMLElement>("#provision-import")?.closest<HTMLElement>(".actions");
  const provisionButton = document.querySelector<HTMLButtonElement>("#provision-import");
  const clearImportButton = document.querySelector<HTMLButtonElement>("#clear-import");
  const deviceNotice = document.querySelector<HTMLElement>("#device-notice");
  assertCondition(actionRow && provisionButton && clearImportButton && deviceNotice, "Provisioning error fixture is incomplete");

  const provisionError = installProvisioningErrorUi(document);
  assertCondition(provisionError, "Provisioning error UI was not installed");
  assertCondition(actionRow.nextElementSibling === provisionError, "Provisioning error is not directly below the action row");
  assertCondition(provisionError.classList.contains("error"), "Provisioning error does not use the error style");
  assertCondition(provisionError.getAttribute("aria-live") === "assertive", "Provisioning error is not an aria-live region");

  provisionButton.click();
  deviceNotice.textContent = "Synthetic provisioning failure.";
  await flushMutations();
  assertCondition(
    provisionError.textContent === "Synthetic provisioning failure.",
    "Provisioning failure was not mirrored beside the Apply action",
  );
  assertCondition(
    getComputedStyle(provisionError).color === "rgb(185, 28, 28)",
    "Provisioning failure is not rendered in the expected red error color",
  );

  clearImportButton.click();
  await flushMutations();
  assertCondition(provisionError.textContent === "", "Clearing the import session did not clear the stale provisioning error");

  // The existing Linux browser smoke has a 5-second virtual-time budget, which
  // is intentionally too short for the production 32 MiB / t=3 Argon2id KDF on
  // hosted runners. The release-blocking platform is Desktop Chrome on Windows,
  // whose existing smoke budget is 20 seconds, so execute the full production
  // KDF there while Linux still covers CSP tokens, JS-eval rejection, UI, and QR.
  if (!navigator.userAgent.includes("Windows")) {
    document.body.dataset.argon2Status = "skipped-non-windows";
    return;
  }

  const vmk = new Uint8Array(32);
  const vaultId = new Uint8Array(16);
  vmk.fill(0x31);
  vaultId.fill(0x42);

  try {
    const wrapped = await wrapVmkWithPassphrase(
      vmk,
      vaultId,
      "Synthetic disposable passphrase 2026!",
    );
    try {
      assertCondition(wrapped.ciphertext.length === 32, "Argon2-backed VMK wrap ciphertext length is invalid");
      assertCondition(wrapped.tag.length === 16, "Argon2-backed VMK wrap authentication tag length is invalid");
      assertCondition(wrapped.kdf.version === ARGON2ID_VERSION, "Argon2 version changed");
      assertCondition(wrapped.kdf.memoryKiB === ARGON2ID_MEMORY_KIB, "Argon2 memory parameter changed");
      assertCondition(wrapped.kdf.iterations === ARGON2ID_ITERATIONS, "Argon2 iteration parameter changed");
      assertCondition(wrapped.kdf.parallelism === ARGON2ID_PARALLELISM, "Argon2 parallelism changed");
      assertCondition(wrapped.kdf.outputBytes === ARGON2ID_OUTPUT_BYTES, "Argon2 output length changed");
      document.body.dataset.argon2Status = "pass";
    } finally {
      wrapped.kdf.salt.fill(0);
      wrapped.nonce.fill(0);
      wrapped.ciphertext.fill(0);
      wrapped.tag.fill(0);
    }
  } finally {
    vmk.fill(0);
    vaultId.fill(0);
  }
}
