interface FirmwareTargetFixture {
  readonly name: string;
  readonly version: string;
  readonly build_commit: string;
  readonly exact_release: boolean;
  readonly factory_manifest: string;
  readonly update_manifest: string;
}

interface FirmwareManifestFixture {
  readonly name: string;
  readonly version: string;
  readonly build_commit: string;
  readonly exact_release: boolean;
  readonly builds: readonly {
    readonly chipFamily: string;
    readonly parts: readonly { readonly path: string; readonly offset: number }[];
  }[];
}

const base = import.meta.env.BASE_URL;
const expectedOrigin = window.location.origin;

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function waitFor(
  predicate: () => boolean,
  message: string,
  timeoutMs = 15_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(message);
}

async function loadFrame(path: string, id: string): Promise<HTMLIFrameElement> {
  const frame = document.createElement("iframe");
  frame.id = id;
  frame.src = new URL(path, window.location.href).toString();
  frame.hidden = true;
  document.body.append(frame);

  await new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(() => reject(new Error(`Timed out loading ${path}`)), 15_000);
    frame.addEventListener(
      "load",
      () => {
        window.clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
  assert(frame.contentWindow?.location.origin === expectedOrigin, `${path} did not load same-origin`);
  assert(frame.contentDocument, `${path} document is unavailable`);
  return frame;
}

function assertProductionCsp(frame: HTMLIFrameElement, route: string): void {
  const meta = frame.contentDocument?.querySelector<HTMLMetaElement>(
    'meta[http-equiv="Content-Security-Policy"]',
  );
  assert(meta, `${route} is missing production CSP`);
  const csp = meta.content;
  assert(csp.includes("default-src 'self'"), `${route} CSP default-src is not production-safe`);
  assert(csp.includes("object-src 'none'"), `${route} CSP object-src is not production-safe`);
  assert(csp.includes("base-uri 'self'"), `${route} CSP base-uri is not production-safe`);
}

async function loadJson<T>(url: URL): Promise<T> {
  assert(url.origin === expectedOrigin, `${url.pathname} escaped same origin`);
  const response = await fetch(url, { cache: "no-store" });
  assert(response.ok, `${url.pathname} returned ${response.status}`);
  return await response.json() as T;
}

async function verifyFirmwareFixture(): Promise<void> {
  const targetUrl = new URL(`${base}firmware/firmware-target.json`, window.location.href);
  const target = await loadJson<FirmwareTargetFixture>(targetUrl);
  assert(target.name === "M5Authenticator", "firmware target name mismatch");
  assert(target.exact_release === false, "production smoke fixture must remain non-exact");

  for (const manifestName of [target.factory_manifest, target.update_manifest]) {
    const manifestUrl = new URL(manifestName, targetUrl);
    const manifest = await loadJson<FirmwareManifestFixture>(manifestUrl);
    assert(manifest.build_commit === target.build_commit, "firmware manifest commit mismatch");
    assert(manifest.version === target.version, "firmware manifest version mismatch");

    for (const build of manifest.builds) {
      assert(build.chipFamily === "ESP32-S3", "unexpected firmware chip family");
      for (const part of build.parts) {
        const partUrl = new URL(part.path, manifestUrl);
        assert(partUrl.origin === expectedOrigin, "firmware part escaped same origin");
        const response = await fetch(partUrl, { cache: "no-store" });
        assert(response.ok, `${partUrl.pathname} returned ${response.status}`);
        assert((await response.arrayBuffer()).byteLength > 0, "synthetic firmware part is empty");
      }
    }
  }
}

async function run(): Promise<void> {
  document.body.dataset.stage = "routes";

  const provisioner = await loadFrame(base, "production-provisioner");
  const firmware = await loadFrame(`${base}flash.html`, "production-firmware");
  const help = await loadFrame(`${base}help.html`, "production-help");

  assertProductionCsp(provisioner, "Provisioner");
  assertProductionCsp(firmware, "Firmware");
  assertProductionCsp(help, "Help");

  await waitFor(
    () => Boolean(provisioner.contentDocument?.querySelector("#app > .shell")),
    "Provisioner production route did not initialize",
  );
  await waitFor(
    () => Boolean(help.contentDocument?.querySelector("#help-app")),
    "Help production route did not initialize",
  );
  await waitFor(
    () => (firmware.contentDocument?.querySelectorAll("#flash-status button").length ?? 0) >= 2,
    "Firmware production route did not expose enabled flash actions",
  );

  const firmwareText = firmware.contentDocument?.querySelector("#flash-status")?.textContent ?? "";
  assert(!firmwareText.includes("Production flashing is not enabled yet"), "Firmware Flash surface is disabled");
  assert(!firmwareText.includes("Firmware target unavailable"), "Firmware target fixture did not validate");

  document.body.dataset.stage = "firmware-assets";
  await verifyFirmwareFixture();

  document.body.dataset.status = "pass";
  document.body.dataset.stage = "complete";
  document.body.textContent = "PRODUCTION_SITE_SMOKE_PASS";
}

void run().catch((error) => {
  document.body.dataset.status = "fail";
  document.body.dataset.stage = "failed";
  document.body.textContent = error instanceof Error ? `PRODUCTION_SITE_SMOKE_FAIL: ${error.message}` : "PRODUCTION_SITE_SMOKE_FAIL";
});
