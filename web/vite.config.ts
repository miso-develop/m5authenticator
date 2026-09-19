import { defineConfig, type Plugin } from "vite";

const SMOKE_BUILD_COMMIT = "fedcba9876543210";
const PRODUCTION_SMOKE_FALLBACK_VERSION = "1.0.0";
const SYNTHETIC_FIRMWARE_BYTES = "M5AUTHENTICATOR_SYNTHETIC_NON_SECRET_FIRMWARE_FIXTURE\n";

function firmwareLayoutSmokeFixture(
  version = "0.1.0",
  buildCommit = SMOKE_BUILD_COMMIT,
  emitFirmwareParts = false,
): Plugin {
  const identity = {
    name: "M5Authenticator",
    version,
    build_commit: buildCommit,
    exact_release: false,
  } as const;
  const factoryPart = `m5authenticator-v${version}-${buildCommit}-m5sticks3.bin`;
  const updateParts = [
    {
      path: `m5authenticator-v${version}-${buildCommit}-m5sticks3-update-bootloader.bin`,
      offset: 0x000000,
    },
    {
      path: `m5authenticator-v${version}-${buildCommit}-m5sticks3-update-partition-table.bin`,
      offset: 0x008000,
    },
    {
      path: `m5authenticator-v${version}-${buildCommit}-m5sticks3-update-ota0.bin`,
      offset: 0x030000,
    },
  ] as const;
  const factoryManifest = {
    ...identity,
    builds: [{
      chipFamily: "ESP32-S3",
      parts: [{
        path: factoryPart,
        offset: 0,
      }],
    }],
  };
  const updateManifest = {
    ...identity,
    builds: [{
      chipFamily: "ESP32-S3",
      parts: updateParts,
    }],
  };
  const target = {
    ...identity,
    factory_manifest: `factory-manifest-${buildCommit}.json`,
    update_manifest: `update-manifest-${buildCommit}.json`,
  };

  return {
    name: "m5auth-firmware-layout-smoke-fixture",
    generateBundle() {
      const emitJson = (fileName: string, value: unknown) => {
        this.emitFile({
          type: "asset",
          fileName,
          source: `${JSON.stringify(value)}\n`,
        });
      };
      emitJson("firmware/firmware-target.json", target);
      emitJson(`firmware/factory-manifest-${buildCommit}.json`, factoryManifest);
      emitJson(`firmware/update-manifest-${buildCommit}.json`, updateManifest);

      if (emitFirmwareParts) {
        for (const fileName of [factoryPart, ...updateParts.map((part) => part.path)]) {
          this.emitFile({
            type: "asset",
            fileName: `firmware/${fileName}`,
            source: SYNTHETIC_FIRMWARE_BYTES,
          });
        }
      }
    },
  };
}

export default defineConfig(({ mode }) => {
  const qrSmoke = mode === "qr-smoke";
  const productionSmoke = mode === "production-smoke";
  const productionSmokeVersion =
    process.env.VITE_M5AUTH_WEB_VERSION ?? PRODUCTION_SMOKE_FALLBACK_VERSION;
  const productionSmokeCommit =
    process.env.VITE_M5AUTH_WEB_BUILD_COMMIT ?? SMOKE_BUILD_COMMIT;

  const smokePlugin = qrSmoke
    ? firmwareLayoutSmokeFixture()
    : productionSmoke
      ? firmwareLayoutSmokeFixture(productionSmokeVersion, productionSmokeCommit, true)
      : undefined;

  return {
    base: "/m5authenticator/",
    plugins: smokePlugin ? [smokePlugin] : [],
    build: {
      outDir: qrSmoke
        ? "dist-smoke"
        : productionSmoke
          ? "dist-production-smoke"
          : "dist",
      rollupOptions: {
        input: {
          provisioner: "index.html",
          flasher: "flash.html",
          help: "help.html",
          ...(qrSmoke ? { qrSmoke: "tests/browser/qr-smoke.html" } : {}),
          ...(productionSmoke
            ? { productionSiteSmoke: "tests/browser/production-site-smoke.html" }
            : {}),
        },
      },
    },
    server: {
      host: "127.0.0.1",
      hmr: false,
    },
    preview: {
      host: "127.0.0.1",
    },
  };
});
