import { defineConfig, type Plugin } from "vite";

const SMOKE_BUILD_COMMIT = "fedcba9876543210";

function firmwareLayoutSmokeFixture(): Plugin {
  const identity = {
    name: "M5Authenticator",
    version: "0.1.0",
    build_commit: SMOKE_BUILD_COMMIT,
    exact_release: false,
  } as const;
  const factoryManifest = {
    ...identity,
    builds: [{
      chipFamily: "ESP32-S3",
      parts: [{
        path: `m5authenticator-v0.1.0-${SMOKE_BUILD_COMMIT}-m5sticks3.bin`,
        offset: 0,
      }],
    }],
  };
  const updateManifest = {
    ...identity,
    builds: [{
      chipFamily: "ESP32-S3",
      parts: [
        {
          path: `m5authenticator-v0.1.0-${SMOKE_BUILD_COMMIT}-m5sticks3-update-bootloader.bin`,
          offset: 0x000000,
        },
        {
          path: `m5authenticator-v0.1.0-${SMOKE_BUILD_COMMIT}-m5sticks3-update-partition-table.bin`,
          offset: 0x008000,
        },
        {
          path: `m5authenticator-v0.1.0-${SMOKE_BUILD_COMMIT}-m5sticks3-update-ota0.bin`,
          offset: 0x030000,
        },
      ],
    }],
  };
  const target = {
    ...identity,
    factory_manifest: `factory-manifest-${SMOKE_BUILD_COMMIT}.json`,
    update_manifest: `update-manifest-${SMOKE_BUILD_COMMIT}.json`,
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
      emitJson(`firmware/factory-manifest-${SMOKE_BUILD_COMMIT}.json`, factoryManifest);
      emitJson(`firmware/update-manifest-${SMOKE_BUILD_COMMIT}.json`, updateManifest);
    },
  };
}

export default defineConfig(({ mode }) => {
  const qrSmoke = mode === "qr-smoke";

  return {
    base: "/m5authenticator/",
    plugins: qrSmoke ? [firmwareLayoutSmokeFixture()] : [],
    build: {
      outDir: qrSmoke ? "dist-smoke" : "dist",
      rollupOptions: {
        input: {
          provisioner: "index.html",
          flasher: "flash.html",
          help: "help.html",
          ...(qrSmoke ? { qrSmoke: "tests/browser/qr-smoke.html" } : {}),
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
