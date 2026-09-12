import { defineConfig } from "vite";

export default defineConfig(({ mode }) => {
  const qrSmoke = mode === "qr-smoke";

  return {
    base: "/m5authenticator/",
    build: {
      outDir: qrSmoke ? "dist-smoke" : "dist",
      rollupOptions: {
        input: {
          provisioner: "index.html",
          flasher: "flash.html",
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
