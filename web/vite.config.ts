import { defineConfig } from "vite";

export default defineConfig(({ mode }) => {
  const qrSmoke = mode === "qr-smoke";
  const securitySmoke = mode === "security-smoke";

  return {
    base: "/m5authenticator/",
    build: {
      outDir: qrSmoke ? "dist-smoke" : securitySmoke ? "dist-security-smoke" : "dist",
      rollupOptions: {
        input: {
          provisioner: "index.html",
          flasher: "flash.html",
          ...(qrSmoke ? { qrSmoke: "tests/browser/qr-smoke.html" } : {}),
          ...(securitySmoke ? { argon2CspSmoke: "tests/browser/argon2-csp-smoke.html" } : {}),
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
