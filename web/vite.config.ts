import { defineConfig } from "vite";

export default defineConfig({
  base: "/m5authenticator/",
  build: {
    rollupOptions: {
      input: {
        provisioner: "index.html",
        flasher: "flash.html",
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
});
