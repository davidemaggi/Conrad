import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// Dev: run `conrad serve` (TLS off or self) and point CONRAD_DEV_TARGET at it.
const target = process.env.CONRAD_DEV_TARGET ?? "https://localhost:8443";
const proxied = ["/api", "/acme", "/roots", "/issuers", "/crl", "/ocsp", "/healthz"];

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  build: {
    outDir: "../internal/web/dist",
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 700,
  },
  server: {
    proxy: Object.fromEntries(proxied.map((p) => [p, { target, changeOrigin: true, secure: false }])),
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
  },
});
