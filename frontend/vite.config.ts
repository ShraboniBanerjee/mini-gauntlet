import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  build: {
    // Emit every asset as a file instead of inlining small ones as data: URIs, so the
    // strict Content-Security-Policy in nginx.conf (font-src 'self') needs no exception.
    assetsInlineLimit: 0,
  },
  server: {
    port: 5173,
    // In development the dashboard calls /api on its own origin, like it does behind nginx.
    proxy: { "/api": "http://localhost:8000" },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    restoreMocks: true,
  },
});
