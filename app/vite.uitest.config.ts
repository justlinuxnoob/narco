import { defineConfig } from "vite";
import { resolve } from "node:path";

// Runs the real frontend against mocked Tauri modules so the UI can be driven
// and inspected in a plain browser.
export default defineConfig({
  server: { port: 1421, strictPort: true },
  resolve: {
    alias: {
      "@tauri-apps/api/core": resolve(__dirname, "uitest/mock-core.ts"),
      "@tauri-apps/api/event": resolve(__dirname, "uitest/mock-event.ts"),
    },
  },
});
