import { defineConfig } from "vite";

// Tauri serves the frontend from a fixed port in dev and from `dist/` in
// release. Nothing here talks to the network at runtime.
export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  build: {
    target: "es2021",
    minify: "esbuild",
    sourcemap: false,
  },
});
