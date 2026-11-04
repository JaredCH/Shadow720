import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Standalone config so the harness does not inherit the app's root or plugins.
export default defineConfig({
  root: __dirname,
  // Tailwind's config lives at the repo root, so point PostCSS at it.
  css: { postcss: "../../" },
  plugins: [react()],
  server: { port: 4174, strictPort: true },
  preview: { port: 4174, strictPort: true },
});
