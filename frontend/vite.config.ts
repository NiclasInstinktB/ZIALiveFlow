import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Im Dev-Modus werden /api-Anfragen (inkl. WebSocket) an das FastAPI-Backend
// (Port 8000) geproxyt, damit Cookies/CORS unkompliziert funktionieren
// (Single-Origin im Browser). `ws: true` proxyt auch den Stream-Upgrade.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
  },
});
