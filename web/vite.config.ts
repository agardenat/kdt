import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Le backend kdt-web sert le bundle et l'API sous la même origine : en développement, tout ce
// qui commence par /api part sur le binaire local plutôt que sur le serveur de Vite.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8080", changeOrigin: false },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
