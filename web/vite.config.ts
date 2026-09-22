import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Le backend kdt-web sert le bundle et l'API sous la même origine : en développement, tout ce
// qui commence par /api part sur le binaire local plutôt que sur le serveur de Vite.
export default defineConfig({
  // Des liens relatifs, pas absolus : la page servie porte un `<base href>` posé par le serveur,
  // qui seul connaît le chemin du déploiement — racine de l'hôte, ou `/web` quand kdt-web partage
  // celui du portail. Une base fixée ici demanderait une image par chemin.
  base: "./",
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
