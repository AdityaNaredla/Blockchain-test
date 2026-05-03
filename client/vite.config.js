import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // No proxy — we use VITE_API_URL with credentials: 'include'.
    // The server allows the dev origin via ALLOWED_ORIGINS.
  },
});
