import { defineConfig } from "vite";

// Tauri injeta TAURI_DEV_HOST em dev com --host; fora isso serve em localhost.
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  clearScreen: false,
  server: {
    port: 5273,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 5274 } : undefined,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  build: {
    // WebView2 no Windows 11 é Chromium recente; podemos mirar alto.
    target: "chrome110",
    minify: "esbuild",
    sourcemap: false,
  },
});
