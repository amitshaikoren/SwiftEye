import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@':           fileURLToPath(new URL('./src',              import.meta.url)),
      '@core':       fileURLToPath(new URL('./src/core',         import.meta.url)),
      '@workspaces': fileURLToPath(new URL('./src/workspaces',   import.meta.url)),
    },
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8642',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1024, // single-page app, D3 + OUI table make 900KB+ expected
  },
});
