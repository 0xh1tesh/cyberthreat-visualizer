import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const apiProxy = {
  '/api': {
    target: process.env.VITE_API_PROXY_TARGET || 'http://localhost:5000',
    changeOrigin: true,
  },
}

// https://vitejs.dev/config/
export default defineConfig({
  // Keep the dep cache outside any cloud-synced folder; sync clients lock files mid-rebuild.
  cacheDir: join(tmpdir(), 'osint-globe-vite'),
  plugins: [react(), tailwindcss()],
  server: { proxy: apiProxy },
  preview: { proxy: apiProxy },
  build: {
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        manualChunks: {
          globe: ['globe.gl', 'three'],
          charts: ['recharts'],
          motion: ['motion'],
        },
      },
    },
  },
  test: {
    include: ['src/**/*.test.{js,jsx}', 'server/**/*.test.js'],
    environment: 'node',
  },
})
