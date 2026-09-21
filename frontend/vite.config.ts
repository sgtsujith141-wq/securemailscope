import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dev server proxies /api to the local backend, so the browser talks to
// one origin and the CORS allowlist stays small. The token is injected by the
// proxy from the environment, which is why it is never in committed source.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: process.env.SMS_API ?? 'http://127.0.0.1:8765',
        changeOrigin: false,
        configure: (proxy) => {
          const token = process.env.SMS_API_TOKEN
          if (token) {
            proxy.on('proxyReq', (proxyReq) => {
              proxyReq.setHeader('x-securemailscope-token', token)
            })
          }
        },
      },
    },
  },
  build: { outDir: 'dist', sourcemap: false, target: 'es2020' },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    // Vitest and Playwright both claim `*.spec.ts`. Without this, vitest
    // collects the browser specs, fails to load them (they import Playwright's
    // own runner) and reports failing *files* while still printing "32 passed"
    // for the unit tests -- a green-looking summary over a broken run.
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
  },
})
