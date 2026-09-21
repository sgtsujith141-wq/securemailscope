import { defineConfig } from '@playwright/test'

/**
 * End-to-end configuration.
 *
 * The backend is the real FastAPI application over the real forensic engine,
 * started by `e2e/start-backend.mjs`. Nothing is mocked: §23 requires the
 * final acceptance test to run against the genuine stack.
 */
export default defineConfig({
  testDir: './e2e',
  // Screenshot capture is opt-in: it writes real application state to a
  // gitignored directory and is not part of the acceptance run.
  testIgnore: process.env.SMS_SCREENSHOTS ? [] : ['screenshots.spec.ts'],
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:5173',
    headless: true,
    trace: 'off',
    screenshot: 'only-on-failure',
  },
  webServer: [
    {
      command: 'node e2e/start-backend.mjs',
      url: 'http://127.0.0.1:8799/api/health',
      reuseExistingServer: false,
      timeout: 60_000,
      stdout: 'pipe',
      stderr: 'pipe',
    },
    {
      command: 'node e2e/start-frontend.mjs',
      url: 'http://127.0.0.1:5173',
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
})
