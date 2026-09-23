/**
 * Visual QA at the viewports the submission claims support for.
 *
 * Loads every page of a real, analysed investigation at each size and records
 * three things that a screenshot alone does not show: horizontal overflow,
 * failed network requests, and console errors. The result is written to
 * `local-evidence/visual-qa.json` so the table in FINAL-QUALITY-CHECK.md is a
 * transcript rather than an assertion.
 *
 * Opt-in, like the other artefact-writing specs:
 *   SMS_SCREENSHOTS=1 npx playwright test visual-qa
 */
import { expect, test } from '@playwright/test'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = join(process.cwd(), '..')
const DEMO = join(ROOT, 'demo', 'captures')
const OUT = join(ROOT, 'local-evidence')

const VIEWPORTS = [
  { width: 1920, height: 1080 },
  { width: 1600, height: 1000 },
  { width: 1440, height: 900 },
  { width: 1280, height: 720 },
]

const ROUTES = [
  '/', '/investigations', '/sessions', '/findings',
  '/intelligence', '/timeline', '/ml', '/reports', '/settings',
]

const CAPTURES = [
  '01-secure-baseline.pcap', '02-weak-legacy-tls.pcap', '03-broken-cipher.pcap',
  '06-tls12-certificate.pcap', '07-tls13-encrypted-certificate.pcap',
  '08-drift-1-b1_tls12.pcap', '08-drift-2-b2_tls10.pcap',
]

interface Row {
  viewport: string
  route: string
  document_width: number
  overflow_px: number
  failed_requests: number
  console_errors: string[]
}

test('no overflow, no failed request and no console error at any supported size', async ({ page }) => {
  test.setTimeout(420_000)
  mkdirSync(OUT, { recursive: true })

  const consoleErrors: string[] = []
  const failedRequests: string[] = []
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()) })
  page.on('pageerror', (e) => consoleErrors.push(String(e)))
  page.on('requestfailed', (r) => failedRequests.push(r.url()))
  page.on('response', (r) => { if (r.status() >= 400) failedRequests.push(`${r.status()} ${r.url()}`) })

  // One real analysis, so every page has something to render.
  await page.setViewportSize(VIEWPORTS[0])
  await page.goto('/investigations')
  await page.setInputFiles('[data-testid="file-input"]', CAPTURES.map((name) => ({
    name, mimeType: 'application/octet-stream', buffer: readFileSync(join(DEMO, name)),
  })))
  await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
  await page.getByTestId('analyse-button').click()
  await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 180_000 })
  const investigation = page.url().split('/investigations/')[1].split('?')[0]

  const rows: Row[] = []
  for (const viewport of VIEWPORTS) {
    await page.setViewportSize(viewport)
    for (const route of [...ROUTES, `/investigations/${investigation}`]) {
      consoleErrors.length = 0
      failedRequests.length = 0
      await page.goto(route, { waitUntil: 'networkidle' })
      await page.waitForTimeout(450)
      const width = await page.evaluate(() => document.documentElement.scrollWidth)
      rows.push({
        viewport: `${viewport.width}x${viewport.height}`,
        route,
        document_width: width,
        overflow_px: Math.max(0, width - viewport.width),
        failed_requests: failedRequests.length,
        console_errors: [...consoleErrors],
      })
    }
  }

  writeFileSync(
    join(OUT, 'visual-qa.json'),
    JSON.stringify(
      {
        schema: 'smsvisualqa/1',
        what_this_is:
          'Horizontal overflow, failed requests and console errors for every ' +
          'page at every supported viewport, measured in a real browser ' +
          'against the real backend.',
        recorded_at: new Date().toISOString(),
        rows,
      },
      null,
      2,
    ) + '\n',
  )

  // The claim the submission makes, asserted rather than merely recorded.
  for (const row of rows) {
    expect(row.overflow_px, `${row.route} at ${row.viewport} overflows`).toBe(0)
    expect(row.failed_requests, `${row.route} at ${row.viewport} had a failed request`).toBe(0)
    expect(row.console_errors, `${row.route} at ${row.viewport} logged an error`).toEqual([])
  }
})
