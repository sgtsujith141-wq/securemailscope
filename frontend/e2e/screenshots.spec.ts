/**
 * Capture genuine screenshots of the running application.
 *
 * Written to a gitignored directory outside the repository's tracked tree, so
 * real application state is never committed. Run with:
 *
 *   npx playwright test screenshots --grep-invert nothing
 */
import { expect, test } from '@playwright/test'
import { readFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'

const OUT = join(process.cwd(), '..', 'local-evidence', 'screenshots')
const FIXTURES = join(process.cwd(), '..', 'tests', 'fixtures', 'generated')

test.describe.configure({ mode: 'serial' })

test('capture application screenshots', async ({ page }) => {
  mkdirSync(OUT, { recursive: true })
  await page.setViewportSize({ width: 1440, height: 1100 })

  // Two captures, so drift and correlation have something to show.
  await page.goto('/investigations')
  await page.setInputFiles('[data-testid="file-input"]', [
    {
      name: 'aa_tls10_static_rsa.pcap',
      mimeType: 'application/octet-stream',
      buffer: readFileSync(join(FIXTURES, 'aa_tls10_static_rsa.pcap')),
    },
    {
      name: 't_a_tls12_complete_handshake.pcap',
      mimeType: 'application/octet-stream',
      buffer: readFileSync(join(FIXTURES, 't_a_tls12_complete_handshake.pcap')),
    },
  ])
  await expect(page.getByText('ACCEPTED').first()).toBeVisible()
  await page.screenshot({ path: join(OUT, '01-upload.png'), fullPage: true })

  await page.getByTestId('analyse-button').click()
  await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 60_000 })
  await page.screenshot({ path: join(OUT, '02-investigation.png'), fullPage: true })

  const nav = (name: string) =>
    page.getByRole('navigation').getByRole('link', { name, exact: true }).click()

  await nav('Overview')
  await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible()
  await page.screenshot({ path: join(OUT, '03-overview.png'), fullPage: true })

  await nav('Sessions')
  await expect(page.getByTestId('session-table')).toBeVisible()
  await page.screenshot({ path: join(OUT, '04-sessions.png'), fullPage: true })

  await page.locator('[data-testid="session-table"] a').first().click()
  await expect(page.getByRole('heading', { level: 1, name: 'Session detail' })).toBeVisible()
  await page.screenshot({ path: join(OUT, '05-session-detail.png'), fullPage: true })

  await nav('Security findings')
  await page.getByTestId('finding-row').first().click()
  await page.getByTestId('finding-detail').getByTestId('evidence-toggle').click()
  await expect(page.getByTestId('evidence-panel')).toBeVisible()
  await page.screenshot({ path: join(OUT, '06-finding-evidence.png'), fullPage: true })

  await nav('Cryptographic intelligence')
  await expect(page.getByTestId('tab-fingerprints')).toBeVisible()
  await page.screenshot({ path: join(OUT, '07-intelligence-fingerprints.png'), fullPage: true })
  await page.getByTestId('tab-drift').click()
  await page.waitForTimeout(400)
  await page.screenshot({ path: join(OUT, '08-intelligence-drift.png'), fullPage: true })
  await page.getByTestId('tab-blast_radius').click()
  await page.waitForTimeout(400)
  await page.screenshot({ path: join(OUT, '09-blast-radius.png'), fullPage: true })

  await nav('Evidence timeline')
  await expect(page.getByTestId('timeline-list')).toBeVisible()
  await page.screenshot({ path: join(OUT, '10-timeline.png'), fullPage: true })

  await nav('ML analysis')
  await expect(page.getByText(/deterministic frequency table/i)).toBeVisible()
  await page.screenshot({ path: join(OUT, '11-ml-analysis.png'), fullPage: true })

  await nav('Reports')
  await page.screenshot({ path: join(OUT, '12-reports.png'), fullPage: true })

  await nav('Settings')
  await expect(page.getByTestId('save-settings')).toBeVisible()
  await page.screenshot({ path: join(OUT, '13-settings.png'), fullPage: true })
})
