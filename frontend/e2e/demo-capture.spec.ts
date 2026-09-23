/**
 * Record genuine product footage for the demonstration video.
 *
 * Playwright records the real browser driving the real backend over the real
 * forensic engine on the synthetic demo dataset. Nothing is mocked, no output
 * is staged, and the analysis takes exactly as long as it takes.
 *
 * Opt-in, like the screenshot and rehearsal specs:
 *   SMS_SCREENSHOTS=1 npx playwright test demo-capture
 *
 * Video lands in local-evidence/footage/, which is gitignored: raw footage is
 * large and is an input to editing, not a submission artefact.
 */
import { expect, test } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = join(process.cwd(), '..')
const DEMO = join(ROOT, 'demo', 'captures')

type Page = import('@playwright/test').Page
const nav = (page: Page, name: string) =>
  page.getByRole('navigation').getByRole('link', { name, exact: true }).click()

const upload = (name: string) => ({
  name,
  mimeType: 'application/octet-stream',
  buffer: readFileSync(join(DEMO, name)),
})

/** A held beat, so a cut has something to land on. */
const beat = (page: Page, ms = 1400) => page.waitForTimeout(ms)

test.use({
  video: { mode: 'on', size: { width: 1920, height: 1080 } },
  viewport: { width: 1920, height: 1080 },
})

test('record the investigation walkthrough', async ({ page }) => {
  test.setTimeout(300_000)

  // -- the first-run screen ------------------------------------------------
  await page.goto('/')
  await expect(page.getByRole('navigation')).toBeVisible()
  await beat(page, 2200)

  // -- upload and analyse, at real speed -----------------------------------
  await nav(page, 'Investigations')
  await beat(page, 900)
  await page.setInputFiles('[data-testid="file-input"]', [
    upload('02-weak-legacy-tls.pcap'),
  ])
  await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
  await beat(page, 1200)

  await page.getByTestId('analyse-button').click()
  await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 120_000 })
  await beat(page, 2600)

  // -- the finding, and the packets behind it ------------------------------
  await nav(page, 'Findings')
  await expect(page.getByTestId('findings-list')).toBeVisible()
  await beat(page, 1200)
  await page.getByTestId('finding-row').first().click()
  await expect(page.getByTestId('finding-detail')).toBeVisible()
  await beat(page, 2200)
  await page.getByTestId('finding-detail').getByTestId('evidence-toggle').click()
  await expect(page.getByTestId('evidence-panel')).toBeVisible()
  await beat(page, 3000)

  // -- the TLS 1.3 limitation ----------------------------------------------
  await nav(page, 'Investigations')
  await page.setInputFiles('[data-testid="file-input"]', [
    upload('07-tls13-encrypted-certificate.pcap'),
  ])
  await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
  await page.getByTestId('analyse-button').click()
  await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 120_000 })
  await nav(page, 'Sessions')
  await expect(page.getByTestId('session-table')).toBeVisible()
  await page.locator('[data-testid="session-table"] a').first().click()
  await expect(page.getByRole('heading', { level: 1, name: 'Session detail' })).toBeVisible()
  await beat(page, 3200)

  // -- drift across two captures -------------------------------------------
  await nav(page, 'Investigations')
  await page.setInputFiles('[data-testid="file-input"]', [
    upload('08-drift-1-b1_tls12.pcap'),
    upload('08-drift-2-b2_tls10.pcap'),
  ])
  await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
  await page.getByTestId('analyse-button').click()
  await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 120_000 })
  await nav(page, 'Intelligence')
  await page.getByTestId('tab-drift').click()
  await beat(page, 3400)

  // -- export ---------------------------------------------------------------
  await nav(page, 'Reports')
  await beat(page, 1200)
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId('export-pdf').click(),
  ])
  expect(await download.path()).toBeTruthy()
  await beat(page, 2000)
})
