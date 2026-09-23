/**
 * The screenshots that go into the submission deck and the README.
 *
 * Run against the real backend and the real forensic engine, on the synthetic
 * demo dataset only. Nothing here is staged: every number in every image was
 * produced by the engine during this run. If a step cannot find what it is
 * looking for, the run fails rather than quietly writing a prettier image.
 *
 * The names are the ones the submission package refers to, so re-running this
 * replaces the set in place.
 *
 *   npx playwright test submission-shots
 */
import { expect, test } from '@playwright/test'
import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = join(process.cwd(), '..')
const OUT = join(ROOT, 'submission', 'assets', 'screenshots-final')
const DEMO = join(ROOT, 'demo', 'captures')

/** The full synthetic dataset, analysed as one investigation. */
const CAPTURES = [
  '01-secure-baseline.pcap',
  '02-weak-legacy-tls.pcap',
  '03-broken-cipher.pcap',
  '04-starttls-upgrade.pcap',
  '05-starttls-refused.pcap',
  '06-tls12-certificate.pcap',
  '07-tls13-encrypted-certificate.pcap',
  '08-drift-1-b1_tls12.pcap',
  '08-drift-2-b2_tls10.pcap',
]

type Page = import('@playwright/test').Page

const nav = (page: Page, name: string) =>
  page.getByRole('navigation').getByRole('link', { name, exact: true }).click()

async function shot(page: Page, file: string): Promise<void> {
  // Settle the layout: Recharts measures its container on a resize observer,
  // and a shot taken in the same frame catches a chart mid-measure.
  await page.waitForTimeout(500)
  await page.screenshot({ path: join(OUT, `${file}.png`), fullPage: true })
}

test('submission screenshots on the synthetic demo dataset', async ({ page }) => {
  test.setTimeout(300_000)
  mkdirSync(OUT, { recursive: true })
  await page.setViewportSize({ width: 1920, height: 1080 })

  // -- 01 the application before anything has been analysed ----------------
  await page.goto('/')
  await expect(page.getByTestId('first-run')).toBeVisible()
  await shot(page, '01-landing')

  // -- analyse the whole demo dataset as one investigation -----------------
  await nav(page, 'Investigations')
  await page.setInputFiles(
    '[data-testid="file-input"]',
    CAPTURES.map((name) => ({
      name,
      mimeType: 'application/octet-stream',
      buffer: readFileSync(join(DEMO, name)),
    })),
  )
  await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
  await page.getByTestId('analyse-button').click()
  await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 180_000 })

  // -- 02 the investigation dashboard --------------------------------------
  await expect(page.getByTestId('posture-hero')).toBeVisible()
  await expect(page.getByTestId('crypto-modules')).toBeVisible()
  await expect(page.getByTestId('session-posture-strip')).toBeVisible()
  await shot(page, '02-overview')

  // -- 03 the findings workspace, master and detail ------------------------
  await nav(page, 'Findings')
  await expect(page.getByTestId('findings-list')).toBeVisible()
  await expect(page.getByTestId('finding-detail')).toBeVisible()
  await shot(page, '03-findings')

  // -- 04 a finding with its packet evidence open --------------------------
  await page.getByTestId('finding-row').first().click()
  const detail = page.getByTestId('finding-detail')
  await expect(detail).toBeVisible()
  await detail.getByTestId('evidence-toggle').click()
  const evidence = page.getByTestId('evidence-panel')
  await expect(evidence).toBeVisible()
  await shot(page, '04-finding-evidence')

  // -- 06 the provenance of that evidence, on its own ----------------------
  // Same panel, scrolled to: packet number, timestamp, stream offset and the
  // observation each reference came from.
  await evidence.scrollIntoViewIfNeeded()
  await page.waitForTimeout(300)
  await page.screenshot({ path: join(OUT, '06-evidence-provenance.png') })

  // -- 05 a session, and where its handshake is weak -----------------------
  await nav(page, 'Sessions')
  await expect(page.getByTestId('session-table')).toBeVisible()
  // The weakest session first, so the negotiation chain has something to
  // show. The column header is a button inside the <th>; clicking the <th>
  // itself does nothing.
  await page.getByRole('button', { name: /^Assessment/ }).click()
  await page.waitForTimeout(600)
  await page.locator('[data-testid="session-table"] a').first().click()
  await expect(page.getByRole('heading', { level: 1, name: 'Session detail' })).toBeVisible()
  await expect(page.getByTestId('negotiation-chain')).toBeVisible()
  await shot(page, '05-session')

  // -- 07 cryptographic intelligence ---------------------------------------
  await nav(page, 'Intelligence')
  await expect(page.getByTestId('tab-fingerprints')).toBeVisible()
  await shot(page, '07-crypto-intelligence')

  // -- 08 drift, before and after ------------------------------------------
  await page.getByTestId('tab-drift').click()
  await expect(page.getByTestId('drift-table')).toBeVisible()
  await shot(page, '08-drift')

  // -- 09 the evidence timeline --------------------------------------------
  await nav(page, 'Evidence timeline')
  await expect(page.getByTestId('timeline-list')).toBeVisible()
  await shot(page, '09-timeline')

  // -- 10 machine learning, with its stated limits -------------------------
  await nav(page, 'ML & analytics')
  await expect(page.getByText(/deterministic frequency table/i)).toBeVisible()
  await shot(page, '10-ml')

  // -- 11 report export ----------------------------------------------------
  await nav(page, 'Reports')
  await expect(page.getByTestId('export-pdf')).toBeVisible()
  await shot(page, '11-reports')

  // The PDF itself is exported here so `scripts/render_report_page.py` has a
  // real report to rasterise for `12-pdf.png`.
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId('export-pdf').click(),
  ])
  await download.saveAs(join(ROOT, 'local-evidence', 'submission-report.pdf'))
})
