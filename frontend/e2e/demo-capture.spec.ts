/**
 * Record the product footage for the demonstration video.
 *
 * Playwright drives the real browser against the real backend over the real
 * forensic engine. Nothing is mocked and the analysis takes as long as it
 * takes.
 *
 * Shots are short on purpose: two to six seconds, then a click, a scroll or a
 * cut. The build script cuts against the beat log written here, so a caption
 * can never describe a screen that is no longer showing, and it is free to
 * reorder -- the finished cut opens on the finding, which is recorded partway
 * through the take.
 *
 *   SMS_SCREENSHOTS=1 npx playwright test demo-capture
 */
import { expect, test } from '@playwright/test'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = join(process.cwd(), '..')
const DEMO = join(ROOT, 'demo', 'captures')
const FOOTAGE = join(ROOT, 'local-evidence', 'footage')
const EXPORTS = join(ROOT, 'local-evidence', 'exports')

type Page = import('@playwright/test').Page
const nav = (page: Page, name: string) =>
  page.getByRole('navigation').getByRole('link', { name, exact: true }).click()

const upload = (name: string) => ({
  name, mimeType: 'application/octet-stream',
  buffer: readFileSync(join(DEMO, name)),
})

const beat = (page: Page, ms = 1000) => page.waitForTimeout(ms)

/** Scroll in small steps, so the recording shows motion rather than a jump. */
async function glide(page: Page, distance: number, steps = 18): Promise<void> {
  const step = Math.round(distance / steps)
  for (let index = 0; index < steps; index += 1) {
    await page.mouse.wheel(0, step)
    await page.waitForTimeout(30)
  }
}

/** Move the pointer along a path, so the cursor is visibly doing something. */
async function sweep(page: Page, points: [number, number][]): Promise<void> {
  for (const [x, y] of points) {
    await page.mouse.move(x, y, { steps: 12 })
    await page.waitForTimeout(100)
  }
}

const CAPTURES = [
  '01-secure-baseline.pcap', '02-weak-legacy-tls.pcap', '03-broken-cipher.pcap',
  '04-starttls-upgrade.pcap', '05-starttls-refused.pcap', '06-tls12-certificate.pcap',
  '07-tls13-encrypted-certificate.pcap', '08-drift-1-b1_tls12.pcap',
  '08-drift-2-b2_tls10.pcap',
]
const DRIFT_PAIR = ['08-drift-1-b1_tls12.pcap', '08-drift-2-b2_tls10.pcap']

test.use({
  video: { mode: 'on', size: { width: 1920, height: 1080 } },
  viewport: { width: 1920, height: 1080 },
})

interface Beat { at_ms: number; id: string }
const beats: Beat[] = []
let started = 0
const mark = (id: string) => { beats.push({ at_ms: Date.now() - started, id }) }

test('record the investigation walkthrough', async ({ page }) => {
  test.setTimeout(480_000)
  mkdirSync(FOOTAGE, { recursive: true })
  mkdirSync(EXPORTS, { recursive: true })

  started = Date.now()
  await page.goto('about:blank')
  await beat(page, 1200)

  // -- what goes in ---------------------------------------------------------
  await page.goto('/')
  await expect(page.getByTestId('first-run')).toBeVisible()
  mark('firstrun')
  await sweep(page, [[1100, 380], [700, 330]])
  await beat(page, 2600)

  await nav(page, 'Investigations')
  await beat(page, 700)
  await page.setInputFiles('[data-testid="file-input"]', CAPTURES.map(upload))
  await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
  mark('upload')
  await glide(page, 420, 14)
  await beat(page, 3200)
  await glide(page, -420, 10)

  // -- the analysis itself --------------------------------------------------
  mark('analyse')
  await page.getByTestId('analyse-button').click()
  await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 180_000 })
  await expect(page.getByTestId('posture-hero')).toBeVisible()
  await beat(page, 1400)

  // -- the conclusion -------------------------------------------------------
  mark('overview')
  await sweep(page, [[900, 320], [1470, 340], [1470, 470]])
  await beat(page, 3200)
  await sweep(page, [[340, 360], [560, 360], [800, 360], [1050, 360]])
  await beat(page, 1600)
  mark('modules')
  await glide(page, 620, 16)
  await beat(page, 2600)
  await glide(page, -620, 12)

  // -- the finding: the cut opens here --------------------------------------
  await nav(page, 'Findings')
  await expect(page.getByTestId('findings-list')).toBeVisible()
  await beat(page, 400)
  mark('finding')
  await sweep(page, [[470, 300], [470, 400]])
  await beat(page, 2400)
  await page.getByTestId('finding-row').first().click()
  await expect(page.getByTestId('finding-detail')).toBeVisible()
  await beat(page, 500)
  mark('finding-detail')
  await sweep(page, [[1250, 380], [1250, 470]])
  await beat(page, 3000)

  // -- the packets ----------------------------------------------------------
  await page.getByTestId('finding-detail').getByTestId('evidence-toggle').click()
  await expect(page.getByTestId('evidence-panel')).toBeVisible()
  await beat(page, 500)
  await glide(page, 430, 14)
  await beat(page, 600)
  mark('evidence')
  await sweep(page, [[820, 470], [1180, 470], [1560, 470]])
  await beat(page, 2600)
  await sweep(page, [[820, 525], [1180, 525], [1560, 525]])
  mark('verify')
  await beat(page, 2800)
  await sweep(page, [[900, 600], [1320, 600]])
  await beat(page, 2000)
  await glide(page, -430, 12)

  // -- what it will not guess ----------------------------------------------
  await nav(page, 'Sessions')
  await expect(page.getByTestId('session-table')).toBeVisible()
  await page.getByRole('button', { name: /^TLS/ }).click()
  await beat(page, 900)
  // The TLS 1.3 session: its certificate is encrypted on the wire.
  const tls13 = page.locator('[data-testid="session-table"] tbody tr', {
    hasText: 'TLS 1.3',
  }).first()
  await tls13.locator('a').first().click()
  await expect(page.getByTestId('negotiation-chain')).toBeVisible()
  await beat(page, 500)
  mark('tls13')
  await sweep(page, [[420, 320], [900, 320], [1400, 320], [1700, 320]])
  await beat(page, 2200)
  await glide(page, 980, 20)
  await beat(page, 3400)
  await glide(page, 620, 14)
  await beat(page, 2600)

  // -- drift: a second investigation over the pair --------------------------
  // Its own beat: building the second investigation takes about ten seconds,
  // and without a mark here the previous caption stays on screen describing a
  // page that has already gone.
  await nav(page, 'Investigations')
  mark('drift-setup')
  await page.setInputFiles('[data-testid="file-input"]', DRIFT_PAIR.map(upload))
  await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
  await beat(page, 900)
  await page.getByTestId('analyse-button').click()
  await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 180_000 })
  await expect(page.getByTestId('posture-hero')).toBeVisible()
  await beat(page, 1600)
  await nav(page, 'Intelligence')
  await page.getByTestId('tab-drift').click()
  await expect(page.getByTestId('drift-table')).toBeVisible()
  await beat(page, 600)
  mark('drift')
  await sweep(page, [[500, 330], [1000, 330], [1500, 330]])
  await beat(page, 3000)
  await sweep(page, [[420, 420], [900, 420], [1500, 420]])
  await beat(page, 3400)
  await glide(page, 380, 12)
  await beat(page, 2400)
  await glide(page, -380, 10)

  // -- the report leaves the tool -------------------------------------------
  // Back to the main investigation first: the drift pair is a side trip, and
  // a report exported while it is selected would describe two captures while
  // the rest of the cut -- and the deck -- describe nine.
  await nav(page, 'Investigations')
  await page.getByRole('link', { name: 'Investigation of 9 captures' }).click()
  await expect(page.getByTestId('posture-hero')).toBeVisible()
  await beat(page, 700)
  await nav(page, 'Reports')
  await expect(page.getByTestId('export-pdf')).toBeVisible()
  await beat(page, 500)
  mark('report')
  await sweep(page, [[900, 300], [1215, 240], [1215, 440]])
  await beat(page, 1600)
  const [pdf] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId('export-pdf').click(),
  ])
  await pdf.saveAs(join(EXPORTS, 'securemailscope-report.pdf'))
  await beat(page, 2200)
  const [html] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId('export-html').click(),
  ])
  const htmlPath = join(EXPORTS, 'securemailscope-report.html')
  await html.saveAs(htmlPath)
  await beat(page, 1800)

  // -- closing montage ------------------------------------------------------
  mark('montage')
  await nav(page, 'Overview')
  await beat(page, 1700)
  await nav(page, 'Evidence timeline')
  await expect(page.getByTestId('timeline-list')).toBeVisible()
  await beat(page, 1700)
  await nav(page, 'ML & analytics')
  await beat(page, 1700)
  await nav(page, 'Findings')
  await beat(page, 1900)
  mark('end')
  await beat(page, 1400)

  writeFileSync(
    join(FOOTAGE, 'beats.json'),
    JSON.stringify({
      schema: 'smsbeats/3',
      what_this_is:
        'Millisecond offsets, from the first recorded frame, of each shot the '
        + 'finished cut uses. Measured during the recording.',
      recorded_at: new Date().toISOString(),
      total_ms: Date.now() - started,
      exported_pdf: 'local-evidence/exports/securemailscope-report.pdf',
      exported_html: 'local-evidence/exports/securemailscope-report.html',
      beats,
    }, null, 2) + '\n',
  )
})
