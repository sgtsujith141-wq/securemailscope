/**
 * Record the product footage for the demonstration video.
 *
 * Playwright drives the real browser against the real backend over the real
 * forensic engine. Nothing is mocked and the analysis takes as long as it
 * takes.
 *
 * **One video per section.** A single long recording cannot be cut reliably:
 * Playwright drops frames while the page is busy, so ninety seconds of wall
 * clock become seventy-five seconds of video and a wall-clock offset no
 * longer points at the right frame. Each section therefore gets its own
 * browser context and its own file, and the build concatenates whole files
 * instead of seeking into one. State survives because it lives in the
 * backend: each section navigates straight to the investigation it needs.
 *
 *   SMS_SCREENSHOTS=1 npx playwright test demo-capture
 */
import { expect, test } from '@playwright/test'
import { mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = join(process.cwd(), '..')
const DEMO = join(ROOT, 'demo', 'captures')
const FOOTAGE = join(ROOT, 'local-evidence', 'footage')
const EXPORTS = join(ROOT, 'local-evidence', 'exports')

type Page = import('@playwright/test').Page
type Browser = import('@playwright/test').Browser

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

//: The investigation the presentation walks through: the deliberately weak
//: capture that carries TLS-KEX-001, plus the TLS 1.3 capture whose
//: certificate a passive observer cannot read. It scores 59/100 WEAK, the
//: same figure the deck shows.
const CAPTURES = ['02-weak-legacy-tls.pcap', '07-tls13-encrypted-certificate.pcap']
const DRIFT_PAIR = ['08-drift-1-b1_tls12.pcap', '08-drift-2-b2_tls10.pcap']

const sections: { name: string; seconds: number }[] = []

/** Record one section into its own file, named for the shot it provides. */
async function section(
  browser: Browser, name: string, entry: string, body: (page: Page) => Promise<void>,
): Promise<void> {
  const dir = join(FOOTAGE, 'raw')
  mkdirSync(dir, { recursive: true })
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    recordVideo: { dir, size: { width: 1920, height: 1080 } },
    acceptDownloads: true,
  })
  const page = await context.newPage()
  const started = Date.now()
  // Straight to the screen this section is about: one navigation, not two.
  // The build trims the load itself off the head of the clip.
  await page.goto(entry)
  await expect(page.getByRole('navigation')).toBeVisible()
  await beat(page, 700)
  await body(page)
  await beat(page, 400)
  const video = page.video()
  await context.close()
  if (video) {
    renameSync(await video.path(), join(FOOTAGE, `${name}.webm`))
  }
  sections.push({ name, seconds: (Date.now() - started) / 1000 })
  console.log(`  recorded ${name}`)
}

test('record the presentation walkthrough', async ({ browser }) => {
  test.setTimeout(600_000)
  mkdirSync(FOOTAGE, { recursive: true })
  mkdirSync(EXPORTS, { recursive: true })
  rmSync(join(FOOTAGE, 'raw'), { recursive: true, force: true })
  for (const file of readdirSync(FOOTAGE).filter((f) => f.endsWith('.webm'))) {
    rmSync(join(FOOTAGE, file))
  }

  let investigation = ''
  let driftInvestigation = ''

  // -- what the tool is, before anything is loaded --------------------------
  await section(browser, 'firstrun', '/', async (page) => {
    await expect(page.getByTestId('first-run')).toBeVisible()
    await beat(page, 2600)
    await sweep(page, [[1100, 380], [760, 340], [520, 330]])
    await beat(page, 2600)
    await glide(page, 300, 12)
    await beat(page, 2600)
    await glide(page, 320, 12)
    await sweep(page, [[600, 520], [1080, 520], [1500, 520]])
    await beat(page, 2600)
    await glide(page, -620, 16)
    await beat(page, 2600)
  })

  // -- the captures going in, and the analysis at its real speed ------------
  // One recording: the staged upload list is component state, so a second
  // context would open on an empty queue with nothing to analyse.
  await section(browser, 'upload', '/investigations', async (page) => {
    await expect(page.getByTestId('file-input')).toBeAttached()
    await beat(page, 2600)
    await page.setInputFiles('[data-testid="file-input"]', CAPTURES.map(upload))
    await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
    await sweep(page, [[700, 420], [1100, 420], [1460, 420]])
    await beat(page, 2400)
    await glide(page, 240, 10)
    await sweep(page, [[700, 470], [1180, 470]])
    await beat(page, 2600)
    await glide(page, -240, 10)
    await beat(page, 1600)
    await expect(page.getByTestId('analyse-button')).toBeVisible()
    await page.getByTestId('analyse-button').click()
    await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 180_000 })
    await expect(page.getByTestId('posture-hero')).toBeVisible()
    investigation = page.url().split('/investigations/')[1].split('?')[0]
    await sweep(page, [[900, 320], [1400, 340]])
    await beat(page, 3000)
  })

  // -- the conclusion ---------------------------------------------------------
  await section(browser, 'overview', `/investigations/${investigation}`, async (page) => {
    await expect(page.getByTestId('posture-hero')).toBeVisible()
    await sweep(page, [[900, 320], [1470, 340], [1470, 470]])
    await beat(page, 3400)
    await sweep(page, [[340, 360], [600, 360]])
    await beat(page, 2000)
  })

  await section(browser, 'modules', `/investigations/${investigation}`, async (page) => {
    await expect(page.getByTestId('crypto-modules')).toBeVisible()
    await glide(page, 620, 16)
    await beat(page, 3000)
    await sweep(page, [[460, 430], [960, 430], [1460, 430]])
    await beat(page, 2600)
    await glide(page, 520, 14)
    await beat(page, 2600)
    await sweep(page, [[520, 500], [1100, 500]])
    await beat(page, 2400)
  })

  // -- the finding ------------------------------------------------------------
  await section(browser, 'finding', `/investigations/${investigation}`, async (page) => {
    await nav(page, 'Findings')
    await expect(page.getByTestId('findings-list')).toBeVisible()
    await sweep(page, [[470, 300], [470, 400]])
    await beat(page, 2400)
    await sweep(page, [[470, 470], [470, 540]])
    await beat(page, 2400)
  })

  await section(browser, 'finding-detail', `/investigations/${investigation}`, async (page) => {
    await nav(page, 'Findings')
    await expect(page.getByTestId('findings-list')).toBeVisible()
    await page.getByTestId('finding-row').first().click()
    await expect(page.getByTestId('finding-detail')).toBeVisible()
    await sweep(page, [[1250, 360], [1250, 450]])
    await beat(page, 3000)
    await glide(page, 240, 10)
    await sweep(page, [[900, 470], [1400, 470]])
    await beat(page, 3000)
    await glide(page, 220, 10)
    await beat(page, 2800)
  })

  // -- the packets behind it ---------------------------------------------------
  await section(browser, 'evidence', `/investigations/${investigation}`, async (page) => {
    await nav(page, 'Findings')
    await page.getByTestId('finding-row').first().click()
    await page.getByTestId('finding-detail').getByTestId('evidence-toggle').click()
    await expect(page.getByTestId('evidence-panel')).toBeVisible()
    await glide(page, 430, 14)
    await beat(page, 1800)
    await sweep(page, [[820, 470], [1180, 470], [1560, 470]])
    await beat(page, 3200)
    await sweep(page, [[820, 525], [1180, 525], [1560, 525]])
    await beat(page, 3200)
    await glide(page, 160, 8)
    await beat(page, 2400)
  })

  await section(browser, 'verify', `/investigations/${investigation}`, async (page) => {
    await nav(page, 'Findings')
    await page.getByTestId('finding-row').first().click()
    await page.getByTestId('finding-detail').getByTestId('evidence-toggle').click()
    await expect(page.getByTestId('evidence-panel')).toBeVisible()
    await glide(page, 430, 14)
    await beat(page, 1600)
    await sweep(page, [[820, 525], [1180, 525], [1560, 525]])
    await beat(page, 3400)
    await sweep(page, [[900, 560], [1400, 560]])
    await beat(page, 3000)
  })

  // -- what it will not guess ---------------------------------------------------
  await section(browser, 'tls13', `/investigations/${investigation}`, async (page) => {
    await nav(page, 'Sessions')
    await expect(page.getByTestId('session-table')).toBeVisible()
    const tls13 = page.locator('[data-testid="session-table"] tbody tr', {
      hasText: 'TLS 1.3',
    }).first()
    await tls13.locator('a').first().click()
    await expect(page.getByTestId('negotiation-chain')).toBeVisible()
    await sweep(page, [[420, 320], [900, 320], [1400, 320], [1700, 320]])
    await beat(page, 3000)
    await glide(page, 520, 14)
    await sweep(page, [[520, 430], [1080, 430]])
    await beat(page, 3200)
    await glide(page, 480, 14)
    await beat(page, 3400)
    await sweep(page, [[640, 500], [1240, 500], [1640, 500]])
    await beat(page, 3400)
    await glide(page, 300, 10)
    await beat(page, 3000)
  })

  // -- a second observation of the same service ---------------------------------
  await section(browser, 'drift-setup', '/investigations', async (page) => {
    await page.setInputFiles('[data-testid="file-input"]', DRIFT_PAIR.map(upload))
    await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
    await beat(page, 900)
    await page.getByTestId('analyse-button').click()
    await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 180_000 })
    await expect(page.getByTestId('posture-hero')).toBeVisible()
    driftInvestigation = page.url().split('/investigations/')[1].split('?')[0]
    await beat(page, 2000)
  })

  await section(browser, 'drift', `/investigations/${driftInvestigation}`, async (page) => {
    await nav(page, 'Intelligence')
    await page.getByTestId('tab-drift').click()
    await expect(page.getByTestId('drift-table')).toBeVisible()
    await sweep(page, [[500, 330], [1000, 330], [1500, 330]])
    await beat(page, 3200)
    await sweep(page, [[420, 420], [900, 420], [1500, 420]])
    await beat(page, 3200)
    await glide(page, 300, 12)
    await sweep(page, [[520, 480], [1120, 480], [1620, 480]])
    await beat(page, 3400)
    await glide(page, 240, 10)
    await beat(page, 3200)
    await sweep(page, [[600, 420], [1200, 420]])
    await beat(page, 2000)
  })

  // -- the report leaves the tool -------------------------------------------------
  await section(browser, 'report', `/investigations/${investigation}`, async (page) => {
    await nav(page, 'Reports')
    await expect(page.getByTestId('export-pdf')).toBeVisible()
    await sweep(page, [[900, 300], [1215, 240], [1215, 440]])
    await beat(page, 2200)
    await glide(page, 220, 10)
    await beat(page, 2000)
    await glide(page, -220, 10)
    await beat(page, 1400)
    const [pdf] = await Promise.all([
      page.waitForEvent('download'),
      page.getByTestId('export-pdf').click(),
    ])
    await pdf.saveAs(join(EXPORTS, 'securemailscope-report.pdf'))
    await beat(page, 2000)
    const [html] = await Promise.all([
      page.waitForEvent('download'),
      page.getByTestId('export-html').click(),
    ])
    await html.saveAs(join(EXPORTS, 'securemailscope-report.html'))
    await beat(page, 2200)
  })

  // -- closing -------------------------------------------------------------------
  await section(browser, 'montage', `/investigations/${investigation}`, async (page) => {
    await expect(page.getByTestId('posture-hero')).toBeVisible()
    await beat(page, 2200)
    await nav(page, 'Evidence timeline')
    await expect(page.getByTestId('timeline-list')).toBeVisible()
    await expect(page.getByTestId('timeline-list').locator('li').first())
      .toBeVisible()
    await beat(page, 3000)
    await glide(page, 260, 10)
    await beat(page, 2200)
    await nav(page, 'Findings')
    await beat(page, 2600)
    await glide(page, 240, 10)
    await beat(page, 2200)
  })

  rmSync(join(FOOTAGE, 'raw'), { recursive: true, force: true })
  writeFileSync(
    join(FOOTAGE, 'sections.json'),
    JSON.stringify({
      schema: 'smssections/1',
      what_this_is:
        'One recording per shot. The build concatenates whole files, so no '
        + 'wall-clock offset has to be mapped onto a video timeline that '
        + 'dropped frames.',
      recorded_at: new Date().toISOString(),
      investigation,
      drift_investigation: driftInvestigation,
      exported_pdf: 'local-evidence/exports/securemailscope-report.pdf',
      exported_html: 'local-evidence/exports/securemailscope-report.html',
      sections,
    }, null, 2) + '\n',
  )
})
