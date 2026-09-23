/**
 * Record genuine product footage for the demonstration video.
 *
 * Playwright drives the real browser against the real backend over the real
 * forensic engine. Nothing is mocked, no output is staged, and the analysis
 * takes exactly as long as it takes.
 *
 * Alongside the video this writes a beat log: the millisecond at which each
 * narrated moment begins, measured from the first frame. `scripts/
 * build_demo_video.py` cuts and captions against those real timings rather
 * than against a script written in advance, so a caption can never describe
 * something the footage is not showing.
 *
 *   SMS_SCREENSHOTS=1 npx playwright test demo-capture
 *
 * Video lands in local-evidence/footage/, which is gitignored: raw footage is
 * large and is an input to editing, not a submission artefact.
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
  name,
  mimeType: 'application/octet-stream',
  buffer: readFileSync(join(DEMO, name)),
})

/** A held beat, so a cut has something to land on. */
const beat = (page: Page, ms = 1200) => page.waitForTimeout(ms)

/**
 * Scroll in small steps rather than one jump.
 *
 * A single large wheel event teleports the page and the recording shows two
 * static frames with nothing between them. Stepping produces real motion,
 * which is what a viewer reads as "someone is using this".
 */
async function glide(page: Page, distance: number, steps = 22): Promise<void> {
  const step = Math.round(distance / steps)
  for (let index = 0; index < steps; index += 1) {
    await page.mouse.wheel(0, step)
    await page.waitForTimeout(34)
  }
}

/** Move the pointer along a path, so the cursor is visibly doing something. */
async function sweep(page: Page, points: [number, number][]): Promise<void> {
  for (const [x, y] of points) {
    await page.mouse.move(x, y, { steps: 14 })
    await page.waitForTimeout(120)
  }
}

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

test.use({
  video: { mode: 'on', size: { width: 1920, height: 1080 } },
  viewport: { width: 1920, height: 1080 },
})

interface Beat { at_ms: number; id: string; note: string }
const beats: Beat[] = []
let started = 0

function mark(id: string, note: string): void {
  beats.push({ at_ms: Date.now() - started, id, note })
}

test('record the investigation walkthrough', async ({ page }) => {
  test.setTimeout(480_000)
  mkdirSync(FOOTAGE, { recursive: true })
  mkdirSync(EXPORTS, { recursive: true })

  started = Date.now()
  await page.goto('about:blank')
  await beat(page, 1500)

  // -- 1. the first-run screen ---------------------------------------------
  await page.goto('/')
  await expect(page.getByTestId('first-run')).toBeVisible()
  mark('first-run', 'Passive by design: nothing is contacted, nothing leaves the machine.')
  await sweep(page, [[1200, 400], [700, 520], [672, 322]])
  await beat(page, 1400)

  // -- 2. upload the dataset ------------------------------------------------
  await nav(page, 'Investigations')
  await beat(page, 900)
  await page.setInputFiles('[data-testid="file-input"]', CAPTURES.map(upload))
  await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
  mark('upload', 'Nine synthetic captures go in.')
  await glide(page, 520, 16)
  await beat(page, 1200)

  // -- 3. analysis, at its real speed ---------------------------------------
  mark('analyse', 'Analysis runs locally, against the bytes in the capture.')
  await glide(page, -520, 12)
  await page.getByTestId('analyse-button').click()
  await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 180_000 })
  await expect(page.getByTestId('posture-hero')).toBeVisible()
  await beat(page, 1400)

  // -- 4. the dashboard, scrolled through -----------------------------------
  mark('dashboard', 'Seven high-priority cryptographic issues require attention.')
  await sweep(page, [[900, 330], [1480, 350], [1480, 500]])
  await beat(page, 1200)
  // Along the per-session posture strip, weakest first.
  await sweep(page, [[340, 365], [430, 365], [530, 365], [620, 365], [720, 365],
                     [815, 365], [910, 365], [1005, 365], [1100, 365]])
  await beat(page, 1200)
  mark('modules', 'TLS posture, severity, protocol and certificate health.')
  await glide(page, 640)
  await beat(page, 1600)
  mark('rows', 'Priority findings beside the evidence timeline they came from.')
  await glide(page, 620)
  await beat(page, 1500)
  await glide(page, 700)
  await beat(page, 1200)
  await glide(page, -1900, 26)

  // -- 5. the findings workspace, driven ------------------------------------
  await nav(page, 'Findings')
  await expect(page.getByTestId('findings-list')).toBeVisible()
  await beat(page, 400)
  mark('findings', 'Every finding names the rule it failed and the session it came from.')
  await sweep(page, [[470, 300], [470, 420], [470, 520]])
  await beat(page, 900)
  // Filter to the high-severity findings, so the list visibly changes.
  await page.getByTestId('severity-filter').selectOption('HIGH')
  await beat(page, 1500)
  await page.getByTestId('category-filter').selectOption('KEY_EXCHANGE')
  await beat(page, 1500)
  await page.getByTestId('category-filter').selectOption('')
  await beat(page, 800)
  await page.getByTestId('severity-filter').selectOption('')
  await beat(page, 900)
  // Move down the list, so the detail pane visibly follows the selection.
  await page.getByTestId('finding-row').nth(3).click()
  await beat(page, 1500)
  await page.getByTestId('finding-row').nth(4).click()
  await beat(page, 1400)

  // -- 6. THE MOMENT: a finding, and packets 4 and 5 ------------------------
  mark('finding-detail', 'Static RSA key exchange: no forward secrecy, under RFC 5246.')
  await page.getByTestId('finding-row').first().click()
  await expect(page.getByTestId('finding-detail')).toBeVisible()
  await sweep(page, [[1300, 400], [1300, 500]])
  await beat(page, 2000)

  mark('evidence', 'And here are the packets the rule was evaluated against.')
  await page.getByTestId('finding-detail').getByTestId('evidence-toggle').click()
  const evidence = page.getByTestId('evidence-panel')
  await expect(evidence).toBeVisible()
  await evidence.scrollIntoViewIfNeeded()
  await beat(page, 700)
  // Lift the packet table into the middle of the frame. The burned-in caption
  // occupies the bottom fifth of the picture, and this is the one shot where
  // something being covered would cost the argument.
  await glide(page, 430, 16)
  await beat(page, 2200)
  // Trace the two packet rows, one at a time.
  await sweep(page, [[820, 470], [1150, 470], [1500, 470], [1790, 470]])
  await beat(page, 2200)
  await sweep(page, [[820, 525], [1150, 525], [1500, 525], [1790, 525]])
  await beat(page, 2400)
  await sweep(page, [[900, 600], [1300, 600]])
  await beat(page, 2000)
  await glide(page, -430, 12)

  // -- 7. the handshake, link by link ---------------------------------------
  await nav(page, 'Sessions')
  await expect(page.getByTestId('session-table')).toBeVisible()
  await page.getByRole('button', { name: /^Assessment/ }).click()
  await beat(page, 1100)
  await page.locator('[data-testid="session-table"] a').first().click()
  await expect(page.getByTestId('negotiation-chain')).toBeVisible()
  await beat(page, 400)
  mark('session', 'The handshake as a chain, tinted where the engine raised a finding.')
  await sweep(page, [[420, 320], [720, 320], [1010, 320], [1300, 320], [1600, 320]])
  await beat(page, 1800)

  mark('tls13', 'Where a capture cannot show something, it says so.')
  await glide(page, 900)
  await beat(page, 1400)
  await glide(page, 900)
  await beat(page, 1600)
  await glide(page, 900)
  await beat(page, 1800)
  await glide(page, 900)
  await beat(page, 1400)

  // -- 8. drift across captures ---------------------------------------------
  await nav(page, 'Intelligence')
  await expect(page.getByTestId('tab-fingerprints')).toBeVisible()
  await beat(page, 400)
  // Its own beat: without one, the previous caption stayed on screen for the
  // five seconds it takes to move through the tabs, describing a page that
  // was no longer showing.
  mark('intelligence', 'Cryptographic fingerprints group configurations, not identities.')
  await sweep(page, [[400, 190], [640, 190], [800, 190]])
  await beat(page, 2000)
  await page.getByTestId('tab-entities').click()
  await beat(page, 2200)
  await page.getByTestId('tab-drift').click()
  await expect(page.getByTestId('drift-table')).toBeVisible()
  await beat(page, 400)
  mark('drift', 'Drift compares the same endpoint across captures, before and after.')
  await beat(page, 1600)
  await glide(page, 620)
  await beat(page, 1500)
  await glide(page, 620)
  await beat(page, 1400)
  await glide(page, -1240, 18)
  await page.getByTestId('tab-correlations').click()
  await beat(page, 1400)
  await page.getByTestId('tab-blast_radius').click()
  await beat(page, 1500)

  // -- 9. the timeline --------------------------------------------------------
  await nav(page, 'Evidence timeline')
  await expect(page.getByTestId('timeline-list')).toBeVisible()
  await beat(page, 400)
  mark('timeline', 'Every event carries its evidence status: observed, or inferred.')
  await beat(page, 900)
  await glide(page, 700)
  await beat(page, 1400)
  await glide(page, 700)
  await beat(page, 1300)
  await glide(page, -1400, 18)
  // Narrow the timeline to one event type, so the list visibly responds.
  await page.getByTestId('event-type-filter').selectOption('CONFIGURATION_DRIFT')
  await beat(page, 1800)
  await page.getByTestId('event-type-filter').selectOption('')
  await beat(page, 1000)

  // -- 10. machine learning, with its limits ---------------------------------
  await nav(page, 'ML & analytics')
  await expect(page.getByText(/deterministic frequency table/i)).toBeVisible()
  await beat(page, 400)
  mark('ml', 'The detector in use is a rarity baseline. The interface says so.')
  await beat(page, 1200)
  await glide(page, 620)
  await beat(page, 1400)
  await glide(page, 760)
  await beat(page, 1500)
  await glide(page, 760)
  await beat(page, 1400)

  // -- 11. export, for real ----------------------------------------------------
  await nav(page, 'Reports')
  await expect(page.getByTestId('export-pdf')).toBeVisible()
  await beat(page, 400)
  mark('reports', 'One canonical model produces JSON, offline HTML and PDF.')
  await sweep(page, [[900, 300], [1220, 240], [1220, 440]])
  await beat(page, 1100)

  const [pdf] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId('export-pdf').click(),
  ])
  const pdfPath = join(EXPORTS, 'securemailscope-report.pdf')
  await pdf.saveAs(pdfPath)
  await beat(page, 1600)

  const [html] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId('export-html').click(),
  ])
  const htmlPath = join(EXPORTS, 'securemailscope-report.html')
  await html.saveAs(htmlPath)
  await beat(page, 1400)

  // -- 12. open the export that was just produced ----------------------------
  // The HTML export is self-contained and loads no external resource, so a
  // file:// URL renders exactly what a reviewer would open. Headless Chromium
  // downloads a PDF rather than displaying it, so the PDF is shown in the cut
  // as a page rasterised from this same downloaded file.

  // The same page navigates to the file, so the recording stays one
  // continuous take -- Playwright records each page separately, and a second
  // tab would land in a second video file. The HTML export is self-contained
  // and loads no external resource, so a file:// URL renders exactly what a
  // reviewer would open. Headless Chromium downloads a PDF rather than
  // displaying it, so the PDF appears in the cut as a page rasterised from
  // this same downloaded file.
  await page.goto(`file://${htmlPath}`)
  await page.waitForTimeout(1600)
  mark('open-report', 'The exported report, opened from disk. Nothing external is fetched.')
  await glide(page, 1400, 30)
  await beat(page, 1500)
  await glide(page, 1600, 28)
  await beat(page, 1500)
  await glide(page, 1800, 28)
  await beat(page, 1600)

  mark('end', 'Passive, local, evidence-backed.')
  await beat(page, 1800)

  writeFileSync(
    join(FOOTAGE, 'beats.json'),
    JSON.stringify(
      {
        schema: 'smsbeats/2',
        what_this_is:
          'Millisecond offsets, from the first recorded frame, of each ' +
          'narrated moment in the walkthrough. Measured during the ' +
          'recording, not written in advance.',
        recorded_at: new Date().toISOString(),
        total_ms: Date.now() - started,
        exported_pdf: 'local-evidence/exports/securemailscope-report.pdf',
        exported_html: 'local-evidence/exports/securemailscope-report.html',
        beats,
      },
      null,
      2,
    ) + '\n',
  )
})
