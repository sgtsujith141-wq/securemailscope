/**
 * Record genuine product footage for the demonstration video.
 *
 * Playwright records the real browser driving the real backend over the real
 * forensic engine on the synthetic demo dataset. Nothing is mocked, no output
 * is staged, and the analysis takes exactly as long as it takes.
 *
 * Alongside the video this writes a beat log: the millisecond at which each
 * narrated moment begins, measured from the first frame. `scripts/
 * build_demo_video.py` cuts and captions against those real timings rather
 * than against a script written in advance, so a caption can never describe
 * something the footage is not showing.
 *
 *   npx playwright test demo-capture
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

/** Every capture in the demo dataset, analysed as one investigation. */
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

/** Mark the current moment as the start of a narrated beat. */
function mark(id: string, note: string): void {
  beats.push({ at_ms: Date.now() - started, id, note })
}

test('record the investigation walkthrough', async ({ page }) => {
  test.setTimeout(420_000)
  mkdirSync(FOOTAGE, { recursive: true })

  // The recording begins when the context opens, a little before the first
  // action. This opening hold absorbs that offset in a static frame so every
  // later beat time is accurate to well under a second.
  started = Date.now()
  await page.goto('about:blank')
  await beat(page, 1800)

  // -- 1. the first-run screen ---------------------------------------------
  mark('first-run', 'Passive by design: nothing is contacted, nothing leaves the machine.')
  await page.goto('/')
  await expect(page.getByTestId('first-run')).toBeVisible()
  await beat(page, 6800)

  // -- 2. upload the dataset ------------------------------------------------
  mark('upload', 'Nine synthetic captures of SMTP, IMAP and POP3 traffic go in.')
  await nav(page, 'Investigations')
  await beat(page, 1200)
  await page.setInputFiles('[data-testid="file-input"]', CAPTURES.map(upload))
  await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
  await beat(page, 5200)

  // -- 3. analysis, at its real speed ---------------------------------------
  mark('analyse', 'Analysis runs locally. No host in the capture is ever contacted.')
  await page.getByTestId('analyse-button').click()
  await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 180_000 })
  await expect(page.getByTestId('posture-hero')).toBeVisible()
  await beat(page, 2000)

  // -- 4. the dashboard ------------------------------------------------------
  mark('dashboard', 'Seven high-priority cryptographic issues require attention.')
  await beat(page, 7400)
  mark('modules', 'TLS posture, severity, protocol and certificate health, per session.')
  await page.mouse.wheel(0, 620)
  await beat(page, 7000)
  mark('rows', 'Priority findings beside the evidence timeline they came from.')
  await page.mouse.wheel(0, 620)
  await beat(page, 6800)
  await page.mouse.wheel(0, -1240)
  await beat(page, 900)

  // -- 5. a finding, and the packets behind it ------------------------------
  mark('findings', 'Every finding names the rule it failed and the session it came from.')
  await nav(page, 'Findings')
  await expect(page.getByTestId('findings-list')).toBeVisible()
  await beat(page, 6200)

  mark('finding-detail', 'Static RSA key exchange: no forward secrecy, under RFC 5246.')
  await page.getByTestId('finding-row').first().click()
  await expect(page.getByTestId('finding-detail')).toBeVisible()
  await beat(page, 7200)

  mark('evidence', 'And here are the packets the rule was evaluated against.')
  await page.getByTestId('finding-detail').getByTestId('evidence-toggle').click()
  await expect(page.getByTestId('evidence-panel')).toBeVisible()
  await beat(page, 7600)

  // -- 6. the handshake, link by link ---------------------------------------
  mark('session', 'The handshake as a chain, tinted where the engine raised a finding.')
  await nav(page, 'Sessions')
  await expect(page.getByTestId('session-table')).toBeVisible()
  await page.getByRole('button', { name: /^Assessment/ }).click()
  await beat(page, 1600)
  await page.locator('[data-testid="session-table"] a').first().click()
  await expect(page.getByTestId('negotiation-chain')).toBeVisible()
  await beat(page, 7800)

  mark('tls13', 'Where a capture cannot show something, it says so.')
  await page.mouse.wheel(0, 1500)
  await beat(page, 7000)

  // -- 7. drift across captures ---------------------------------------------
  mark('drift', 'Drift compares the same endpoint across captures, before and after.')
  await nav(page, 'Intelligence')
  await page.getByTestId('tab-drift').click()
  await expect(page.getByTestId('drift-table')).toBeVisible()
  await beat(page, 8000)

  // -- 8. the timeline -------------------------------------------------------
  mark('timeline', 'Every event carries its evidence status: observed, or inferred.')
  await nav(page, 'Evidence timeline')
  await expect(page.getByTestId('timeline-list')).toBeVisible()
  await beat(page, 6800)

  // -- 9. machine learning, with its limits ---------------------------------
  mark('ml', 'The detector in use is a rarity baseline. The interface says so.')
  await nav(page, 'ML & analytics')
  await expect(page.getByText(/deterministic frequency table/i)).toBeVisible()
  await beat(page, 7200)

  // -- 10. export -------------------------------------------------------------
  mark('reports', 'One canonical model produces JSON, offline HTML and PDF.')
  await nav(page, 'Reports')
  await expect(page.getByTestId('export-pdf')).toBeVisible()
  await beat(page, 4600)
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId('export-pdf').click(),
  ])
  expect(await download.path()).toBeTruthy()
  await download.saveAs(join(ROOT, 'local-evidence', 'demo-report.pdf'))
  await beat(page, 3600)

  mark('end', 'Passive, local, evidence-backed.')
  await beat(page, 2600)

  writeFileSync(
    join(FOOTAGE, 'beats.json'),
    JSON.stringify(
      {
        schema: 'smsbeats/1',
        what_this_is:
          'Millisecond offsets, from the first recorded frame, of each ' +
          'narrated moment in the walkthrough. Measured during the recording, ' +
          'not written in advance.',
        recorded_at: new Date().toISOString(),
        total_ms: Date.now() - started,
        beats,
      },
      null,
      2,
    ) + '\n',
  )
})
