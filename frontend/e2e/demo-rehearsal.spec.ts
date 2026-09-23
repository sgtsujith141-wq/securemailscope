/**
 * M9 section 9: the demonstration rehearsal, run against the real stack.
 *
 * This is not a test of the application -- `acceptance.spec.ts` is that. This
 * drives the exact sequence the demonstration follows, using only the
 * synthetic demo dataset, and records two things:
 *
 *  - genuine screenshots, written to `docs/screenshots/`, which are committed
 *    and used in the README and the submission deck;
 *  - a rehearsal record, written to `submission/demo/rehearsal.json`, holding
 *    the real timings and the engine's real output for each step.
 *
 * Nothing here is staged or mocked. If a step fails, the rehearsal record says
 * so rather than the run quietly producing a prettier screenshot.
 *
 * Run with:  npx playwright test demo-rehearsal
 */
import { expect, test } from '@playwright/test'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = join(process.cwd(), '..')
const SHOTS = join(ROOT, 'docs', 'screenshots')
const DEMO = join(ROOT, 'demo', 'captures')
const RECORD = join(ROOT, 'submission', 'demo', 'rehearsal.json')

type Page = import('@playwright/test').Page

const nav = (page: Page, name: string) =>
  page.getByRole('navigation').getByRole('link', { name, exact: true }).click()

interface Step {
  step: number
  name: string
  outcome: string
  seconds: number
  screenshot?: string
  observed?: Record<string, unknown>
}

const steps: Step[] = []
let counter = 0

async function record<T>(
  name: string,
  action: () => Promise<T>,
  observed?: () => Promise<Record<string, unknown>>,
): Promise<T> {
  counter += 1
  const started = Date.now()
  let outcome = 'OK'
  let value: T
  try {
    value = await action()
  } catch (error) {
    outcome = `FAILED: ${(error as Error).message.split('\n')[0]}`
    steps.push({ step: counter, name, outcome, seconds: (Date.now() - started) / 1000 })
    throw error
  }
  const entry: Step = {
    step: counter,
    name,
    outcome,
    seconds: Number(((Date.now() - started) / 1000).toFixed(2)),
  }
  if (observed) entry.observed = await observed()
  steps.push(entry)
  return value
}

async function shot(page: Page, file: string): Promise<void> {
  await page.screenshot({ path: join(SHOTS, file), fullPage: true })
  const last = steps[steps.length - 1]
  if (last) last.screenshot = `docs/screenshots/${file}`
}

test('demonstration rehearsal on the synthetic demo dataset', async ({ page }) => {
  test.setTimeout(240_000)
  mkdirSync(SHOTS, { recursive: true })
  mkdirSync(join(ROOT, 'submission', 'demo'), { recursive: true })
  await page.setViewportSize({ width: 1440, height: 1100 })

  const upload = (name: string) => ({
    name,
    mimeType: 'application/octet-stream',
    buffer: readFileSync(join(DEMO, name)),
  })

  // -- 1. The application, before anything has been analysed --------------
  await record('launch the application', async () => {
    await page.goto('/')
    await expect(page.getByRole('navigation')).toBeVisible()
  })
  await shot(page, '01-empty-state.png')

  // -- 2. Upload the demo dataset ------------------------------------------
  const files = [
    '01-secure-baseline.pcap',
    '02-weak-legacy-tls.pcap',
    '03-broken-cipher.pcap',
    '04-starttls-upgrade.pcap',
    '05-starttls-refused.pcap',
    '06-tls12-certificate.pcap',
    '07-tls13-encrypted-certificate.pcap',
  ]
  await record('upload seven synthetic captures', async () => {
    await nav(page, 'Investigations')
    await page.setInputFiles('[data-testid="file-input"]', files.map(upload))
    await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
  })
  await shot(page, '02-upload.png')

  // -- 3. Analyse ----------------------------------------------------------
  const investigationId = await record(
    'analyse the investigation',
    async () => {
      await page.getByTestId('analyse-button').click()
      await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 180_000 })
      return page.url().split('/investigations/')[1].split('?')[0]
    },
    async () => ({
      posture_score: (await page.getByTestId('posture-score').textContent())?.trim(),
      sessions: (await page.getByTestId('session-count').textContent())?.trim(),
      findings: (await page.getByTestId('finding-count').textContent())?.trim(),
    }),
  )
  await shot(page, '03-investigation-workspace.png')
  expect(investigationId).toMatch(/^inv-[0-9a-f]+$/)

  // -- 4. Overview ---------------------------------------------------------
  await record('overview across the investigation', async () => {
    await nav(page, 'Overview')
    await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible()
  })
  await shot(page, '04-overview.png')

  // -- 5. Sessions: TLS version and cipher suite per session ---------------
  await record(
    'inspect the session inventory',
    async () => {
      await nav(page, 'Sessions')
      await expect(page.getByTestId('session-table')).toBeVisible()
    },
    async () => ({
      rows: await page.locator('[data-testid="session-table"] tbody tr').count(),
    }),
  )
  await shot(page, '05-sessions.png')

  // -- 6. Session detail: reconstruction, negotiation, certificate ---------
  await record('open a session and read its negotiation', async () => {
    await page.locator('[data-testid="session-table"] a').first().click()
    await expect(page.getByRole('heading', { level: 1, name: 'Session detail' })).toBeVisible()
    await expect(page.getByText('TLS negotiation').first()).toBeVisible()
  })
  await shot(page, '06-session-detail.png')

  // -- 7. A finding, and the packets it was read from ----------------------
  await record(
    'open a security finding and its packet evidence',
    async () => {
      await nav(page, 'Findings')
      await expect(page.getByTestId('findings-list')).toBeVisible()
      await page.getByTestId('finding-row').first().click()
      await page.getByTestId('finding-detail').getByTestId('evidence-toggle').click()
      await expect(page.getByTestId('evidence-panel')).toBeVisible()
    },
    async () => ({
      findings_listed: await page.getByTestId('finding-row').count(),
      evidence_text: (
        await page.getByTestId('evidence-panel').textContent()
      )?.replace(/\s+/g, ' ').slice(0, 200),
    }),
  )
  await shot(page, '07-finding-evidence.png')

  // -- 8. Cryptographic intelligence ---------------------------------------
  await record('cryptographic fingerprints', async () => {
    await nav(page, 'Intelligence')
    await expect(page.getByTestId('tab-fingerprints')).toBeVisible()
  })
  await shot(page, '08-intelligence-fingerprints.png')

  // -- 9. Evidence timeline -------------------------------------------------
  await record('evidence timeline', async () => {
    await nav(page, 'Evidence timeline')
    await expect(page.getByTestId('timeline-list')).toBeVisible()
  })
  await shot(page, '09-timeline.png')

  // -- 10. ML, with its stated limits ---------------------------------------
  await record(
    'ML analysis and its limitations',
    async () => {
      await nav(page, 'ML & analytics')
      await expect(page.getByText(/deterministic frequency table/i)).toBeVisible()
    },
    async () => ({
      states_baseline_is_not_ml: await page
        .getByText(/deterministic frequency table, not a machine-learning model/i)
        .isVisible(),
      states_not_confirmed_threats: await page
        .getByText(/not confirmed threats/i)
        .isVisible(),
    }),
  )
  await shot(page, '10-ml-analysis.png')

  // -- 11. Export the PDF report --------------------------------------------
  const sizes: Record<string, number> = {}
  await record(
    'export JSON, HTML and PDF reports',
    async () => {
      await nav(page, 'Reports')
      for (const format of ['json', 'html', 'pdf'] as const) {
        const [download] = await Promise.all([
          page.waitForEvent('download'),
          page.getByTestId(`export-${format}`).click(),
        ])
        const path = await download.path()
        sizes[format] = readFileSync(path!).length
      }
    },
    async () => ({ report_bytes: sizes }),
  )
  await shot(page, '11-reports.png')

  // -- 12. The drift investigation, as a second investigation ---------------
  await record('analyse the two-capture drift investigation', async () => {
    await nav(page, 'Investigations')
    await page.setInputFiles(
      '[data-testid="file-input"]',
      ['08-drift-1-b1_tls12.pcap', '08-drift-2-b2_tls10.pcap'].map(upload),
    )
    await expect(page.getByText('ACCEPTED').first()).toBeVisible({ timeout: 60_000 })
    await page.getByTestId('analyse-button').click()
    await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 180_000 })
  })
  await shot(page, '12-drift-investigation.png')

  await record(
    'cryptographic drift between the two captures',
    async () => {
      await nav(page, 'Intelligence')
      await page.getByTestId('tab-drift').click()
      await expect(page.getByTestId('tab-drift')).toBeVisible()
      await page.waitForTimeout(600)
    },
    async () => ({
      drift_panel: (await page.getByRole('main').textContent())
        ?.replace(/\s+/g, ' ')
        .slice(0, 300),
    }),
  )
  await shot(page, '13-drift.png')

  await record('blast radius', async () => {
    await page.getByTestId('tab-blast_radius').click()
    await page.waitForTimeout(600)
  })
  await shot(page, '14-blast-radius.png')
})

test.afterAll(async () => {
  const failed = steps.filter((s) => s.outcome !== 'OK')
  writeFileSync(
    RECORD,
    JSON.stringify(
      {
        schema: 'smsrehearsal/1',
        what_this_is:
          'A record of an actual demonstration run against the real backend ' +
          'and the real forensic engine, using only the synthetic demo ' +
          'dataset. Timings are wall-clock on the machine that ran it.',
        recorded_at: new Date().toISOString(),
        dataset: 'demo/captures (see demo/manifest.json)',
        steps_total: steps.length,
        steps_failed: failed.length,
        reproducible:
          'python scripts/build_demo_dataset.py && ' +
          'cd frontend && npx playwright test demo-rehearsal',
        steps,
      },
      null,
      2,
    ) + '\n',
  )
})
