/**
 * The full browser-to-backend workflow (§23).
 *
 * Upload → analyse → open investigation → inspect session → open finding →
 * navigate to packet evidence → inspect timeline → export JSON, HTML and PDF.
 *
 * No mocked backend. Every step drives the real FastAPI application over the
 * real forensic engine, with a capture generated locally by the project's own
 * fixture generator.
 */
import { expect, test } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const FIXTURES = join(process.cwd(), '..', 'tests', 'fixtures', 'generated')
const CAPTURE = 'aa_tls10_static_rsa.pcap'

test.describe.configure({ mode: 'serial' })

/**
 * Several pages offer a shortcut link with the same name as a navigation
 * entry — the workspace links to "Sessions" and "Findings" as well as the
 * sidebar. Navigation is therefore scoped to the sidebar explicitly.
 */
const navigate = (page: import('@playwright/test').Page, name: string) =>
  page.getByRole('navigation').getByRole('link', { name, exact: true }).click()

test('upload, analyse, investigate, navigate to evidence and export', async ({ page }) => {
  // -- 1. Upload a locally generated capture ------------------------------
  await page.goto('/investigations')
  await expect(page.getByRole('heading', { level: 1, name: 'Investigations' })).toBeVisible()

  await page.setInputFiles('[data-testid="file-input"]', {
    name: CAPTURE,
    mimeType: 'application/octet-stream',
    buffer: readFileSync(join(FIXTURES, CAPTURE)),
  })
  await expect(page.getByText('ACCEPTED')).toBeVisible()

  // -- 2. Analyse ----------------------------------------------------------
  await page.getByTestId('analyse-button').click()
  // The workspace opens by itself once the job completes.
  await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 60_000 })

  // -- 3. The investigation shows real engine output -----------------------
  await expect(page.getByText('Observed within analyzed captures only.').first()).toBeVisible()
  await expect(page.getByText('Captures analysed').first()).toBeVisible()
  // The engine's own numbers for this fixture: 59/100, band WEAK.
  await expect(page.getByText('59/100').first()).toBeVisible()
  await expect(page.getByText(/WEAK/).first()).toBeVisible()

  const url = page.url()
  const investigationId = url.split('/investigations/')[1]
  expect(investigationId).toMatch(/^inv-[0-9a-f]+$/)

  // -- 4. Inspect a session ------------------------------------------------
  await navigate(page, 'Sessions')
  await expect(page.getByTestId('session-table')).toBeVisible()
  await expect(page.getByText('TLS_RSA_WITH_AES_128_CBC_SHA').first()).toBeVisible()
  await page.locator('[data-testid="session-table"] a').first().click()
  await expect(page.getByRole('heading', { level: 1, name: 'Session detail' })).toBeVisible()
  await expect(page.getByText('TCP reconstruction').first()).toBeVisible()
  await expect(page.getByText('TLS negotiation').first()).toBeVisible()

  // -- 5. Open a security finding -----------------------------------------
  await navigate(page, 'Security findings')
  await expect(page.getByTestId('findings-list')).toBeVisible()
  await page.getByTestId('finding-row').first().click()
  const detail = page.getByTestId('finding-detail')
  await expect(detail).toBeVisible()

  // -- 6. Navigate to the packet evidence ----------------------------------
  await detail.getByTestId('evidence-toggle').click()
  const evidence = page.getByTestId('evidence-panel')
  await expect(evidence).toBeVisible()
  // Real packet numbers from the generated capture.
  await expect(evidence.getByText('#4')).toBeVisible()
  await expect(evidence.getByText('#5')).toBeVisible()
  await expect(evidence.getByText(/payload bytes are never included/i)).toBeVisible()

  // -- 7. Inspect the timeline --------------------------------------------
  await navigate(page, 'Evidence timeline')
  const timeline = page.getByTestId('timeline-list')
  await expect(timeline).toBeVisible()
  // Scoped to the list: the event-type filter contains options with the same
  // names, and an option inside a closed select is not visible.
  await expect(timeline.getByText('SESSION FIRST PACKET').first()).toBeVisible()
  await expect(timeline.getByText(/^Packets /).first()).toBeVisible()

  // -- 8. Export all three formats ----------------------------------------
  await navigate(page, 'Reports')
  for (const format of ['json', 'html', 'pdf'] as const) {
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByTestId(`export-${format}`).click(),
    ])
    expect(download.suggestedFilename()).toContain(format)
    const path = await download.path()
    expect(path).toBeTruthy()
    const bytes = readFileSync(path!)
    expect(bytes.length).toBeGreaterThan(500)
    if (format === 'pdf') expect(bytes.subarray(0, 4).toString()).toBe('%PDF')
    if (format === 'json') expect(JSON.parse(bytes.toString()).findings.length).toBe(4)
    if (format === 'html') {
      const html = bytes.toString()
      expect(html).toContain('TLS-KEX-001')
      // Standalone: no external resource is referenced.
      expect(html).not.toMatch(/<script[^>]*\ssrc=/)
      expect(html).not.toMatch(/<link[^>]*href=["']?https?:/)
    }
  }
})

/**
 * Each test gets a fresh browser context, so the selected investigation --
 * which lives in sessionStorage -- has to be re-established through the
 * interface. The backend state persists across tests; the browser's does not.
 */
async function selectFirstInvestigation(page: import('@playwright/test').Page) {
  await page.goto('/investigations')
  await page.locator('table a[href^="/investigations/inv-"]').first().click()
  await expect(page).toHaveURL(/\/investigations\/inv-/)
}

test('ML analysis preserves the M6 distinctions', async ({ page }) => {
  await selectFirstInvestigation(page)
  await navigate(page, 'ML analysis')
  await expect(page.getByRole('heading', { level: 1, name: 'ML analysis' })).toBeVisible()
  // The deterministic baseline must not be presented as machine learning.
  await expect(
    page.getByText(/deterministic frequency table, not a machine-learning model/i),
  ).toBeVisible()
  await expect(page.getByText(/Experimental anomaly model — not in use/i)).toBeVisible()
  await expect(page.getByText(/not confirmed threats/i)).toBeVisible()
})

test('an unknown route shows a real not-found page', async ({ page }) => {
  await page.goto('/nowhere/at/all')
  await expect(page.getByText(/This page does not exist/i)).toBeVisible()
})

test('a refresh preserves the selected investigation', async ({ page }) => {
  await selectFirstInvestigation(page)
  await navigate(page, 'Security findings')
  await expect(page.getByRole('heading', { level: 1, name: 'Security findings' })).toBeVisible()
  await page.reload()
  // The selection survives, so the page still has data rather than prompting.
  await expect(page.getByTestId('findings-list')).toBeVisible()
})
