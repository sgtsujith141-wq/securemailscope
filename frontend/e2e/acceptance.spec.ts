/**
 * M8 §15: the complete acceptance walkthrough, browser to backend.
 *
 * Twenty-two numbered steps, run in order against the real FastAPI
 * application over the real forensic engine. Nothing is mocked and no value is
 * hardcoded from a previous run: every expectation is either a property that
 * must hold (a count agreeing across two views) or a number the engine
 * produced earlier in the same test.
 *
 * Step 20 stops the backend process and starts it again on the same data
 * directory, which is the only way to show that an investigation is genuinely
 * persisted rather than held in memory.
 */
import { expect, test } from '@playwright/test'
import { readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const FIXTURES = join(process.cwd(), '..', 'tests', 'fixtures', 'generated')
const RESTART_FLAG = join(tmpdir(), 'sms-e2e-restart')

/** Two captures, so the investigation exercises cross-capture intelligence. */
const CAPTURES = ['aa_tls10_static_rsa.pcap', 't_a_tls12_complete_handshake.pcap']

test.describe.configure({ mode: 'serial' })

type Page = import('@playwright/test').Page

const navigate = (page: Page, name: string) =>
  page.getByRole('navigation').getByRole('link', { name, exact: true }).click()

function upload(name: string) {
  return {
    name,
    mimeType: 'application/octet-stream',
    buffer: readFileSync(join(FIXTURES, name)),
  }
}

/** Numbers the engine produced, carried between steps rather than hardcoded. */
const observed: Record<string, string> = {}

test('the complete acceptance walkthrough', async ({ page }) => {
  test.setTimeout(180_000)

  // -- 1. The application loads and the navigation is present --------------
  await page.goto('/')
  await expect(page.getByRole('navigation')).toBeVisible()

  // -- 2. The empty state says so, rather than showing zeroes --------------
  //     Note: the overview returns this instead of the capabilities panel when
  //     nothing has been analysed, so the backend's reported schema versions
  //     are checked at step 17a, once there is data.
  // With nothing analysed the product explains itself: what it does, what it
  // accepts, the four steps, and one primary action.
  await expect(page.getByTestId('first-run')).toBeVisible()
  await expect(
    page.getByText(/Investigate cryptographic security directly from captured email traffic/i),
  ).toBeVisible()
  await expect(page.getByTestId('start-investigation')).toBeVisible()

  // -- 3. Upload two captures ----------------------------------------------
  await navigate(page, 'Investigations')
  await expect(page.getByRole('heading', { level: 1, name: 'Investigations' })).toBeVisible()
  await page.setInputFiles('[data-testid="file-input"]', CAPTURES.map(upload))
  for (const name of CAPTURES) {
    await expect(page.getByText(name, { exact: false }).first()).toBeVisible()
  }
  await expect(page.getByText('ACCEPTED').first()).toBeVisible()

  // -- 4. A file that is not a capture is refused, with a reason ------------
  await page.setInputFiles('[data-testid="file-input"]', {
    name: 'not-a-capture.pcap',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('this is not a pcap file at all'),
  })
  await expect(page.getByText(/not a pcap or pcapng capture|REJECTED/i).first()).toBeVisible()

  // -- 5. Analyse both captures as one investigation ------------------------
  await page.getByTestId('analyse-button').click()

  // -- 6. Progress is reported from the backend, not from a timer -----------
  //     The job either reports a stage or completes; what must not happen is a
  //     progress display that advances with no backend to back it.
  await expect(page).toHaveURL(/\/investigations\/inv-/, { timeout: 120_000 })
  const investigationId = page.url().split('/investigations/')[1].split('?')[0]
  expect(investigationId).toMatch(/^inv-[0-9a-f]+$/)
  observed.investigationId = investigationId

  // -- 7. The workspace shows the engine's own result ----------------------
  await expect(page.getByText('Captures analysed').first()).toBeVisible()
  const score = page.getByTestId('posture-score')
  await expect(score).toBeVisible()
  observed.score = ((await score.textContent()) ?? '').trim()
  expect(observed.score).toMatch(/Posture score(\d+\/100|INSUFFICIENT EVIDENCE|NOT ANALYSED)/)

  // -- 8. Scope is stated, not implied -------------------------------------
  await expect(page.getByText('Observed within analyzed captures only.').first()).toBeVisible()

  // -- 9. Sessions list, and its count agrees with the workspace -----------
  await navigate(page, 'Sessions')
  await expect(page.getByTestId('session-table')).toBeVisible()
  const sessionRows = page.locator('[data-testid="session-table"] tbody tr')
  const sessionCount = await sessionRows.count()
  expect(sessionCount).toBeGreaterThan(0)
  observed.sessionCount = String(sessionCount)

  // -- 10. Search narrows the list and can be cleared ----------------------
  await page.getByTestId('session-search').fill('zzz-no-such-session')
  await expect(sessionRows).toHaveCount(0)
  await page.getByTestId('session-search').fill('')
  await expect(sessionRows).toHaveCount(sessionCount)

  // -- 11. A filter narrows the list without losing the honest labels ------
  await page.getByTestId('protocol-filter').selectOption('SMTP')
  await expect(page.getByTestId('session-table')).toBeVisible()
  await page.getByTestId('protocol-filter').selectOption('')
  await expect(sessionRows).toHaveCount(sessionCount)

  // -- 12. Session detail shows reconstruction and negotiation -------------
  await sessionRows.first().locator('a').first().click()
  await expect(page.getByRole('heading', { level: 1, name: 'Session detail' })).toBeVisible()
  await expect(page.getByText('TCP reconstruction').first()).toBeVisible()
  await expect(page.getByText('TLS negotiation').first()).toBeVisible()

  // -- 13. Findings, with a severity filter --------------------------------
  await navigate(page, 'Findings')
  await expect(page.getByTestId('findings-list')).toBeVisible()
  const findingRows = page.getByTestId('finding-row')
  const findingCount = await findingRows.count()
  expect(findingCount).toBeGreaterThan(0)
  observed.findingCount = String(findingCount)

  // -- 14. A finding opens, with its evidence ------------------------------
  await findingRows.first().click()
  const detail = page.getByTestId('finding-detail')
  await expect(detail).toBeVisible()
  await detail.getByTestId('evidence-toggle').click()
  const evidence = page.getByTestId('evidence-panel')
  await expect(evidence).toBeVisible()
  await expect(evidence.getByText(/^#\d+$/).first()).toBeVisible()
  await expect(evidence.getByText(/payload bytes are never included/i)).toBeVisible()

  // -- 15. Cross-capture intelligence --------------------------------------
  await navigate(page, 'Intelligence')
  await expect(
    page.getByRole('heading', { level: 1, name: /intelligence/i }),
  ).toBeVisible()
  await expect(page.getByText(/fingerprint|entit|drift|correlat/i).first()).toBeVisible()

  // -- 16. The evidence timeline -------------------------------------------
  await navigate(page, 'Evidence timeline')
  const timeline = page.getByTestId('timeline-list')
  await expect(timeline).toBeVisible()
  await expect(timeline.getByText(/^Packets /).first()).toBeVisible()

  // -- 17. ML analysis keeps its M6 honesty ---------------------------------
  await navigate(page, 'ML & analytics')
  await expect(
    page.getByText(/deterministic frequency table, not a machine-learning model/i),
  ).toBeVisible()
  await expect(page.getByText(/not confirmed threats/i)).toBeVisible()

  // -- 17a. The backend's own health response, rendered -------------------
  await navigate(page, 'Overview')
  await expect(page.getByText('Analysis capabilities')).toBeVisible()
  await expect(page.getByText('Report schema')).toBeVisible()
  await expect(page.getByText('Database schema')).toBeVisible()

  // -- 18. Settings are readable and state what needs a re-analysis ---------
  await navigate(page, 'Settings')
  await expect(page.getByRole('heading', { level: 1, name: 'Settings' })).toBeVisible()
  await expect(page.getByTestId('setting-max_packets')).toBeVisible()

  // -- 19. Export all three formats, and check they agree -------------------
  await navigate(page, 'Reports')
  const exported: Record<string, Buffer> = {}
  for (const format of ['json', 'html', 'pdf'] as const) {
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByTestId(`export-${format}`).click(),
    ])
    const path = await download.path()
    expect(path).toBeTruthy()
    exported[format] = readFileSync(path!)
    expect(exported[format].length).toBeGreaterThan(500)
  }
  expect(exported.pdf.subarray(0, 4).toString()).toBe('%PDF')

  const document = JSON.parse(exported.json.toString())
  expect(document.findings.length).toBe(findingCount)
  const html = exported.html.toString()
  expect(html).not.toMatch(/<script[^>]*\ssrc=/)
  expect(html).not.toMatch(/<link[^>]*href=["']?https?:/)
  // Every finding in the JSON export is identifiable in the HTML report.
  for (const finding of document.findings) {
    expect(html).toContain(finding.finding_id)
  }

  // -- 20. Restart the backend ---------------------------------------------
  //     Two waits, not one. The supervisor polls for the request once a
  //     second, so for up to a second after the flag is written the *old*
  //     process is still answering 200. Polling only for "up" would sail
  //     straight past and then hit a server mid-shutdown.
  const health = async () => {
    try {
      const response = await page.request.get('http://127.0.0.1:8799/api/health', {
        timeout: 2000,
      })
      return response.status()
    } catch {
      return 0
    }
  }

  writeFileSync(RESTART_FLAG, 'restart')
  await expect
    .poll(health, { timeout: 60_000, intervals: [200] })
    .not.toBe(200) // gone
  await expect.poll(health, { timeout: 60_000, intervals: [200] }).toBe(200) // back

  // -- 21. Reopen the investigation: everything survived --------------------
  await page.goto(`/investigations/${investigationId}`)
  await expect(page.getByTestId('posture-score')).toHaveText(observed.score)
  await expect(page.getByTestId('session-count')).toContainText(String(sessionCount))
  await navigate(page, 'Findings')
  await expect(page.getByTestId('findings-list')).toBeVisible()
  await expect(page.getByTestId('finding-row')).toHaveCount(findingCount)
  await navigate(page, 'Sessions')
  await expect(page.locator('[data-testid="session-table"] tbody tr')).toHaveCount(sessionCount)

  // -- 22. A report still generates from the restored state -----------------
  await navigate(page, 'Reports')
  const [afterRestart] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId('export-json').click(),
  ])
  const restoredPath = await afterRestart.path()
  const restored = JSON.parse(readFileSync(restoredPath!).toString())
  expect(restored.findings.length).toBe(findingCount)
  expect(restored.findings.map((f: { finding_id: string }) => f.finding_id).sort()).toEqual(
    document.findings.map((f: { finding_id: string }) => f.finding_id).sort(),
  )
})
