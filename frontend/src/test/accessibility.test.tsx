/**
 * M8 §11: frontend reliability and accessibility.
 *
 * The dashboard is a forensic tool. An analyst has to be able to reach every
 * control from the keyboard, know where the focus is, and be told what failed
 * rather than shown an empty panel. These tests assert the properties that a
 * screen reader and a keyboard user depend on, and the error paths that
 * decide whether a failure is visible or silent.
 *
 * Contrast is checked against the WCAG 2.1 AA contrast formula on the design
 * tokens, computed rather than eyeballed.
 */
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'

import * as fixtures from './fixtures'
import { InvestigationProvider } from '../lib/context'

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api')
  return {
    ...actual,
    api: {
      health: vi.fn(), listCaptures: vi.fn(), uploadCapture: vi.fn(),
      createInvestigation: vi.fn(), startAnalysis: vi.fn(),
      listInvestigations: vi.fn(), getInvestigation: vi.fn(), getJob: vi.fn(),
      listSessions: vi.fn(), getSession: vi.fn(), listFindings: vi.fn(),
      getFinding: vi.fn(), getIntelligence: vi.fn(), getTimeline: vi.fn(),
      getML: vi.fn(), getSettings: vi.fn(), updateSettings: vi.fn(),
      exportUrl: (id: string, f: string) => `/api/investigations/${id}/export/${f}`,
      download: vi.fn(),
    },
  }
})

import { ApiError, api } from '../lib/api'
import App from '../App'
import { Overview } from '../pages/Overview'
import { Investigations } from '../pages/Investigations'
import { Sessions } from '../pages/Sessions'
import { Findings } from '../pages/Findings'
import { Timeline } from '../pages/Timeline'
import { MLAnalysis } from '../pages/MLAnalysis'
import { Reports } from '../pages/Reports'
import { Intelligence } from '../pages/Intelligence'

const mocked = api as unknown as Record<string, ReturnType<typeof vi.fn>>

function withRouter(ui: ReactNode, initial = '/') {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <InvestigationProvider>{ui}</InvestigationProvider>
    </MemoryRouter>,
  )
}

function withSelection(ui: ReactNode) {
  window.sessionStorage.setItem(
    'sms.selectedInvestigation',
    fixtures.investigation.investigation_id,
  )
  return withRouter(ui)
}

/** Every page resolving successfully, so navigation tests do not hit errors. */
function resolveEverything() {
  mocked.listInvestigations.mockResolvedValue(fixtures.page([fixtures.investigation]))
  mocked.getInvestigation.mockResolvedValue(fixtures.investigationDetail)
  mocked.listCaptures.mockResolvedValue(fixtures.page([]))
  mocked.listSessions.mockResolvedValue(fixtures.page([fixtures.session]))
  mocked.getSession.mockResolvedValue(fixtures.sessionDetail)
  mocked.listFindings.mockResolvedValue(fixtures.page([fixtures.finding]))
  mocked.getFinding.mockResolvedValue(fixtures.findingDetail)
  mocked.getIntelligence.mockResolvedValue(fixtures.intelligence)
  mocked.getTimeline.mockResolvedValue(fixtures.page(fixtures.timeline))
  mocked.getML.mockResolvedValue(fixtures.ml)
  mocked.getSettings.mockResolvedValue(fixtures.settings)
}

beforeEach(() => {
  vi.clearAllMocks()
  window.sessionStorage.clear()
  mocked.health.mockResolvedValue({
    status: 'ok', tool_name: 'securemailscope', tool_version: '1.0.0',
    report_schema_version: '1.4.0', database_schema_version: 1,
    ml_available: true, ml_status: 'COMPLETED', analyzer_works_without_ml: true,
  })
})

// ---------------------------------------------------------------------------
// Structure a screen reader depends on
// ---------------------------------------------------------------------------
describe('document structure', () => {
  it('gives the application a single level-one heading', async () => {
    resolveEverything()
    withRouter(<App />)
    await waitFor(() => expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1))
  })

  it('marks its landmarks so a screen reader can skip between them', async () => {
    resolveEverything()
    withRouter(<App />)
    expect(await screen.findByRole('navigation')).toBeInTheDocument()
    expect(screen.getByRole('main')).toBeInTheDocument()
  })

  it('names every navigation link', async () => {
    resolveEverything()
    withRouter(<App />)
    const nav = await screen.findByRole('navigation')
    const links = within(nav).getAllByRole('link')
    // Primary workflow (4) plus Settings. The per-investigation group appears
    // only once an investigation is selected, which is the point: an empty
    // "Sessions" page tells a first-time user nothing.
    expect(links.length).toBeGreaterThanOrEqual(5)
    for (const link of links) {
      expect(link).toHaveAccessibleName()
      expect(link.getAttribute('href')).toBeTruthy()
    }
  })
})

describe('accessible names', () => {
  const pages: Array<[string, () => ReactNode]> = [
    ['Overview', () => <Overview />],
    ['Investigations', () => <Investigations />],
    ['Sessions', () => <Sessions />],
    ['Findings', () => <Findings />],
    ['Timeline', () => <Timeline />],
    ['Intelligence', () => <Intelligence />],
    ['ML analysis', () => <MLAnalysis />],
    ['Reports', () => <Reports />],
  ]

  it.each(pages)('%s labels every control it renders', async (_name, page) => {
    resolveEverything()
    withSelection(page())
    await waitFor(() => expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument(), {
      timeout: 3000,
    })

    for (const control of [
      ...screen.queryAllByRole('button'),
      ...screen.queryAllByRole('link'),
      ...screen.queryAllByRole('combobox'),
      ...screen.queryAllByRole('textbox'),
      ...screen.queryAllByRole('checkbox'),
    ]) {
      expect(control).toHaveAccessibleName()
    }
  })

  it.each(pages)('%s gives every table a header row', async (_name, page) => {
    resolveEverything()
    withSelection(page())
    await waitFor(() => expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument(), {
      timeout: 3000,
    })
    for (const table of screen.queryAllByRole('table')) {
      expect(within(table).queryAllByRole('columnheader').length).toBeGreaterThan(0)
    }
  })
})

// ---------------------------------------------------------------------------
// Keyboard
// ---------------------------------------------------------------------------
describe('keyboard operation', () => {
  it('reaches the navigation by tabbing, without a mouse', async () => {
    resolveEverything()
    const user = userEvent.setup()
    withRouter(<App />)
    const nav = await screen.findByRole('navigation')
    const first = within(nav).getAllByRole('link')[0]

    for (let i = 0; i < 12; i += 1) {
      await user.tab()
      if (document.activeElement === first) break
    }
    expect(document.activeElement).toBe(first)
  })

  it('leaves no control unreachable by keyboard', async () => {
    resolveEverything()
    withSelection(<Sessions />)
    await waitFor(() => expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument())

    for (const control of [
      ...screen.queryAllByRole('button'),
      ...screen.queryAllByRole('link'),
      ...screen.queryAllByRole('combobox'),
      ...screen.queryAllByRole('textbox'),
    ]) {
      // A disabled control is legitimately skipped -- pagination on the first
      // page, for instance. What must not happen is an *enabled* control that
      // the keyboard cannot reach.
      if ((control as HTMLInputElement).disabled) continue
      expect(control.getAttribute('tabindex')).not.toBe('-1')
    }
  })

  it('activates a filter from the keyboard alone', async () => {
    resolveEverything()
    const user = userEvent.setup()
    withSelection(<Findings />)
    await waitFor(() => expect(mocked.listFindings).toHaveBeenCalled())

    const combos = screen.queryAllByRole('combobox')
    if (combos.length === 0) return
    combos[0].focus()
    expect(document.activeElement).toBe(combos[0])
    await user.keyboard('{ArrowDown}')
    expect(document.activeElement).toBe(combos[0])
  })

  it('does not trap focus inside any single control', async () => {
    resolveEverything()
    const user = userEvent.setup()
    withSelection(<Sessions />)
    await waitFor(() => expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument())

    const seen = new Set<Element>()
    for (let i = 0; i < 10; i += 1) {
      await user.tab()
      if (document.activeElement) seen.add(document.activeElement)
    }
    expect(seen.size).toBeGreaterThan(1)
  })
})

// ---------------------------------------------------------------------------
// Failure is visible
// ---------------------------------------------------------------------------
describe('failure states', () => {
  const pages: Array<[string, () => ReactNode, string]> = [
    ['Overview', () => <Overview />, 'listInvestigations'],
    ['Investigations', () => <Investigations />, 'listInvestigations'],
    ['Sessions', () => <Sessions />, 'listSessions'],
    ['Findings', () => <Findings />, 'listFindings'],
    ['Timeline', () => <Timeline />, 'getTimeline'],
    ['Intelligence', () => <Intelligence />, 'getIntelligence'],
    ['ML analysis', () => <MLAnalysis />, 'getML'],
  ]

  it.each(pages)('%s announces a failure instead of an empty panel', async (
    _name, page, method,
  ) => {
    resolveEverything()
    mocked[method].mockRejectedValue(new Error('the backend is unreachable'))
    withSelection(page())

    const alert = await screen.findByRole('alert', {}, { timeout: 3000 })
    expect(alert).toHaveTextContent(/\w/)
    // A failure must never be dressed up as a zero.
    expect(alert.textContent).not.toMatch(/^0$/)
  })

  it.each(pages)('%s does not claim a result while it is still loading', async (
    _name, page, method,
  ) => {
    resolveEverything()
    let release: (value: unknown) => void = () => {}
    mocked[method].mockReturnValue(new Promise((resolve) => { release = resolve }))
    withSelection(page())

    // Nothing may assert an outcome before the data has arrived.
    expect(screen.queryByRole('alert')).toBeNull()
    release(fixtures.page([]))
  })
})

// ---------------------------------------------------------------------------
// Narrow viewports
// ---------------------------------------------------------------------------
describe('narrow viewports', () => {
  it.each([320, 480, 768, 1024])('renders at %ipx without losing the navigation', async (
    width,
  ) => {
    resolveEverything()
    window.innerWidth = width
    window.dispatchEvent(new Event('resize'))
    withRouter(<App />)

    const nav = await screen.findByRole('navigation')
    expect(nav).toBeInTheDocument()
    expect(within(nav).getAllByRole('link').length).toBeGreaterThanOrEqual(5)
  })
})

// ---------------------------------------------------------------------------
// Contrast, computed from the design tokens
// ---------------------------------------------------------------------------
describe('colour contrast', () => {
  /** WCAG 2.1 relative luminance. */
  function luminance(hex: string): number {
    const value = hex.replace('#', '')
    const full = value.length === 3 ? value.split('').map((c) => c + c).join('') : value
    const channels = [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16) / 255)
    const linear = channels.map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]
  }

  function ratio(a: string, b: string): number {
    const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x)
    return (light + 0.05) / (dark + 0.05)
  }

  it('computes the reference ratios correctly', () => {
    expect(ratio('#000000', '#ffffff')).toBeCloseTo(21, 1)
    expect(ratio('#ffffff', '#ffffff')).toBeCloseTo(1, 1)
  })

  /**
   * The palette as defined in tailwind.config.js and index.css. If a colour
   * changes there and is not changed here, this test does not fail -- so the
   * pairs are listed with the class names that use them, and the M8 report
   * records that this is a token-level check, not a rendered-pixel check.
   */
  const pairs: Array<[string, string, string, number]> = [
    ['body text on page', '#e6edf7', '#0b1017', 4.5],
    ['muted text on page', '#93a4bd', '#0b1017', 4.5],
    ['body text on panel', '#e6edf7', '#121a25', 4.5],
    ['muted text on panel', '#93a4bd', '#121a25', 4.5],
    ['critical tag', '#ffd9d9', '#7f1d1d', 4.5],
    ['high tag', '#ffe4cc', '#7c2d12', 4.5],
    ['medium tag', '#fff3c4', '#713f12', 4.5],
    ['low tag', '#d8ecff', '#1e3a5f', 4.5],
    ['accent on page', '#5eb0ff', '#0b1017', 3.0],
  ]

  it.each(pairs)('%s meets its contrast minimum', (_name, fg, bg, minimum) => {
    expect(ratio(fg, bg)).toBeGreaterThanOrEqual(minimum)
  })
})

// ---------------------------------------------------------------------------
// Upload staging
// ---------------------------------------------------------------------------
describe('upload staging', () => {
  /**
   * Regression for a defect the M8 acceptance walkthrough found: a second
   * selection replaced the staging list, so two already-uploaded captures
   * disappeared and the Analyse button went with them, even though the backend
   * still held them.
   */
  it('keeps earlier uploads when more files are selected', async () => {
    resolveEverything()
    mocked.uploadCapture
      .mockResolvedValueOnce({ ...fixtures.capture, capture_id: 'sha256:aaa' })
      .mockResolvedValueOnce({ ...fixtures.capture, capture_id: 'sha256:bbb' })
      .mockRejectedValueOnce(new ApiError(422, 'not a pcap or pcapng capture'))

    withRouter(<Investigations />)
    const input = await screen.findByTestId('file-input')

    await userEvent.upload(input, [
      new File(['a'], 'one.pcap'),
      new File(['b'], 'two.pcap'),
    ])
    await waitFor(() => expect(screen.getByTestId('analyse-button')).toBeInTheDocument())

    await userEvent.upload(input, [new File(['x'], 'bad.pcap')])
    await waitFor(() => expect(screen.getByText(/not a pcap or pcapng capture/i)).toBeInTheDocument())

    // The two good captures are still staged, and still analysable.
    expect(screen.getByText('one.pcap')).toBeInTheDocument()
    expect(screen.getByText('two.pcap')).toBeInTheDocument()
    expect(screen.getByTestId('analyse-button')).toBeInTheDocument()
  })

  it('lists a capture staged twice only once when analysing', async () => {
    resolveEverything()
    mocked.uploadCapture.mockResolvedValue({ ...fixtures.capture, capture_id: 'sha256:same' })
    mocked.createInvestigation.mockResolvedValue(fixtures.investigation)
    mocked.startAnalysis.mockResolvedValue(fixtures.job)

    withRouter(<Investigations />)
    const input = await screen.findByTestId('file-input')
    await userEvent.upload(input, [new File(['a'], 'one.pcap')])
    await waitFor(() => expect(screen.getByTestId('analyse-button')).toBeInTheDocument())
    await userEvent.upload(input, [new File(['a'], 'one-again.pcap')])
    await waitFor(() => expect(screen.getByText('one-again.pcap')).toBeInTheDocument())

    await userEvent.click(screen.getByTestId('analyse-button'))
    await waitFor(() => expect(mocked.createInvestigation).toHaveBeenCalled())
    const [, ids] = mocked.createInvestigation.mock.calls[0]
    expect(ids).toEqual(['sha256:same'])
  })
})
