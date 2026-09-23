/**
 * Frontend behaviour tests (§23).
 *
 * The API module is mocked so each test drives a specific backend state —
 * empty, failed, unscored, unknown. What is asserted is that the interface
 * tells the truth about each one: that it distinguishes "no findings" from
 * "not analysed" from "insufficient evidence", and that it never renders a
 * zero where the honest answer is unknown.
 */
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'

import * as fixtures from './fixtures'
import { InvestigationProvider } from '../lib/context'

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api')
  return {
    ...actual,
    api: {
      health: vi.fn(),
      listCaptures: vi.fn(),
      uploadCapture: vi.fn(),
      createInvestigation: vi.fn(),
      startAnalysis: vi.fn(),
      listInvestigations: vi.fn(),
      getInvestigation: vi.fn(),
      getJob: vi.fn(),
      listSessions: vi.fn(),
      getSession: vi.fn(),
      listFindings: vi.fn(),
      getFinding: vi.fn(),
      getIntelligence: vi.fn(),
      getTimeline: vi.fn(),
      getML: vi.fn(),
      getSettings: vi.fn(),
      updateSettings: vi.fn(),
      exportUrl: (id: string, f: string) => `/api/investigations/${id}/export/${f}`,
      download: vi.fn(),
    },
  }
})

import { api } from '../lib/api'
import { Overview } from '../pages/Overview'
import { Investigations } from '../pages/Investigations'
import { InvestigationWorkspace } from '../pages/InvestigationWorkspace'
import { Sessions } from '../pages/Sessions'
import { SessionDetailPage } from '../pages/SessionDetail'
import { Findings } from '../pages/Findings'
import { Intelligence } from '../pages/Intelligence'
import { Timeline } from '../pages/Timeline'
import { MLAnalysis } from '../pages/MLAnalysis'
import { Reports } from '../pages/Reports'
import App from '../App'

const mocked = api as unknown as Record<string, ReturnType<typeof vi.fn>>

function withRouter(ui: ReactNode, initial = '/') {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <InvestigationProvider>{ui}</InvestigationProvider>
    </MemoryRouter>,
  )
}

/** Selects an investigation first, so context-dependent pages have one. */
function withSelection(ui: ReactNode) {
  window.sessionStorage.setItem('sms.selectedInvestigation', fixtures.investigation.investigation_id)
  return withRouter(ui)
}

beforeEach(() => {
  vi.clearAllMocks()
  window.sessionStorage.clear()
  mocked.health.mockResolvedValue({
    status: 'ok', tool_name: 'securemailscope', tool_version: '1.0.0',
    report_schema_version: '1.4.0', database_schema_version: 1,
    ml_available: true, ml_status: 'COMPLETED', analyzer_works_without_ml: true,
  })
  // The workspace dashboard loads its top findings, the sessions its
  // cryptographic modules aggregate, and the head of the evidence timeline.
  // Tests that are not about any of those still render them, so give each
  // call a default rather than leaving every test to stub a request it does
  // not care about. Tests that *are* about one override it.
  mocked.listFindings.mockResolvedValue(fixtures.page([]))
  mocked.listSessions.mockResolvedValue(fixtures.page([fixtures.session]))
  mocked.getTimeline.mockResolvedValue(fixtures.page(fixtures.timeline))
})

describe('Overview', () => {
  it('shows an empty state before anything is analysed', async () => {
    mocked.listInvestigations.mockResolvedValue(fixtures.page([]))
    withRouter(<Overview />)
    // With nothing analysed the product explains itself rather than the
    // database: what it does, what it accepts, and the four steps.
    expect(await screen.findByTestId('first-run')).toBeInTheDocument()
    expect(
      screen.getByText(/Investigate cryptographic security directly from captured email traffic/i),
    ).toBeInTheDocument()
    expect(screen.getByTestId('start-investigation')).toBeInTheDocument()
    // No invented counts while the database is empty.
    expect(screen.queryByText(/^0$/)).not.toBeInTheDocument()
  })

  it('reports a failure rather than pretending there is no data', async () => {
    mocked.listInvestigations.mockRejectedValue(new Error('boom'))
    withRouter(<Overview />)
    expect(await screen.findByRole('alert')).toHaveTextContent(/Could not load investigations/i)
  })

  it('distinguishes NO FINDINGS from a count of zero', async () => {
    mocked.listInvestigations.mockResolvedValue(
      fixtures.page([{ ...fixtures.investigation, finding_count: 0, severity_counts: {} }]),
    )
    withRouter(<Overview />)
    expect(await screen.findAllByText('NO FINDINGS')).not.toHaveLength(0)
  })

  it('shows INSUFFICIENT EVIDENCE rather than a score of zero', async () => {
    mocked.listInvestigations.mockResolvedValue(fixtures.page([fixtures.unscoredInvestigation]))
    withRouter(<Overview />)
    expect(await screen.findByText(/INSUFFICIENT EVIDENCE/)).toBeInTheDocument()
    expect(screen.queryByText('0/100')).not.toBeInTheDocument()
  })

  it('keeps a high-severity finding prominent beside the score', async () => {
    mocked.listInvestigations.mockResolvedValue(fixtures.page([fixtures.investigation]))
    withRouter(<Overview />)
    expect(await screen.findByText(/does not remove an individual finding/i)).toBeInTheDocument()
    expect(screen.getByText(/highest severity HIGH/i)).toBeInTheDocument()
  })

  it('states the scope of its counts', async () => {
    mocked.listInvestigations.mockResolvedValue(fixtures.page([fixtures.investigation]))
    withRouter(<Overview />)
    expect(await screen.findByText(/Observed within analyzed captures only/i)).toBeInTheDocument()
  })
})

describe('Upload workflow', () => {
  beforeEach(() => {
    mocked.listInvestigations.mockResolvedValue(fixtures.page([]))
    mocked.listCaptures.mockResolvedValue(fixtures.page([]))
  })

  it('shows validation state for an accepted capture', async () => {
    mocked.uploadCapture.mockResolvedValue(fixtures.capture)
    withRouter(<Investigations />)
    const input = await screen.findByTestId('file-input')
    await userEvent.upload(input, new File(['\xd4\xc3\xb2\xa1data'], 'a.pcap'))
    expect(await screen.findByText('ACCEPTED')).toBeInTheDocument()
  })

  it('shows the rejection reason for a file that is not a capture', async () => {
    const { ApiError } = await vi.importActual<typeof import('../lib/api')>('../lib/api')
    mocked.uploadCapture.mockRejectedValue(
      new ApiError(422, 'this file is not a pcap or pcapng capture'),
    )
    withRouter(<Investigations />)
    await userEvent.upload(await screen.findByTestId('file-input'), new File(['nope'], 'x.pcap'))
    expect(await screen.findByText('REJECTED')).toBeInTheDocument()
    expect(screen.getByText(/not a pcap or pcapng capture/i)).toBeInTheDocument()
  })

  it('shows determinate progress only when the backend reports a proportion', async () => {
    mocked.uploadCapture.mockResolvedValue(fixtures.capture)
    mocked.createInvestigation.mockResolvedValue(fixtures.investigation)
    mocked.startAnalysis.mockResolvedValue({ ...fixtures.job, status: 'RUNNING', captures_done: 0 })
    mocked.getJob.mockResolvedValue(fixtures.job)
    withRouter(<Investigations />)
    await userEvent.upload(await screen.findByTestId('file-input'), new File(['x'], 'a.pcap'))
    await userEvent.click(await screen.findByTestId('analyse-button'))
    expect(await screen.findByTestId('progress-determinate')).toBeInTheDocument()
  })
})

describe('Investigation workspace', () => {
  it('leads with what needs attention, not with the score', async () => {
    // The workspace used to open with four equal-weight metric cards, the
    // largest of which was the score. A reader had to work out for themselves
    // which findings were HIGH. The hero now says it.
    mocked.getInvestigation.mockResolvedValue(fixtures.investigationDetail)
    mocked.listFindings.mockResolvedValue(
      fixtures.page([
        { ...fixtures.finding, finding_id: 'find-a', severity: 'HIGH', priority: 'P1' },
        { ...fixtures.finding, finding_id: 'find-b', severity: 'HIGH', priority: 'P1' },
        { ...fixtures.finding, finding_id: 'find-c', severity: 'INFO', priority: 'P4' },
      ]),
    )
    withRouter(<InvestigationWorkspace investigationId={fixtures.investigation.investigation_id} />)

    const headline = await screen.findByTestId('attention-headline')
    expect(headline).toHaveTextContent(/2 high-priority cryptographic issues require attention/i)
    // Only the urgent ones are promoted; the INFO finding is not.
    expect(screen.getAllByTestId('attention-item')).toHaveLength(2)
  })

  it('states that no rule failed rather than claiming the systems are secure', async () => {
    mocked.getInvestigation.mockResolvedValue({
      ...fixtures.investigationDetail,
      investigation: { ...fixtures.investigation, finding_count: 0, severity_counts: {} },
    })
    mocked.listFindings.mockResolvedValue(fixtures.page([]))
    withRouter(<InvestigationWorkspace investigationId={fixtures.investigation.investigation_id} />)

    const panel = await screen.findByTestId('needs-attention')
    expect(panel).toHaveTextContent(/No findings were raised/i)
    expect(panel).toHaveTextContent(/not a conclusion that the analysed systems are secure/i)
  })

  it('shows partial batch failures rather than hiding them', async () => {
    mocked.getInvestigation.mockResolvedValue({
      ...fixtures.investigationDetail,
      captures: [fixtures.capture, fixtures.failedCapture],
      jobs: [fixtures.job, fixtures.failedJob],
      investigation: { ...fixtures.investigation, failed_capture_count: 1 },
    })
    withRouter(<InvestigationWorkspace investigationId="inv-1234567890ab" />)
    expect(await screen.findByText(/Partial batch failures/i)).toBeInTheDocument()
    expect(screen.getByText(/do not cover these captures/i)).toBeInTheDocument()
  })

  it('shows NOT ANALYSED for an investigation with no score yet', async () => {
    mocked.getInvestigation.mockResolvedValue({
      ...fixtures.investigationDetail,
      investigation: { ...fixtures.investigation, status: 'QUEUED', posture_score: null, score_status: null },
    })
    withRouter(<InvestigationWorkspace investigationId="inv-1234567890ab" />)
    expect(await screen.findByText('NOT ANALYSED')).toBeInTheDocument()
  })
})

describe('Session explorer', () => {
  beforeEach(() => {
    mocked.listSessions.mockResolvedValue(fixtures.page([fixtures.session]))
  })

  it('renders real session data', async () => {
    withSelection(<Sessions />)
    expect(await screen.findByText('TLS_RSA_WITH_AES_128_CBC_SHA')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.25:993')).toBeInTheDocument()
  })

  it('passes a filter to the backend rather than filtering locally', async () => {
    withSelection(<Sessions />)
    await screen.findByTestId('session-table')
    await userEvent.selectOptions(screen.getByTestId('tls-filter'), 'TLS 1.2')
    await waitFor(() =>
      expect(mocked.listSessions).toHaveBeenLastCalledWith(
        fixtures.investigation.investigation_id,
        expect.objectContaining({ tls_version: 'TLS 1.2' }),
      ),
    )
  })

  it('prompts for an investigation when none is selected', async () => {
    withRouter(<Sessions />)
    expect(await screen.findByText(/No investigation selected/i)).toBeInTheDocument()
  })
})

describe('Session detail', () => {
  it('shows NOT AVAILABLE for a TLS 1.3 certificate rather than a blank', async () => {
    mocked.getSession.mockResolvedValue({
      ...fixtures.sessionDetail,
      session: fixtures.tls13Session,
      findings: [],
    })
    withRouter(<SessionDetailPage />, '/sessions/sess-tls13000000001')
    render(
      <MemoryRouter initialEntries={['/sessions/sess-tls13000000001']}>
        <InvestigationProvider>
          <Routes><Route path="/sessions/:sessionId" element={<SessionDetailPage />} /></Routes>
        </InvestigationProvider>
      </MemoryRouter>,
    )
    expect(await screen.findAllByText(/NOT AVAILABLE/)).not.toHaveLength(0)
    expect(screen.getAllByText(/TLS 1.3 encrypts the Certificate message/i)).not.toHaveLength(0)
  })

  it('shows NO FINDINGS for a clean session', async () => {
    mocked.getSession.mockResolvedValue({ ...fixtures.sessionDetail, findings: [] })
    render(
      <MemoryRouter initialEntries={['/sessions/sess-efe8cce0daf09e49']}>
        <InvestigationProvider>
          <Routes><Route path="/sessions/:sessionId" element={<SessionDetailPage />} /></Routes>
        </InvestigationProvider>
      </MemoryRouter>,
    )
    expect(await screen.findByText('NO FINDINGS')).toBeInTheDocument()
  })
})

describe('Cryptographic intelligence', () => {
  beforeEach(() => {
    mocked.getInvestigation.mockResolvedValue(fixtures.investigationDetail)
  })

  it('does not render one section\u2019s rows under another section\u2019s tab', async () => {
    // The hook keeps the previous result while the next request is in flight.
    // Without a check that the loaded document belongs to the tab now
    // selected, clicking "Server entities" rendered the fingerprint rows in
    // the entities table -- every field it reads missing, and every React key
    // undefined. The fix is asserted here rather than left to a console
    // warning nobody reads.
    mocked.getIntelligence.mockImplementation(async (_id: string, section?: string) => {
      if (section === 'fingerprints') {
        return {
          section: 'fingerprints',
          items: [{
            fingerprint_id: 'smsfp/1:aaaaaaaaaaaa',
            algorithm_version: 'smsfp/1',
            completeness: 'PARTIAL',
            endpoint: { ip: '198.51.100.25', port: 993 },
            missing_components: ['alpn_selected'],
          }],
          scope_statement: 'Covers only the captures listed.',
        }
      }
      // Never resolves: the entities tab stays in flight for the whole test,
      // which is exactly the window the defect lived in.
      return new Promise(() => {})
    })

    withSelection(<Intelligence />)
    expect(await screen.findByText('smsfp/1:aaaaaaaaaaaa')).toBeInTheDocument()

    await userEvent.click(screen.getByTestId('tab-entities'))

    // The symptom was structural rather than textual: an entities table was
    // rendered from fingerprint objects, so it had a row per fingerprint with
    // every cell empty. Assert the table is not there at all while the
    // entities request is still in flight.
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent(/loading intelligence/i)
    })
    expect(screen.queryAllByRole('table')).toHaveLength(0)
    expect(screen.queryByText('smsfp/1:aaaaaaaaaaaa')).not.toBeInTheDocument()
  })
})

describe('Findings and evidence navigation', () => {
  beforeEach(() => {
    mocked.getInvestigation.mockResolvedValue(fixtures.investigationDetail)
    mocked.listFindings.mockResolvedValue(fixtures.page([fixtures.finding]))
    mocked.getFinding.mockResolvedValue(fixtures.findingDetail)
  })

  it('shows the score and coverage together', async () => {
    withSelection(<Findings />)
    expect(await screen.findByText('59')).toBeInTheDocument()
    expect(screen.getByText('76%')).toBeInTheDocument()
    expect(screen.getByText(/does not reduce the severity/i)).toBeInTheDocument()
  })

  it('navigates from a finding to its packet evidence', async () => {
    withSelection(<Findings />)
    await userEvent.click(await screen.findByTestId('finding-row'))
    const detail = await screen.findByTestId('finding-detail')
    await userEvent.click(within(detail).getByTestId('evidence-toggle'))
    const panel = await screen.findByTestId('evidence-panel')
    expect(within(panel).getByText('#4')).toBeInTheDocument()
    expect(within(panel).getByText('#5')).toBeInTheDocument()
    expect(within(panel).getAllByText(/assessment rule TLS-KEX-001/)).toHaveLength(2)
    expect(within(panel).getByText(/payload bytes are never included/i)).toBeInTheDocument()
  })

  it('shows NO FINDINGS rather than an empty table', async () => {
    mocked.listFindings.mockResolvedValue(fixtures.page([]))
    withSelection(<Findings />)
    expect(await screen.findByText('NO FINDINGS')).toBeInTheDocument()
    expect(screen.getByText(/UNKNOWN rule evaluations are not failures/i)).toBeInTheDocument()
  })
})

describe('Timeline', () => {
  it('lists events with their packet evidence', async () => {
    mocked.getInvestigation.mockResolvedValue(fixtures.investigationDetail)
    mocked.getTimeline.mockResolvedValue(fixtures.page(fixtures.timeline))
    withSelection(<Timeline />)
    const list = await screen.findByTestId('timeline-list')
    expect(within(list).getByText(/SESSION FIRST PACKET/i)).toBeInTheDocument()
    expect(within(list).getByText(/packets 4, 5/i)).toBeInTheDocument()
  })

  it('discloses clock limitations for a multi-capture investigation', async () => {
    mocked.getInvestigation.mockResolvedValue({
      ...fixtures.investigationDetail,
      captures: [fixtures.capture, { ...fixtures.capture, capture_id: 'sha256:second' }],
    })
    mocked.getTimeline.mockResolvedValue(fixtures.page(fixtures.timeline))
    withSelection(<Timeline />)
    expect(await screen.findByText(/no synchronisation is assumed/i)).toBeInTheDocument()
  })

  it('filters by event type through the backend', async () => {
    mocked.getInvestigation.mockResolvedValue(fixtures.investigationDetail)
    mocked.getTimeline.mockResolvedValue(fixtures.page(fixtures.timeline))
    withSelection(<Timeline />)
    await screen.findByTestId('timeline-list')
    await userEvent.selectOptions(screen.getByTestId('event-type-filter'), 'CLIENT_HELLO')
    await waitFor(() =>
      expect(mocked.getTimeline).toHaveBeenLastCalledWith(
        fixtures.investigation.investigation_id,
        expect.objectContaining({ event_type: 'CLIENT_HELLO' }),
      ),
    )
  })
})

describe('ML analysis presentation', () => {
  const evaluation = {
    dataset: { generated_sessions: 608, independent_groups: 152 },
    anomaly_selection: {
      selected: 'rarity_baseline',
      selection_rule: 'highest validation F1',
      selected_on: 'validation split only',
    },
    anomaly_metrics: {
      rarity_baseline_test: {
        precision: 1, recall: 1, f1: 1, false_positive_rate: 0,
        true_positives: 8, false_positives: 0, true_negatives: 93, false_negatives: 0,
      },
      isolation_forest_test: {
        precision: 0.4706, recall: 1, f1: 0.64, false_positive_rate: 0.0968,
        true_positives: 8, false_positives: 9, true_negatives: 84, false_negatives: 0,
      },
    },
    classification_metrics: {
      test: {
        macro_f1: 0.5624, accuracy: 0.5248,
        per_class: { HIGH: { precision: 0.9231, recall: 0.3429, f1: 0.5 } },
        support: { HIGH: 35 },
      },
      baseline_most_frequent_test: { macro_f1: 0.1231 },
    },
    classification_selection: { selected: 'logistic_regression', selected_on: 'validation split only' },
  }

  it('never calls the rarity baseline machine learning', async () => {
    mocked.getML.mockResolvedValue({
      summary: fixtures.investigationDetail.ml, results: [], evaluation,
    })
    withSelection(<MLAnalysis />)
    expect(await screen.findByText(/deterministic frequency table, not a machine-learning model/i))
      .toBeInTheDocument()
  })

  it('shows Isolation Forest as an experimental model that was not selected', async () => {
    mocked.getML.mockResolvedValue({
      summary: fixtures.investigationDetail.ml, results: [], evaluation,
    })
    withSelection(<MLAnalysis />)
    expect(await screen.findByText(/Experimental anomaly model — not in use/i)).toBeInTheDocument()
    expect(screen.getByText(/was trained and evaluated, and was not selected/i)).toBeInTheDocument()
  })

  it('reads benchmark numbers from the evaluation record, not from the UI', async () => {
    mocked.getML.mockResolvedValue({
      summary: fixtures.investigationDetail.ml, results: [], evaluation,
    })
    withSelection(<MLAnalysis />)
    // 0.4706 exists only in the supplied evaluation record.
    expect(await screen.findByText('0.4706')).toBeInTheDocument()
    expect(screen.getByText(/macro-F1 0.5624/)).toBeInTheDocument()
  })

  it('always shows the classifier as NOT_VALIDATED', async () => {
    mocked.getML.mockResolvedValue({
      summary: fixtures.investigationDetail.ml, results: [], evaluation,
    })
    withSelection(<MLAnalysis />)
    expect(await screen.findByText(/not confirmed threats/i)).toBeInTheDocument()
    expect(screen.getByText(/not calibrated probabilities/i)).toBeInTheDocument()
  })

  it('handles MODEL_UNAVAILABLE without breaking the page', async () => {
    mocked.getML.mockResolvedValue({ summary: null, results: [], evaluation: null })
    withSelection(<MLAnalysis />)
    expect(await screen.findAllByText('MODEL_UNAVAILABLE')).not.toHaveLength(0)
    expect(
      screen.getByText(/No machine-learning model is installed/i),
    ).toBeInTheDocument()
  })
})

describe('Reports', () => {
  it('offers all three formats once analysis has completed', async () => {
    mocked.getInvestigation.mockResolvedValue(fixtures.investigationDetail)
    withSelection(<Reports />)
    for (const format of ['json', 'html', 'pdf']) {
      expect(await screen.findByTestId(`export-${format}`)).toBeEnabled()
    }
  })

  it('disables export until analysis has completed', async () => {
    mocked.getInvestigation.mockResolvedValue({
      ...fixtures.investigationDetail,
      investigation: { ...fixtures.investigation, status: 'RUNNING' },
    })
    withSelection(<Reports />)
    expect(await screen.findByTestId('export-pdf')).toBeDisabled()
    expect(screen.getByText(/has not completed analysis/i)).toBeInTheDocument()
  })

  it('downloads a generated report', async () => {
    mocked.getInvestigation.mockResolvedValue(fixtures.investigationDetail)
    mocked.download.mockResolvedValue(new Blob(['{}'], { type: 'application/json' }))
    URL.createObjectURL = vi.fn(() => 'blob:mock')
    URL.revokeObjectURL = vi.fn()
    withSelection(<Reports />)
    await userEvent.click(await screen.findByTestId('export-json'))
    await waitFor(() => expect(mocked.download).toHaveBeenCalledWith(
      fixtures.investigation.investigation_id, 'json',
    ))
    expect(await screen.findByText('Downloaded.')).toBeInTheDocument()
  })
})

describe('Navigation', () => {
  it('renders every primary area in the navigation', async () => {
    mocked.listInvestigations.mockResolvedValue(fixtures.page([]))
    withRouter(<App />)
    // The primary workflow, plus Settings held visually secondary. The
    // per-investigation group is asserted separately, because it is
    // deliberately absent until an investigation is selected.
    for (const label of [
      'Investigations', 'Findings', 'Intelligence', 'Reports', 'Settings',
    ]) {
      expect(await screen.findByRole('link', { name: label })).toBeInTheDocument()
    }
    expect(screen.queryByRole('link', { name: 'Sessions' })).toBeNull()
  })

  it('reveals the per-investigation group only once one is selected', async () => {
    // The redesign hides Sessions, Evidence timeline and ML behind a selected
    // investigation. Showing them with nothing selected was a first-time-user
    // trap: every one of them was an empty page with no explanation.
    mocked.listInvestigations.mockResolvedValue(fixtures.page([fixtures.investigation]))
    mocked.getInvestigation.mockResolvedValue(fixtures.investigationDetail)
    withSelection(<App />)
    for (const label of ['Overview', 'Sessions', 'Evidence timeline', 'ML & analytics']) {
      expect(await screen.findByRole('link', { name: label })).toBeInTheDocument()
    }
    expect(screen.getByTestId('selected-investigation')).toHaveTextContent(
      fixtures.investigation.investigation_id,
    )
  })

  it('handles an unknown route without crashing', async () => {
    withRouter(<App />, '/nope/nowhere')
    expect(await screen.findByText(/This page does not exist/i)).toBeInTheDocument()
  })
})
