/**
 * The lower rows of the investigation dashboard: the evidence timeline rail,
 * the cryptographic drift comparison, and the report hand-off.
 *
 * Each is a preview of a full page rather than a second implementation of it.
 * They render only what the API returned; where the engine reported an event
 * as INFERRED rather than OBSERVED, the rail says so on the event itself
 * instead of letting the reader assume every dot was seen in a packet.
 */
import { useState } from 'react'
import { Link } from 'react-router-dom'

import type { InvestigationDetail, TimelineEntry } from '../lib/api'
import { ApiError, api } from '../lib/api'
import { formatTime } from '../lib/hooks'
import { Empty, Loading } from './ui'
import {
  IconArrowRight, IconClock, IconDownload, IconFingerprint, IconReport,
} from './icons'

const EVENT_TINT: Record<string, string> = {
  OBSERVED: '#22d3ee',
  INFERRED: '#a78bfa',
  UNKNOWN: '#64748b',
  NOT_AVAILABLE: '#64748b',
}

export function TimelinePreview({
  entries, total, loading,
}: {
  entries: TimelineEntry[]
  total: number
  loading?: boolean
}) {
  return (
    <section className="section rule-intelligence" data-testid="timeline-preview">
      <div className="section-head">
        <div className="flex items-center gap-1.5">
          <span className="text-area-intelligence" aria-hidden="true"><IconClock size={14} /></span>
          <h2 className="section-title">Evidence timeline</h2>
        </div>
        <Link className="btn btn-ghost text-xs" to="/timeline">
          All {total}
          <IconArrowRight size={13} />
        </Link>
      </div>

      <div className="section-body">
        {loading ? <Loading what="timeline" />
         : entries.length === 0 ? (
           <Empty title="No timeline events"
                  detail="The analysis recorded no ordered events for these captures." />
         ) : (
          /* A rail rather than a table: the left border is the thread, each
             dot is one event, and the tint is the evidence status. */
          <ol className="relative space-y-3 border-l border-ink-780 pl-4">
            {entries.map((entry) => {
              const tint = EVENT_TINT[entry.evidence_status] ?? '#64748b'
              return (
                <li key={entry.event_id} className="relative">
                  <span
                    className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full border-2 border-ink-900"
                    style={{ background: tint, boxShadow: `0 0 0 3px ${tint}22` }}
                    aria-hidden="true"
                  />
                  <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                    <span className="text-xs font-semibold text-mist-100">
                      {entry.event_type.replace(/_/g, ' ').toLowerCase()}
                    </span>
                    <span className="hint !text-3xs" style={{ color: tint }}>
                      {entry.evidence_status}
                    </span>
                    <span className="hint !text-3xs">{formatTime(entry.timestamp)}</span>
                  </div>
                  <p className="hint mt-0.5 !text-xs !text-mist-300">{entry.description}</p>
                  {entry.packet_numbers.length > 0 && (
                    <p className="hint mt-0.5 !text-3xs">
                      packet {entry.packet_numbers.slice(0, 4).join(', ')}
                      {entry.packet_numbers.length > 4 && ` +${entry.packet_numbers.length - 4}`}
                    </p>
                  )}
                </li>
              )
            })}
          </ol>
        )}
      </div>
    </section>
  )
}

export function IntelligencePreview({ detail }: { detail: InvestigationDetail }) {
  const rows: [string, number, string][] = [
    ['Cryptographic fingerprints', detail.fingerprint_count, '#22d3ee'],
    ['Server entities', detail.entity_count, '#a78bfa'],
    ['Drift observations', detail.drift_count, '#fb923c'],
    ['Session correlations', detail.correlation_count, '#60a5fa'],
  ]
  const peak = Math.max(1, ...rows.map(([, n]) => n))

  return (
    <section className="section rule-intelligence" data-testid="intelligence-preview">
      <div className="section-head">
        <div className="flex items-center gap-1.5">
          <span className="text-area-intelligence" aria-hidden="true">
            <IconFingerprint size={14} />
          </span>
          <h2 className="section-title">Cryptographic intelligence</h2>
        </div>
        <Link className="btn btn-ghost text-xs" to="/intelligence">
          Open
          <IconArrowRight size={13} />
        </Link>
      </div>

      <div className="section-body space-y-2.5">
        {rows.map(([label, n, tint]) => (
          <div key={label}>
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-xs text-mist-200">{label}</span>
              <span className="text-sm font-semibold tabular-nums text-mist-100">{n}</span>
            </div>
            <span className="sevbar mt-1">
              <span style={{ width: `${(n / peak) * 100}%`, background: tint }} />
            </span>
          </div>
        ))}
        <p className="hint !text-3xs">
          A fingerprint identifies a configuration, not an operator. Drift is
          reported as INCONCLUSIVE where the clients offered different things,
          rather than attributed to the server.
        </p>
      </div>
    </section>
  )
}

export function ReportHandoff({
  investigationId, schemaNote,
}: {
  investigationId: string
  /** Rendered verbatim; the caller supplies the engine's own scope wording. */
  schemaNote: string
}) {
  // The export endpoints require the API token, so a bare <a href> would get
  // a 401. The download goes through the same authenticated client the
  // Reports page uses, and `busy` tracks a request genuinely in flight.
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function download(format: 'json' | 'html' | 'pdf') {
    setBusy(format)
    setError(null)
    try {
      const blob = await api.download(investigationId, format)
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `securemailscope-${investigationId}.${format}`
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
    } catch (cause) {
      setError(
        cause instanceof ApiError ? cause.detail : 'the report could not be generated',
      )
    } finally {
      setBusy(null)
    }
  }

  const formats: ['json' | 'html' | 'pdf', string][] = [
    ['pdf', 'Portable report for review'],
    ['html', 'Self-contained, opens offline'],
    ['json', 'Schema-versioned, machine-readable'],
  ]

  return (
    <section className="section rule-reports" data-testid="report-handoff">
      <div className="section-head">
        <div className="flex items-center gap-1.5">
          <span className="text-area-reports" aria-hidden="true"><IconReport size={14} /></span>
          <h2 className="section-title">Export this investigation</h2>
        </div>
        <Link className="btn btn-ghost text-xs" to="/reports">
          Reports
          <IconArrowRight size={13} />
        </Link>
      </div>

      <div className="section-body">
        <ul className="space-y-1.5">
          {formats.map(([format, note]) => (
            <li key={format}>
              <button
                type="button"
                className="row-link flex w-full items-center gap-2.5 rounded-md border
                           border-ink-820 px-2.5 py-2 text-left disabled:opacity-60"
                disabled={busy !== null}
                onClick={() => void download(format)}
              >
                <span className="text-area-reports" aria-hidden="true">
                  <IconDownload size={14} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium text-mist-100">
                    {format.toUpperCase()}
                  </span>
                  <span className="hint !text-3xs">{note}</span>
                </span>
                {busy === format
                  ? <span className="hint !text-3xs">generating…</span>
                  : <IconArrowRight size={13} />}
              </button>
            </li>
          ))}
        </ul>
        {error && <p className="mt-2 text-xs text-sev-critical" role="alert">{error}</p>}
        <p className="hint mt-2 !text-3xs break-words">{schemaNote}</p>
      </div>
    </section>
  )
}
