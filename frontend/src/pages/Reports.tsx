/** Report generation (§17–19). All three formats come from the same backend model. */
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, api } from '../lib/api'
import { useAsync } from '../lib/hooks'
import { useInvestigationContext } from '../lib/context'
import { IconDownload } from '../components/icons'
import { Empty, Failure, Loading, Note, Panel, Value } from '../components/ui'

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
const SEVERITY_COLOUR: Record<string, string> = {
  CRITICAL: '#fb7185', HIGH: '#fb923c', MEDIUM: '#fbbf24', LOW: '#22d3ee', INFO: '#60a5fa',
}

const FORMATS: { key: 'json' | 'html' | 'pdf'; label: string; detail: string }[] = [
  { key: 'json', label: 'JSON', detail: 'The canonical report model, for further processing or archival.' },
  { key: 'html', label: 'HTML', detail: 'A standalone document. Loads no external font, script, stylesheet or image, and makes no network request.' },
  { key: 'pdf', label: 'PDF', detail: 'A4, paginated, with page numbers and generation metadata. Rendered offline.' },
]

export function Reports() {
  const { selected } = useInvestigationContext()
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<string[]>([])

  const detail = useAsync(
    () => (selected ? api.getInvestigation(selected) : Promise.resolve(null)),
    [selected],
  )

  async function download(format: 'json' | 'html' | 'pdf') {
    if (!selected) return
    setBusy(format)
    setError(null)
    try {
      const blob = await api.download(selected, format)
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `securemailscope-${selected}.${format}`
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
      setDone((current) => [...new Set([...current, format])])
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.detail : 'the report could not be generated')
    } finally {
      setBusy(null)
    }
  }

  if (!selected) {
    return <Empty title="No investigation selected"
                  detail="Open an investigation to export its report."
                  action={<Link className="btn btn-primary" to="/investigations">Investigations</Link>} />
  }

  const ready = detail.data?.investigation.status === 'COMPLETED'
  const inv = detail.data?.investigation

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Reports</h1>
        <p className="text-[13px] text-mist-300 mt-0.5">
          All three formats are rendered from one canonical report model, so their facts
          cannot disagree. Presentation differs; capture ids, session counts, finding ids,
          severities, scores and coverage do not.
        </p>
      </header>

      {detail.loading && <Loading what="investigation" />}
      {detail.error && <Failure title="Could not load the investigation" detail={detail.error} />}

      {detail.data && !ready && (
        <Note tone="warn">
          This investigation has not completed analysis, so there is nothing to export yet.
          Its status is {detail.data.investigation.status}.
        </Note>
      )}

      <div className="grid items-start gap-3 xl:grid-cols-[1fr_minmax(320px,400px)]">
        <Panel area="reports" title="Export">
          <div className="space-y-2">
            {FORMATS.map((format) => (
              <div key={format.key}
                   className="surface-sunken flex flex-wrap items-center gap-3 p-2.5">
                <span className="text-area-reports shrink-0" aria-hidden="true">
                  <IconDownload size={16} />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-mist-100">{format.label}</p>
                  <p className="hint mt-0.5 !text-xs">{format.detail}</p>
                </div>
                <button
                  className="btn btn-primary shrink-0"
                  disabled={!ready || busy !== null}
                  data-testid={`export-${format.key}`}
                  onClick={() => download(format.key)}
                >
                  {busy === format.key ? 'Generating…' : `Download ${format.label}`}
                </button>
                {done.includes(format.key) && (
                  <p className="w-full text-[11px] text-sev-ok">Downloaded.</p>
                )}
              </div>
            ))}
          </div>
          {error && <div className="mt-3"><Failure title="Export failed" detail={error} /></div>}
          <Note>
            Reports contain packet references — capture, session, packet number, timestamp
            and stream offset — and never reconstructed payload bytes, credentials, message
            bodies or private keys.
          </Note>
        </Panel>

        {/* What the export will contain, taken from the investigation itself
            rather than described in prose that could drift from it. */}
        {inv && (
          <Panel area="reports" title="What this report will contain">
            <dl className="space-y-1.5 text-[13px]">
              {([
                ['Investigation', inv.name],
                ['Captures analysed', `${inv.analysed_capture_count} of ${inv.capture_count}`],
                ['Sessions', String(inv.session_count)],
                ['Findings', String(inv.finding_count)],
                ['Posture score', inv.posture_score === null
                  ? 'not available' : `${inv.posture_score}/100${inv.score_band ? ` · ${inv.score_band}` : ''}`],
                ['Assessment coverage', inv.coverage_ratio === null
                  ? 'unknown' : `${(inv.coverage_ratio * 100).toFixed(0)}%`],
              ] as [string, string][]).map(([k, v]) => (
                <div key={k} className="flex items-baseline justify-between gap-3 border-b border-ink-820 pb-1.5 last:border-0">
                  <dt className="shrink-0 text-mist-300">{k}</dt>
                  <dd className="min-w-0 truncate text-right font-medium text-mist-100">{v}</dd>
                </div>
              ))}
            </dl>

            {inv.finding_count > 0 && (
              <div className="mt-3">
                <div className="label mb-1.5">Findings by severity</div>
                <ul className="space-y-1">
                  {SEVERITY_ORDER.filter((sev) => (inv.severity_counts?.[sev] ?? 0) > 0).map((sev) => (
                    <li key={sev} className="flex items-center gap-2 text-xs">
                      <span className="h-2 w-2 shrink-0 rounded-sm"
                            style={{ background: SEVERITY_COLOUR[sev] }} aria-hidden="true" />
                      <span className="flex-1 text-mist-200">{sev}</span>
                      <span className="font-semibold tabular-nums">{inv.severity_counts[sev]}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <dl className="mt-3 space-y-1.5 border-t border-ink-820 pt-3 text-[12px]">
              <div>
                <dt className="label">Policy</dt>
                <dd className="mt-0.5"><Value value={detail.data?.policy_id} /></dd>
              </div>
              <div>
                <dt className="label">Policy version</dt>
                <dd className="mono mt-0.5"><Value value={detail.data?.policy_version} /></dd>
              </div>
              <div>
                <dt className="label">Policy fingerprint</dt>
                <dd className="mono mt-0.5 break-all"><Value value={detail.data?.policy_fingerprint} /></dd>
              </div>
            </dl>

            <p className="hint mt-3 !text-3xs break-words">{detail.data?.scope_statement}</p>
          </Panel>
        )}
      </div>
    </div>
  )
}
