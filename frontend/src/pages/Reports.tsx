/** Report generation (§17–19). All three formats come from the same backend model. */
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, api } from '../lib/api'
import { useAsync } from '../lib/hooks'
import { useInvestigationContext } from '../lib/context'
import { Empty, Failure, Loading, Note, Panel } from '../components/ui'

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

      <Panel title="Export">
        <div className="grid gap-3 sm:grid-cols-3">
          {FORMATS.map((format) => (
            <div key={format.key} className="panel bg-ink-900/50 p-3 flex flex-col">
              <p className="text-sm font-medium">{format.label}</p>
              <p className="text-[12px] text-mist-300 mt-1 flex-1">{format.detail}</p>
              <button
                className="btn btn-primary mt-3"
                disabled={!ready || busy !== null}
                data-testid={`export-${format.key}`}
                onClick={() => download(format.key)}
              >
                {busy === format.key ? 'Generating…' : `Download ${format.label}`}
              </button>
              {done.includes(format.key) && (
                <p className="text-[11px] text-sev-ok mt-2">Downloaded.</p>
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
    </div>
  )
}
