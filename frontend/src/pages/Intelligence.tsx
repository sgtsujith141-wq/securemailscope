/**
 * Cryptographic intelligence (§14).
 *
 * The caveats are part of the interface, not a footnote: a fingerprint does
 * not establish identity, a drift status is not automatically a server change,
 * and a blast radius covers analysed captures only. No topology is drawn,
 * because none is observed.
 */
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api'
import { useAsync } from '../lib/hooks'
import { useInvestigationContext } from '../lib/context'
import { IconArrowRight } from '../components/icons'
import { Empty, Failure, Loading, Note, Panel, Value } from '../components/ui'

/** One half of a drift comparison. An unobserved side says so explicitly
 *  rather than rendering an empty cell a reader could mistake for a value. */
function DriftSide({ label, side, tone = 'same' }: {
  label: string
  side: { observed?: boolean; value?: unknown; capture_id?: string } | undefined
  tone?: 'same' | 'changed'
}) {
  const observed = Boolean(side?.observed)
  return (
    <div className={`rounded-md border px-2.5 py-1.5 ${
      tone === 'changed' ? 'border-sev-high/40 bg-sev-high/[0.06]' : 'border-ink-780 bg-ink-900'
    }`}>
      <div className="flex items-baseline gap-2">
        <span className="label shrink-0">{label}</span>
        <span className="mono min-w-0 flex-1 !text-[12px] !text-mist-100">
          {observed
            ? String(side?.value)
            : <span className="text-mist-400">not observed</span>}
        </span>
      </div>
      {side?.capture_id && (
        <div className="hint mt-0.5 truncate !text-3xs" title={side.capture_id}>
          {side.capture_id}
        </div>
      )}
    </div>
  )
}

type Tab = 'fingerprints' | 'entities' | 'drift' | 'correlations' | 'blast_radius'
const TABS: { key: Tab; label: string }[] = [
  { key: 'fingerprints', label: 'Cryptographic DNA' },
  { key: 'entities', label: 'Server entities' },
  { key: 'drift', label: 'Drift' },
  { key: 'correlations', label: 'Correlations' },
  { key: 'blast_radius', label: 'Blast radius' },
]

const DRIFT_TONE: Record<string, string> = {
  OBSERVED_CHANGE: 'text-sev-high',
  UNCHANGED_WITH_EVIDENCE: 'text-sev-ok',
  INCONCLUSIVE: 'text-sev-medium',
  NOT_COMPARABLE: 'text-mist-300',
}

/**
 * Reading order for the drift tab.
 *
 * The engine orders drift events by entity and property, which is the right
 * order for a machine and the wrong one for a reader: it puts every
 * "not observed, so not comparable" pair above the one property that actually
 * changed. This reorders the same events; it changes no status and drops
 * none of them.
 */
const DRIFT_RANK: Record<string, number> = {
  OBSERVED_CHANGE: 0,
  INCONCLUSIVE: 1,
  UNCHANGED_WITH_EVIDENCE: 2,
  NOT_COMPARABLE: 3,
}

export function Intelligence() {
  const { selected } = useInvestigationContext()
  const [tab, setTab] = useState<Tab>('fingerprints')
  const data = useAsync(
    () => (selected ? api.getIntelligence(selected, tab) : Promise.resolve(null)),
    [selected, tab],
  )
  // Counts come from the investigation the backend already summarised, so a
  // tab can say how much is behind it before it is opened. Blast radius has
  // no count of its own and shows none rather than an invented zero.
  const detail = useAsync(
    () => (selected ? api.getInvestigation(selected) : Promise.resolve(null)),
    [selected],
  )

  if (!selected) {
    return <Empty title="No investigation selected"
                  action={<Link className="btn btn-primary" to="/investigations">Investigations</Link>} />
  }

  // Only render rows that belong to the tab now selected. `useAsync` keeps
  // the previous result while the next request is in flight, so without this
  // the entities table briefly rendered fingerprint objects -- every row
  // missing the fields it reads, and every React key undefined. The response
  // names its own section, so the check uses that rather than a second piece
  // of state that could disagree with it.
  const loaded = data.data?.section === tab
  const items = loaded ? ((data.data?.items as Record<string, any>[]) ?? []) : []
  const counts: Partial<Record<Tab, number>> = detail.data
    ? {
        fingerprints: detail.data.fingerprint_count,
        entities: detail.data.entity_count,
        drift: detail.data.drift_count,
        correlations: detail.data.correlation_count,
      }
    : {}

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Cryptographic intelligence</h1>
        <p className="text-[13px] text-mist-300 mt-0.5">
          {(data.data?.scope_statement as string) ?? 'Observed within analyzed captures only.'}
        </p>
      </header>

      <div className="flex flex-wrap gap-1.5" role="tablist">
        {TABS.map((item) => {
          const active = tab === item.key
          const count = counts[item.key]
          return (
            <button key={item.key}
                    role="tab"
                    aria-selected={active}
                    className={`btn py-1 ${active ? 'btn-primary' : ''}`}
                    data-testid={`tab-${item.key}`}
                    onClick={() => setTab(item.key)}>
              {item.label}
              {count !== undefined && (
                <span className={`ml-1.5 rounded px-1 text-3xs tabular-nums
                                  ${active ? 'bg-ink-980/40' : 'bg-ink-820 text-mist-300'}`}>
                  {count}
                </span>
              )}
            </button>
          )
        })}
      </div>

      <Panel>
        {(data.loading || !loaded) && !data.error && <Loading what="intelligence" />}
        {data.error && <Failure title="Could not load intelligence" detail={data.error} onRetry={data.reload} />}
        {loaded && items.length === 0 && (
          <Empty title="Nothing to show"
                 detail="This investigation produced no results in this category. A single capture cannot produce drift, and correlations need at least two sessions sharing an observation." />
        )}

        {items.length > 0 && tab === 'fingerprints' && (
          <>
            <Note>
              A fingerprint groups configurations. It does <strong>not</strong> establish a
              unique server identity — two unrelated servers running the same defaults
              produce the same value.
            </Note>
            <table className="w-full">
              <thead><tr>
                <th className="th">Fingerprint</th><th className="th">Version</th>
                <th className="th">Completeness</th><th className="th">Endpoint</th>
                <th className="th">Missing components</th>
              </tr></thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.fingerprint_id}>
                    <td className="td mono">{item.fingerprint_id}</td>
                    <td className="td mono text-[11px]">{item.algorithm_version}</td>
                    <td className="td">
                      <span className={item.completeness === 'COMPLETE' ? 'text-sev-ok' : 'text-sev-medium'}>
                        {item.completeness}
                      </span>
                    </td>
                    <td className="td mono">{item.endpoint?.ip}:{item.endpoint?.port}</td>
                    <td className="td text-[11px] text-mist-300">
                      {(item.missing_components ?? []).join(', ') || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}

        {items.length > 0 && tab === 'entities' && (
          <>
            <Note>
              An entity is one observed (ip, port). Entities are never merged on a shared
              certificate, key or name — those appear as typed relationships instead.
            </Note>
            <table className="w-full">
              <thead><tr>
                <th className="th">Entity</th><th className="th">Endpoint</th><th className="th">Sessions</th>
                <th className="th">Captures</th><th className="th">Relationships</th>
              </tr></thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.entity_id}>
                    <td className="td mono text-[11px]">{item.entity_id}</td>
                    <td className="td mono">{item.endpoint?.ip}:{item.endpoint?.port}</td>
                    <td className="td">{(item.session_ids ?? []).length}</td>
                    <td className="td">{(item.capture_ids ?? []).length}</td>
                    <td className="td text-[12px]">
                      {(item.relationships ?? []).length === 0 ? (
                        <span className="text-mist-400 text-[11px]">none</span>
                      ) : (
                        <ul className="space-y-1">
                          {(item.relationships ?? []).map((rel: any, index: number) => (
                            <li key={index}>
                              <span className="text-sev-info">{rel.relation}</span>
                              <span className="mono text-[10px] text-mist-400 ml-1">{rel.basis}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}

        {items.length > 0 && tab === 'drift' && (
          <>
            <Note>
              A different negotiated parameter is not automatically a server configuration
              change. Where the clients offered different things, the comparison is
              reported as INCONCLUSIVE rather than attributed to the server.
            </Note>
            <div className="mb-2 flex flex-wrap gap-1.5">
              {Object.keys(DRIFT_RANK)
                .map((status) => [status, items.filter((i) => i.status === status).length] as const)
                .filter(([, n]) => n > 0)
                .map(([status, n]) => (
                  <span key={status} className={`chip !border-current ${DRIFT_TONE[status] ?? ''}`}>
                    <span className="tabular-nums font-semibold">{n}</span> {status}
                  </span>
                ))}
            </div>
            {/* A before/after pair per property rather than a six-column table:
                the comparison *is* the content, so the layout shows it. */}
            <ul className="space-y-2" data-testid="drift-table">
              {[...items]
                .sort((a, b) =>
                  (DRIFT_RANK[a.status] ?? 9) - (DRIFT_RANK[b.status] ?? 9) ||
                  String(a.kind).localeCompare(String(b.kind)))
                .map((item) => (
                <li key={item.drift_id} className="surface-sunken p-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[13px] font-semibold text-mist-100">
                      {String(item.kind).replace(/_/g, ' ').toLowerCase()}
                    </span>
                    <span className={`chip !border-current ${DRIFT_TONE[item.status] ?? ''}`}>
                      {item.status}
                    </span>
                    <span className="hint ml-auto !text-3xs">
                      client offers comparable:{' '}
                      <Value
                        value={item.client_offers_comparable === null
                          ? null : String(item.client_offers_comparable)}
                        kind="not-applicable"
                      />
                    </span>
                  </div>

                  <div className="mt-2 grid items-stretch gap-2 sm:grid-cols-[1fr_auto_1fr]">
                    <DriftSide label="Before" side={item.before} />
                    <span className="hidden self-center text-mist-500 sm:block" aria-hidden="true">
                      <IconArrowRight size={16} />
                    </span>
                    <DriftSide label="After" side={item.after}
                               tone={item.status === 'OBSERVED_CHANGE' ? 'changed' : 'same'} />
                  </div>

                  <p className="hint mt-2 !text-xs">{item.explanation}</p>
                </li>
              ))}
            </ul>
          </>
        )}

        {items.length > 0 && tab === 'correlations' && (
          <>
            <Note>
              A correlation groups shared observations. It establishes no common ownership,
              administration, cause, actor or intent.
            </Note>
            <table className="w-full">
              <thead><tr>
                <th className="th">Type</th><th className="th">Relationship basis</th>
                <th className="th">Sessions</th><th className="th">Captures</th>
                <th className="th">Findings</th><th className="th">Policies</th>
              </tr></thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.correlation_id}>
                    <td className="td text-[12px]">{item.correlation_type}</td>
                    <td className="td mono text-[11px]">{item.relationship_basis}</td>
                    <td className="td">
                      <ul className="space-y-0.5">
                        {(item.related_session_ids ?? []).slice(0, 4).map((id: string) => (
                          <li key={id}>
                            <Link className="mono text-[11px] text-sev-info hover:underline" to={`/sessions/${id}`}>
                              {id}
                            </Link>
                          </li>
                        ))}
                      </ul>
                    </td>
                    <td className="td">{(item.related_capture_ids ?? []).length}</td>
                    <td className="td">{(item.related_finding_ids ?? []).length}</td>
                    <td className="td text-[11px] text-mist-300">
                      {(item.policy_versions ?? []).join(', ') || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}

        {items.length > 0 && tab === 'blast_radius' && (
          <>
            <table className="w-full" data-testid="blast-table">
              <thead><tr>
                <th className="th">Subject</th><th className="th">Sessions</th>
                <th className="th">Endpoints</th><th className="th">Captures</th>
                <th className="th">Findings</th><th className="th">Protocols</th>
              </tr></thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.subject}>
                    <td className="td mono">{item.subject}</td>
                    <td className="td">{item.session_count}</td>
                    <td className="td">{item.entity_count}</td>
                    <td className="td">{item.capture_count}</td>
                    <td className="td">{item.finding_count}</td>
                    <td className="td text-[11px] text-mist-300">
                      {Object.entries(item.protocol_distribution ?? {})
                        .map(([k, v]) => `${k}: ${v}`).join(', ') || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Note>
              <strong>{items[0].scope_statement}</strong> {items[0].counting_method}
            </Note>
          </>
        )}
      </Panel>
    </div>
  )
}
