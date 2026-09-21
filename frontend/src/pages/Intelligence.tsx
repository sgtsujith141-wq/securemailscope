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
import { Empty, Failure, Loading, Note, Panel, Value } from '../components/ui'

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

export function Intelligence() {
  const { selected } = useInvestigationContext()
  const [tab, setTab] = useState<Tab>('fingerprints')
  const data = useAsync(
    () => (selected ? api.getIntelligence(selected, tab) : Promise.resolve(null)),
    [selected, tab],
  )

  if (!selected) {
    return <Empty title="No investigation selected"
                  action={<Link className="btn btn-primary" to="/investigations">Investigations</Link>} />
  }

  const items = (data.data?.items as Record<string, any>[]) ?? []

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Cryptographic intelligence</h1>
        <p className="text-[13px] text-mist-300 mt-0.5">
          {(data.data?.scope_statement as string) ?? 'Observed within analyzed captures only.'}
        </p>
      </header>

      <div className="flex flex-wrap gap-1.5">
        {TABS.map((item) => (
          <button key={item.key}
                  className={`btn py-1 ${tab === item.key ? 'btn-primary' : ''}`}
                  data-testid={`tab-${item.key}`}
                  onClick={() => setTab(item.key)}>
            {item.label}
          </button>
        ))}
      </div>

      <Panel>
        {data.loading && <Loading what="intelligence" />}
        {data.error && <Failure title="Could not load intelligence" detail={data.error} onRetry={data.reload} />}
        {data.data && items.length === 0 && (
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
            <table className="w-full" data-testid="drift-table">
              <thead><tr>
                <th className="th">Property</th><th className="th">Status</th>
                <th className="th">Before</th><th className="th">After</th>
                <th className="th">Offers comparable</th><th className="th">Explanation</th>
              </tr></thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.drift_id}>
                    <td className="td text-[12px]">{item.kind}</td>
                    <td className={`td text-[12px] font-medium ${DRIFT_TONE[item.status] ?? ''}`}>
                      {item.status}
                    </td>
                    <td className="td mono text-[11px]">
                      {item.before?.observed ? item.before?.value : <span className="text-mist-400">not observed</span>}
                      <div className="text-mist-400 text-[10px]">{item.before?.capture_id?.slice(0, 20)}</div>
                    </td>
                    <td className="td mono text-[11px]">
                      {item.after?.observed ? item.after?.value : <span className="text-mist-400">not observed</span>}
                      <div className="text-mist-400 text-[10px]">{item.after?.capture_id?.slice(0, 20)}</div>
                    </td>
                    <td className="td text-[11px]">
                      <Value value={item.client_offers_comparable === null ? null : String(item.client_offers_comparable)}
                             kind="not-applicable" />
                    </td>
                    <td className="td text-[12px] text-mist-300">{item.explanation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
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
