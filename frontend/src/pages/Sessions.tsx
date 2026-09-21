/** The session explorer (§11): search, sort, filter, paginate — all server-side. */
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api'
import { useAsync } from '../lib/hooks'
import { useInvestigationContext } from '../lib/context'
import { Empty, Failure, Loading, Pagination, Panel, Value } from '../components/ui'

const COLUMNS: { key: string; label: string; sortable?: boolean }[] = [
  { key: 'session_id', label: 'Session', sortable: true },
  { key: 'server', label: 'Server endpoint', sortable: true },
  { key: 'protocol', label: 'Protocol', sortable: true },
  { key: 'detection_status', label: 'Detection' },
  { key: 'tls_version', label: 'TLS', sortable: true },
  { key: 'cipher_suite', label: 'Cipher suite' },
  { key: 'key_exchange', label: 'Key exchange' },
  { key: 'certificate_visibility', label: 'Certificate' },
  { key: 'posture_score', label: 'Assessment', sortable: true },
  { key: 'completeness', label: 'Evidence' },
]

export function Sessions() {
  const { selected } = useInvestigationContext()
  const [offset, setOffset] = useState(0)
  const [search, setSearch] = useState('')
  const [protocol, setProtocol] = useState('')
  const [tls, setTls] = useState('')
  const [sort, setSort] = useState('session_id')
  const [direction, setDirection] = useState<'asc' | 'desc'>('asc')

  const page = useAsync(
    () =>
      selected
        ? api.listSessions(selected, {
            offset, limit: 25, search: search || undefined,
            protocol: protocol || undefined, tls_version: tls || undefined,
            sort, direction,
          })
        : Promise.resolve(null),
    [selected, offset, search, protocol, tls, sort, direction],
  )

  if (!selected) {
    return (
      <Empty
        title="No investigation selected"
        detail="Open an investigation to explore its sessions."
        action={<Link className="btn btn-primary" to="/investigations">Investigations</Link>}
      />
    )
  }

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Sessions</h1>
        <p className="text-[13px] text-mist-300 mt-0.5">
          Reconstructed TCP sessions in the selected investigation.
        </p>
      </header>

      <Panel>
        <div className="flex flex-wrap gap-2 items-center">
          {/* A placeholder is not an accessible name: it is not reliably
              announced and it disappears the moment the analyst types. */}
          <input className="input flex-1 min-w-[200px]" placeholder="Search session, endpoint or cipher suite"
                 aria-label="Search sessions by session id, endpoint or cipher suite"
                 value={search} data-testid="session-search"
                 onChange={(e) => { setSearch(e.target.value); setOffset(0) }} />
          <select className="input" value={protocol} data-testid="protocol-filter"
                  aria-label="Filter sessions by protocol"
                  onChange={(e) => { setProtocol(e.target.value); setOffset(0) }}>
            <option value="">All protocols</option>
            {['SMTP', 'IMAP', 'POP3', 'UNKNOWN'].map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <select className="input" value={tls} data-testid="tls-filter"
                  aria-label="Filter sessions by TLS version"
                  onChange={(e) => { setTls(e.target.value); setOffset(0) }}>
            <option value="">All TLS versions</option>
            {['TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'].map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
      </Panel>

      <Panel>
        {page.loading && <Loading what="sessions" />}
        {page.error && <Failure title="Could not load sessions" detail={page.error} onRetry={page.reload} />}
        {page.data && page.data.items.length === 0 && (
          <Empty title="No sessions match" detail="Adjust the filters, or the investigation may contain no TCP sessions." />
        )}
        {page.data && page.data.items.length > 0 && (
          <>
            <div className="overflow-x-auto">
              <table className="w-full" data-testid="session-table">
                <thead>
                  <tr>
                    {COLUMNS.map((column) => (
                      <th key={column.key} className="th">
                        {column.sortable ? (
                          <button
                            className="hover:text-mist-100"
                            onClick={() => {
                              if (sort === column.key) setDirection(direction === 'asc' ? 'desc' : 'asc')
                              else { setSort(column.key); setDirection('asc') }
                              setOffset(0)
                            }}
                          >
                            {column.label}
                            {sort === column.key && <span>{direction === 'asc' ? ' ▲' : ' ▼'}</span>}
                          </button>
                        ) : column.label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {page.data.items.map((session) => (
                    <tr key={session.session_id} className="hover:bg-ink-700/40">
                      <td className="td">
                        <Link className="mono text-sev-info hover:underline" to={`/sessions/${session.session_id}`}>
                          {session.session_id}
                        </Link>
                      </td>
                      <td className="td mono">{session.server}</td>
                      <td className="td"><Value value={session.protocol} /></td>
                      <td className="td text-[11px] text-mist-300"><Value value={session.detection_status} /></td>
                      <td className="td"><Value value={session.tls_version} /></td>
                      <td className="td mono text-[11px]"><Value value={session.cipher_suite} /></td>
                      <td className="td"><Value value={session.key_exchange} /></td>
                      <td className="td text-[11px]">
                        <Value value={session.certificate_visibility}
                               kind={session.tls_version === 'TLS 1.3' ? 'not-available' : 'unknown'} />
                      </td>
                      <td className="td">
                        {session.posture_score === null ? (
                          <span className="text-[11px] text-mist-300">{session.score_status ?? 'UNKNOWN'}</span>
                        ) : (
                          <span>{session.posture_score}
                            {session.finding_count > 0 && (
                              <span className="text-sev-high text-[11px]"> · {session.finding_count} finding
                                {session.finding_count === 1 ? '' : 's'}</span>
                            )}
                          </span>
                        )}
                      </td>
                      <td className="td text-[11px] text-mist-300"><Value value={session.completeness} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page.data} onOffset={setOffset} />
          </>
        )}
      </Panel>
    </div>
  )
}
