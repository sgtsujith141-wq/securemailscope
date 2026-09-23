/**
 * The overview (§9).
 *
 * Every number comes from the API. The page distinguishes three states that
 * look alike if you render them all as zero: NO FINDINGS (analysed, nothing
 * failed), NOT ANALYSED (no analysis has run) and INSUFFICIENT EVIDENCE
 * (analysed, but the evidence could not support a score).
 */
import { Link } from 'react-router-dom'

import { FirstRun } from '../components/FirstRun'
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../lib/api'
import { useAsync } from '../lib/hooks'
import { Empty, Failure, Loading, Note, Panel, SeverityTag, StatusTag, Value } from '../components/ui'

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const SEVERITY_FILL: Record<string, string> = {
  CRITICAL: '#fb7185', HIGH: '#fb923c', MEDIUM: '#fbbf24', LOW: '#22d3ee', INFO: '#60a5fa',
}
const PROTOCOL_FILL: Record<string, string> = {
  SMTP: '#60a5fa', IMAP: '#a78bfa', POP3: '#e879b9', UNKNOWN: '#64748b',
}

export function Overview() {
  const health = useAsync(() => api.health(), [])
  const list = useAsync(() => api.listInvestigations(0, 100), [])

  if (list.loading) return <Loading what="investigations" />
  if (list.error) return <Failure title="Could not load investigations" detail={list.error} onRetry={list.reload} />

  const investigations = list.data?.items ?? []
  const analysed = investigations.filter((item) => item.status === 'COMPLETED')

  // Nothing analysed yet: explain the product rather than the database.
  if (investigations.length === 0) return <FirstRun />

  const totalCaptures = investigations.reduce((sum, i) => sum + i.analysed_capture_count, 0)
  const failedCaptures = investigations.reduce((sum, i) => sum + i.failed_capture_count, 0)
  const totalSessions = investigations.reduce((sum, i) => sum + i.session_count, 0)
  const totalFindings = investigations.reduce((sum, i) => sum + i.finding_count, 0)

  const severities: Record<string, number> = {}
  const protocols: Record<string, number> = {}
  for (const item of investigations) {
    for (const [key, count] of Object.entries(item.severity_counts ?? {})) {
      severities[key] = (severities[key] ?? 0) + count
    }
    for (const [key, count] of Object.entries(item.protocol_counts ?? {})) {
      protocols[key] = (protocols[key] ?? 0) + count
    }
  }

  const unscored = analysed.filter((item) => item.posture_score === null)
  const coverageValues = analysed.map((i) => i.coverage_ratio).filter((v): v is number => v !== null)
  const meanCoverage = coverageValues.length
    ? coverageValues.reduce((a, b) => a + b, 0) / coverageValues.length
    : null

  const severityData = SEVERITY_ORDER
    .filter((name) => severities[name])
    .map((name) => ({ name, count: severities[name] }))

  const worst = SEVERITY_ORDER.find((name) => severities[name] > 0)

  return (
    <div className="space-y-5">
      <header className="hero hero-grid flex flex-wrap items-end justify-between gap-x-8 gap-y-4 px-4 py-4">
        <div className="min-w-0">
          <span className="label">Estate overview</span>
          <h1 className="mt-1 text-2xl font-semibold leading-tight tracking-[-0.02em] text-mist-50">
            {investigations.length} investigation{investigations.length === 1 ? '' : 's'},
            {' '}{totalCaptures} capture{totalCaptures === 1 ? '' : 's'} analysed
          </h1>
          {/* Kept verbatim: this restates the engine's own scope statement,
              which is spelled "analyzed". Rewording it here would let the two
              drift apart. */}
          <p className="hint mt-1 max-w-xl !text-sm">
            Observed within analyzed captures only. These counts describe the captures
            listed below and nothing beyond them.
          </p>
        </div>

        <dl className="flex flex-wrap items-end gap-x-7 gap-y-3">
          <div>
            <dt className="label">Sessions observed</dt>
            <dd className="mt-0.5 text-3xl font-semibold leading-none tabular-nums">
              {totalSessions}
            </dd>
          </div>
          <div>
            <dt className="label">Security findings</dt>
            <dd className="mt-0.5 text-3xl font-semibold leading-none tabular-nums"
                style={{ color: totalFindings === 0 ? '#34d399' : SEVERITY_FILL[worst ?? 'INFO'] }}>
              {totalFindings === 0 ? <span className="text-base">NO FINDINGS</span> : totalFindings}
            </dd>
            <dd className="hint mt-1 !text-3xs">
              {totalFindings === 0
                ? 'no rule failed on the available evidence'
                : `highest severity ${worst}`}
            </dd>
          </div>
          <div>
            <dt className="label">Assessment coverage</dt>
            <dd className="mt-0.5 text-3xl font-semibold leading-none tabular-nums">
              {meanCoverage === null
                ? <span className="text-base text-mist-300">UNKNOWN</span>
                : `${(meanCoverage * 100).toFixed(0)}%`}
            </dd>
            <dd className="hint mt-1 !text-3xs">
              {meanCoverage === null
                ? 'no analysed investigation reported coverage'
                : `mean across ${coverageValues.length} investigation(s)`}
            </dd>
          </div>
          {failedCaptures > 0 && (
            <div>
              <dt className="label">Failed to analyse</dt>
              <dd className="mt-0.5 text-3xl font-semibold leading-none tabular-nums text-sev-critical">
                {failedCaptures}
              </dd>
            </div>
          )}
        </dl>
      </header>

      {totalFindings > 0 && (
        <Note tone="warn">
          A numerically adequate score does not remove an individual finding. The
          highest severity observed is <strong>{worst}</strong>; open the findings
          workspace to see every one.
        </Note>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Findings by severity">
          {severityData.length === 0 ? (
            <Empty title="No findings" detail="No rule failed on the evidence available. This is not a statement that the analysed systems are secure." />
          ) : (
            <div style={{ height: 180 }}>
              <ResponsiveContainer width="100%" height="100%">
                {/* `maxBarSize` matters: without it Recharts stretches three
                    categories into three slabs the width of the panel, which
                    reads as decoration rather than as a measurement. */}
                <BarChart data={severityData} margin={{ top: 4, right: 8, bottom: 4, left: -18 }}
                          barCategoryGap="28%" maxBarSize={56}>
                  <XAxis dataKey="name" tick={{ fill: '#93a3bb', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fill: '#93a3bb', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#161d2b', border: '1px solid #263449', borderRadius: 6, fontSize: 12 }} />
                  <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                    {severityData.map((entry) => (
                      <Cell key={entry.name} fill={SEVERITY_FILL[entry.name]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>

        <Panel title="Protocol distribution">
          {Object.keys(protocols).length === 0 ? (
            <Empty title="No email protocol was identified" detail="Sessions may have been implicit TLS, where a port is a hint rather than an identification." />
          ) : (
            (() => {
              const rows = Object.entries(protocols).sort((a, b) => b[1] - a[1])
              const total = rows.reduce((sum, [, n]) => sum + n, 0)
              return (
                <>
                  <div className="flex h-2.5 w-full gap-px overflow-hidden rounded-full bg-ink-820"
                       role="img"
                       aria-label={rows.map(([k, n]) => `${n} ${k}`).join(', ')}>
                    {rows.map(([name, count]) => (
                      <span key={name}
                            style={{ width: `${(count / total) * 100}%`,
                                     background: PROTOCOL_FILL[name] ?? '#64748b' }} />
                    ))}
                  </div>
                  <ul className="mt-3 space-y-1.5">
                    {rows.map(([name, count]) => (
                      <li key={name} className="flex items-center gap-2 text-[13px]">
                        <span className="h-2.5 w-2.5 shrink-0 rounded-sm"
                              style={{ background: PROTOCOL_FILL[name] ?? '#64748b' }}
                              aria-hidden="true" />
                        <span className="flex-1 text-mist-200">{name}</span>
                        <span className="font-semibold tabular-nums text-mist-100">{count}</span>
                        <span className="w-10 text-right tabular-nums text-mist-400">
                          {Math.round((count / total) * 100)}%
                        </span>
                      </li>
                    ))}
                  </ul>
                  <p className="hint mt-2 !text-3xs">
                    Identified from the dialogue, never from the port number.
                  </p>
                </>
              )
            })()
          )}
        </Panel>
      </div>

      <Panel title="Posture scores">
        {analysed.length === 0 ? (
          <Empty title="NOT ANALYSED" detail="No investigation has completed analysis yet." />
        ) : (
          <>
            <table className="w-full">
              <thead>
                <tr>
                  <th className="th">Investigation</th><th className="th">Status</th>
                  <th className="th">Score</th><th className="th">Coverage</th>
                  <th className="th">Findings</th>
                </tr>
              </thead>
              <tbody>
                {analysed.map((item) => (
                  <tr key={item.investigation_id}>
                    <td className="td">
                      <Link className="text-sev-info hover:underline" to={`/investigations/${item.investigation_id}`}>
                        {item.name}
                      </Link>
                      <div className="mono text-mist-400 text-[11px]">{item.investigation_id}</div>
                    </td>
                    <td className="td"><StatusTag status={item.status} /></td>
                    <td className="td">
                      {item.posture_score === null ? (
                        <span className="text-[11px] text-mist-300">
                          INSUFFICIENT EVIDENCE
                          <div className="text-mist-400">{item.score_status}</div>
                        </span>
                      ) : (
                        <span>{item.posture_score}<span className="text-mist-400">/100</span>{' '}
                          <span className="text-mist-300 text-[11px]">{item.score_band}</span>
                        </span>
                      )}
                    </td>
                    <td className="td">
                      <Value value={item.coverage_ratio === null ? null : `${(item.coverage_ratio * 100).toFixed(0)}%`} />
                    </td>
                    <td className="td">
                      {item.finding_count === 0
                        ? <span className="text-[11px] text-sev-ok">NO FINDINGS</span>
                        : <span className="flex gap-1 flex-wrap">
                            {SEVERITY_ORDER.filter((s) => item.severity_counts?.[s]).map((s) => (
                              <span key={s} className="inline-flex items-center gap-1">
                                <SeverityTag severity={s} />
                                <span className="text-[11px] text-mist-300">{item.severity_counts[s]}</span>
                              </span>
                            ))}
                          </span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {unscored.length > 0 && (
              <Note>
                {unscored.length} analysed investigation(s) produced no score. That is not a
                score of zero: the evidence did not cover enough of the policy for a number
                to mean anything.
              </Note>
            )}
          </>
        )}
      </Panel>

      <Panel title="Analysis capabilities">
        {health.loading && <Loading what="system status" />}
        {health.error && <Failure title="Could not read system status" detail={health.error} />}
        {health.data && (
          <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-[13px]">
            <div><dt className="label">Report schema</dt><dd className="mono mt-1">{health.data.report_schema_version}</dd></div>
            <div><dt className="label">Database schema</dt><dd className="mono mt-1">v{health.data.database_schema_version}</dd></div>
            <div><dt className="label">ML status</dt><dd className="mt-1">{health.data.ml_status}</dd></div>
            <div>
              <dt className="label">Cryptographic intelligence</dt>
              <dd className="mt-1">{investigations.some((i) => i.status === 'COMPLETED') ? 'Available' : 'Not yet available'}</dd>
            </div>
          </dl>
        )}
        <Note>
          The forensic analysis is complete with or without a machine-learning model. ML
          results are advisory and never modify a finding or a score.
        </Note>
      </Panel>
    </div>
  )
}
