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
import { Empty, Failure, Loading, Metric, Note, Panel, SeverityTag, StatusTag, Value } from '../components/ui'

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const SEVERITY_FILL: Record<string, string> = {
  CRITICAL: '#ff6b6b', HIGH: '#ffa657', MEDIUM: '#ffd479', LOW: '#7fd1c1', INFO: '#8ab4f8',
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
      <header>
        <h1 className="text-xl font-semibold">Overview</h1>
        <p className="text-[13px] text-mist-300 mt-0.5">
          Observed within analyzed captures only. These counts describe the captures listed
          below and nothing beyond them.
        </p>
      </header>

      <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
        <Metric label="Captures analysed" value={totalCaptures}
                note={failedCaptures > 0 ? `${failedCaptures} failed to analyse` : undefined} />
        <Metric label="Sessions observed" value={totalSessions} />
        <Metric
          label="Security findings"
          value={totalFindings === 0 ? <span className="text-sev-ok text-base">NO FINDINGS</span> : totalFindings}
          note={totalFindings === 0
            ? 'No rule failed on the available evidence'
            : `highest severity ${worst}`}
          tone={totalFindings === 0 ? 'unknown' : 'default'}
        />
        <Metric
          label="Assessment coverage"
          value={meanCoverage === null
            ? <span className="text-mist-300 text-base">UNKNOWN</span>
            : `${(meanCoverage * 100).toFixed(0)}%`}
          note={meanCoverage === null
            ? 'no analysed investigation reported coverage'
            : `mean across ${coverageValues.length} investigation(s)`}
          tone={meanCoverage === null ? 'unknown' : 'default'}
        />
      </div>

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
                <BarChart data={severityData} margin={{ top: 4, right: 8, bottom: 4, left: -18 }}>
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
            <table className="w-full">
              <thead><tr><th className="th">Protocol</th><th className="th">Sessions</th></tr></thead>
              <tbody>
                {Object.entries(protocols).sort().map(([name, count]) => (
                  <tr key={name}><td className="td">{name}</td><td className="td">{count}</td></tr>
                ))}
              </tbody>
            </table>
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
