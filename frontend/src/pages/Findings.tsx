/**
 * The findings workspace (§13).
 *
 * Scoring and findings are kept visually separate, and coverage sits beside
 * the score. A high-severity finding stays prominent whatever the aggregate
 * says — the score is a summary, not a verdict on each finding.
 */
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../lib/api'
import { useAsync } from '../lib/hooks'
import { useInvestigationContext } from '../lib/context'
import { EvidenceLink } from '../components/EvidenceLink'
import { Empty, Failure, Loading, Note, Pagination, Panel, SeverityTag, Value } from '../components/ui'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const CATEGORIES = ['TLS_PROTOCOL', 'CIPHER_SUITE', 'KEY_EXCHANGE', 'CERTIFICATE', 'EMAIL_TRANSPORT']

export function Findings() {
  const { selected } = useInvestigationContext()
  const { findingId } = useParams()
  const [offset, setOffset] = useState(0)
  const [severity, setSeverity] = useState('')
  const [category, setCategory] = useState('')
  const [expanded, setExpanded] = useState<string | null>(findingId ?? null)

  const investigation = useAsync(
    () => (selected ? api.getInvestigation(selected) : Promise.resolve(null)),
    [selected],
  )
  const page = useAsync(
    () =>
      selected
        ? api.listFindings(selected, {
            offset, limit: 25,
            severity: severity || undefined, category: category || undefined,
          })
        : Promise.resolve(null),
    [selected, offset, severity, category],
  )

  if (!selected) {
    return (
      <Empty title="No investigation selected"
             detail="Open an investigation to review its security findings."
             action={<Link className="btn btn-primary" to="/investigations">Investigations</Link>} />
    )
  }

  const inv = investigation.data?.investigation

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Security findings</h1>
        <p className="text-[13px] text-mist-300 mt-0.5">
          Each finding is a rule that failed on observed evidence. Findings describe
          configuration, not exploitation.
        </p>
      </header>

      {inv && (
        <Panel area="findings" title="Posture score and coverage">
          <div className="flex flex-wrap gap-8 items-start">
            <div>
              <div className="label">Score</div>
              <div className="text-2xl font-semibold mt-1">
                {inv.posture_score === null
                  ? <span className="text-mist-300 text-base">
                      {inv.score_status === 'SCORE_UNAVAILABLE' ? 'INSUFFICIENT EVIDENCE' : 'UNKNOWN'}
                    </span>
                  : <>{inv.posture_score}<span className="text-mist-400 text-base">/100</span></>}
              </div>
              {inv.score_band && <div className="text-[12px] text-mist-300 mt-1">{inv.score_band}</div>}
            </div>
            <div>
              <div className="label">Assessment coverage</div>
              <div className="text-2xl font-semibold mt-1">
                <Value value={inv.coverage_ratio === null ? null : `${(inv.coverage_ratio * 100).toFixed(0)}%`} />
              </div>
              <div className="text-[12px] text-mist-300 mt-1">
                of the applicable policy could be evaluated
              </div>
            </div>
            <div>
              <div className="label">Findings</div>
              <div className="text-2xl font-semibold mt-1">{inv.finding_count}</div>
            </div>
          </div>
          {inv.finding_count > 0 && (
            <Note tone="warn">
              The score above is an aggregate over weighted controls. It does not reduce
              the severity of any individual finding below.
            </Note>
          )}
        </Panel>
      )}

      <Panel>
        <div className="flex flex-wrap gap-2">
          <select className="input" value={severity} data-testid="severity-filter"
                  aria-label="Filter findings by severity"
                  onChange={(e) => { setSeverity(e.target.value); setOffset(0) }}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="input" value={category} data-testid="category-filter"
                  aria-label="Filter findings by category"
                  onChange={(e) => { setCategory(e.target.value); setOffset(0) }}>
            <option value="">All categories</option>
            {CATEGORIES.map((c) => <option key={c} value={c}>{c.replace(/_/g, ' ')}</option>)}
          </select>
        </div>
      </Panel>

      <Panel>
        {page.loading && <Loading what="findings" />}
        {page.error && <Failure title="Could not load findings" detail={page.error} onRetry={page.reload} />}
        {page.data && page.data.items.length === 0 && (
          <Empty title="NO FINDINGS"
                 detail="No rule failed on the evidence available under these filters. UNKNOWN rule evaluations are not failures and are not shown here." />
        )}
        {page.data && page.data.items.length > 0 && (
          <>
            <div className="space-y-2" data-testid="findings-list">
              {page.data.items.map((finding) => (
                <div key={finding.finding_id} className="panel bg-ink-900/50">
                  <button
                    className="w-full text-left p-3 flex flex-wrap items-center gap-2 hover:bg-ink-700/30"
                    onClick={() => setExpanded(expanded === finding.finding_id ? null : finding.finding_id)}
                    aria-expanded={expanded === finding.finding_id}
                    data-testid="finding-row"
                  >
                    <SeverityTag severity={finding.severity} />
                    <span className="text-[13px] font-medium">{finding.title}</span>
                    <span className="mono text-[11px] text-mist-400">{finding.rule_id}</span>
                    {finding.priority && (
                      <span className="text-[11px] text-mist-300">{finding.priority}</span>
                    )}
                    <span className="text-[11px] text-mist-400">confidence {finding.confidence}</span>
                    <Link className="mono text-[11px] text-sev-info hover:underline ml-auto"
                          to={`/sessions/${finding.session_id}`}
                          onClick={(e) => e.stopPropagation()}>
                      {finding.session_id}
                    </Link>
                  </button>
                  {expanded === finding.finding_id && <FindingDetailBlock findingId={finding.finding_id} />}
                </div>
              ))}
            </div>
            <Pagination page={page.data} onOffset={setOffset} />
          </>
        )}
      </Panel>
    </div>
  )
}

function FindingDetailBlock({ findingId }: { findingId: string }) {
  const { selected } = useInvestigationContext()
  const detail = useAsync(() => api.getFinding(findingId, selected), [findingId, selected])
  if (detail.loading) return <div className="px-3 pb-3"><Loading what="finding detail" /></div>
  if (detail.error) return <div className="px-3 pb-3"><Failure title="Could not load detail" detail={detail.error} /></div>
  if (!detail.data) return null
  const d = detail.data
  return (
    <div className="px-3 pb-3 border-t border-ink-700 pt-3" data-testid="finding-detail">
      <p className="text-[13px] text-mist-200">{d.description}</p>
      <p className="text-[12px] text-mist-300 mt-2"><strong>Impact.</strong> {d.technical_impact}</p>

      {d.standards_references.length > 0 && (
        <p className="text-[12px] text-mist-300 mt-2">
          <strong>References.</strong> {d.standards_references.join('; ')}
        </p>
      )}
      {d.remediation_ids.length > 0 && (
        <p className="text-[12px] text-mist-300 mt-2">
          <strong>Remediation.</strong> <span className="mono">{d.remediation_ids.join(', ')}</span>
          {' '}— see the exported report for the full corrective action.
        </p>
      )}
      <p className="text-[11px] text-mist-400 mt-2">
        Evaluated under policy version <span className="mono">{d.policy_version ?? 'unknown'}</span>,
        status {d.finding.evaluation_status}.
      </p>

      <EvidenceLink evidence={d.evidence} limitations={d.limitations} />
    </div>
  )
}
