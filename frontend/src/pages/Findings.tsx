/**
 * The findings workspace (§13).
 *
 * A master/detail investigation surface rather than a stack of identical
 * rows: the list on the left stays visible while the detail on the right
 * carries the description, impact, references and the packet evidence chain.
 *
 * Scoring and findings are kept visually separate, and coverage sits beside
 * the score. A high-severity finding stays prominent whatever the aggregate
 * says — the score is a summary, not a verdict on each finding.
 */
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import { api } from '../lib/api'
import { useAsync } from '../lib/hooks'
import { useInvestigationContext } from '../lib/context'
import { EvidenceLink } from '../components/EvidenceLink'
import { IconAlert, IconArrowRight, IconSessions } from '../components/icons'
import { Empty, Failure, Loading, Note, Pagination, Panel, Value } from '../components/ui'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const CATEGORIES = ['TLS_PROTOCOL', 'CIPHER_SUITE', 'KEY_EXCHANGE', 'CERTIFICATE', 'EMAIL_TRANSPORT']

export function Findings() {
  const { selected } = useInvestigationContext()
  const { findingId } = useParams()
  const [offset, setOffset] = useState(0)
  const [severity, setSeverity] = useState('')
  const [category, setCategory] = useState('')
  const [active, setActive] = useState<string | null>(findingId ?? null)

  // A deep link names the finding; keep the pane in step when it changes.
  useEffect(() => { if (findingId) setActive(findingId) }, [findingId])

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
  const items = page.data?.items ?? []
  // Open the first finding rather than showing an empty pane: the list is
  // ordered by the engine's priority, so the first row is the one a reader
  // would have clicked anyway.
  const activeId = active ?? items[0]?.finding_id ?? null

  return (
    <div className="space-y-3">
      <header className="flex flex-wrap items-end justify-between gap-x-4 gap-y-2">
        <div>
          <h1 className="text-xl font-semibold">Security findings</h1>
          <p className="mt-0.5 text-[13px] text-mist-300">
            Each finding is a rule that failed on observed evidence. Findings describe
            configuration, not exploitation.
          </p>
        </div>

        {inv && (
          <div className="flex items-stretch gap-3 rounded-lg border border-ink-780
                          bg-ink-900 px-3 py-2 shadow-panel">
            <div>
              <div className="label">Score</div>
              <div className="mt-0.5 text-2xl font-semibold leading-none tabular-nums">
                {inv.posture_score === null
                  ? <span className="text-base text-mist-300">
                      {inv.score_status === 'SCORE_UNAVAILABLE' ? 'INSUFFICIENT EVIDENCE' : 'UNKNOWN'}
                    </span>
                  : <>{inv.posture_score}<span className="text-base text-mist-400">/100</span></>}
              </div>
              {inv.score_band && <div className="hint mt-0.5 !text-3xs">{inv.score_band}</div>}
            </div>
            <span className="w-px bg-ink-780" aria-hidden="true" />
            <div>
              <div className="label">Assessment coverage</div>
              <div className="mt-0.5 text-2xl font-semibold leading-none tabular-nums">
                <Value value={inv.coverage_ratio === null ? null : `${(inv.coverage_ratio * 100).toFixed(0)}%`} />
              </div>
              <div className="hint mt-0.5 !text-3xs">of the applicable policy could be evaluated</div>
            </div>
            <span className="w-px bg-ink-780" aria-hidden="true" />
            <div>
              <div className="label">Findings</div>
              <div className="mt-0.5 text-2xl font-semibold leading-none tabular-nums">
                {inv.finding_count}
              </div>
            </div>
          </div>
        )}
      </header>

      {inv && inv.finding_count > 0 && (
        <Note tone="warn">
          The score above is an aggregate over weighted controls. It does not reduce
          the severity of any individual finding below.
        </Note>
      )}

      <div className="grid items-start gap-3 xl:grid-cols-[minmax(340px,420px)_1fr]">
        {/* ---- master ---------------------------------------------------- */}
        <section className="section rule-findings">
          <div className="section-head !py-1.5">
            <div className="flex flex-wrap gap-1.5">
              <select className="input !py-1 !text-xs" value={severity} data-testid="severity-filter"
                      aria-label="Filter findings by severity"
                      onChange={(e) => { setSeverity(e.target.value); setOffset(0) }}>
                <option value="">All severities</option>
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <select className="input !py-1 !text-xs" value={category} data-testid="category-filter"
                      aria-label="Filter findings by category"
                      onChange={(e) => { setCategory(e.target.value); setOffset(0) }}>
                <option value="">All categories</option>
                {CATEGORIES.map((c) => <option key={c} value={c}>{c.replace(/_/g, ' ')}</option>)}
              </select>
            </div>
          </div>

          {page.loading && <div className="section-body"><Loading what="findings" /></div>}
          {page.error && (
            <div className="section-body">
              <Failure title="Could not load findings" detail={page.error} onRetry={page.reload} />
            </div>
          )}
          {page.data && items.length === 0 && (
            <Empty title="NO FINDINGS"
                   detail="No rule failed on the evidence available under these filters. UNKNOWN rule evaluations are not failures and are not shown here." />
          )}
          {items.length > 0 && (
            <>
              <ul className="max-h-[calc(100vh-17rem)] divide-y divide-ink-820 overflow-y-auto"
                  data-testid="findings-list">
                {items.map((finding) => {
                  const isActive = activeId === finding.finding_id
                  return (
                    <li key={finding.finding_id}>
                      <button
                        type="button"
                        className={`row-link relative flex w-full flex-col items-start gap-0.5 px-3 py-2 text-left
                                    ${isActive ? 'bg-ink-820' : ''}`}
                        aria-current={isActive ? 'true' : undefined}
                        onClick={() => setActive(finding.finding_id)}
                        data-testid="finding-row"
                      >
                        {/* The selected row carries the accent on its left edge;
                            the tint never becomes a background fill. */}
                        {isActive && (
                          <span className="absolute inset-y-0 left-0 w-[3px] bg-area-findings"
                                aria-hidden="true" />
                        )}
                        <span className="flex w-full items-start gap-1.5">
                          <span className={`tag tag-${finding.severity} mt-px shrink-0`}>
                            {finding.severity}
                          </span>
                          {finding.priority && (
                            <span className="chip mt-px shrink-0">{finding.priority}</span>
                          )}
                          <span className="min-w-0 flex-1 text-[13px] font-medium leading-snug text-mist-100">
                            {finding.title}
                          </span>
                        </span>
                        <span className="flex w-full flex-wrap items-center gap-x-2">
                          <span className="chip-mono">{finding.rule_id}</span>
                          <span className="hint inline-flex items-center gap-1 !text-3xs">
                            <IconSessions size={11} />
                            {finding.session_id}
                          </span>
                          <span className="ml-auto shrink-0 text-3xs text-mist-500">
                            {finding.confidence}
                          </span>
                        </span>
                      </button>
                    </li>
                  )
                })}
              </ul>
              {page.data && (
                <div className="border-t border-ink-820 px-3 pb-2">
                  <Pagination page={page.data} onOffset={setOffset} />
                </div>
              )}
            </>
          )}
        </section>

        {/* ---- detail ----------------------------------------------------- */}
        {activeId
          ? <FindingDetailPane findingId={activeId} />
          : (
            <Panel>
              <Empty
                title="Select a finding"
                detail="The description, technical impact, standards references and the packets the rule was evaluated against appear here."
              />
            </Panel>
          )}
      </div>
    </div>
  )
}

function FindingDetailPane({ findingId }: { findingId: string }) {
  const { selected } = useInvestigationContext()
  const detail = useAsync(() => api.getFinding(findingId, selected), [findingId, selected])

  if (detail.loading) return <Panel><Loading what="finding detail" /></Panel>
  if (detail.error) {
    return <Panel><Failure title="Could not load detail" detail={detail.error} onRetry={detail.reload} /></Panel>
  }
  if (!detail.data) return null
  const d = detail.data
  const f = d.finding

  return (
    <section className="section rule-findings" data-testid="finding-detail">
      <div className="section-head">
        <div className="flex min-w-0 items-center gap-2">
          <span className="text-area-findings shrink-0" aria-hidden="true"><IconAlert size={15} /></span>
          <h2 className="section-title truncate">{f.title}</h2>
        </div>
        <Link className="btn btn-ghost text-xs" to={`/sessions/${f.session_id}`}>
          Open session
          <IconArrowRight size={13} />
        </Link>
      </div>

      <div className="section-body space-y-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className={`tag tag-${f.severity}`}>{f.severity}</span>
          {f.priority && <span className="chip">{f.priority}</span>}
          <span className="chip-mono">{f.rule_id}</span>
          <span className="chip">{f.category.replace(/_/g, ' ').toLowerCase()}</span>
          <span className="chip">confidence {f.confidence}</span>
          <span className="chip">{f.evaluation_status}</span>
        </div>

        <p className="text-[13px] leading-relaxed text-mist-200">{d.description}</p>

        <div className="grid gap-3 md:grid-cols-2">
          <div className="surface-sunken p-2.5">
            <div className="label">Technical impact</div>
            <p className="mt-1 text-[12px] leading-relaxed text-mist-300">{d.technical_impact}</p>
          </div>
          <div className="surface-sunken space-y-2 p-2.5">
            {d.standards_references.length > 0 && (
              <div>
                <div className="label">Standards</div>
                <p className="mt-1 text-[12px] leading-relaxed text-mist-300">
                  {d.standards_references.join('; ')}
                </p>
              </div>
            )}
            {d.remediation_ids.length > 0 && (
              <div>
                <div className="label">Remediation</div>
                <p className="mt-1 text-[12px] leading-relaxed text-mist-300">
                  <span className="mono">{d.remediation_ids.join(', ')}</span>
                  {' '}— see the exported report for the full corrective action.
                </p>
              </div>
            )}
            <div>
              <div className="label">Policy</div>
              <p className="mt-1 text-[12px] text-mist-300">
                version <span className="mono">{d.policy_version ?? 'unknown'}</span>,
                status {f.evaluation_status}.
              </p>
            </div>
          </div>
        </div>

        <EvidenceLink evidence={d.evidence} limitations={d.limitations} />
      </div>
    </section>
  )
}
