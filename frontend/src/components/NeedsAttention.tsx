/**
 * The two halves of "what needs attention" on the investigation dashboard.
 *
 * Before this, the workspace opened with four equal-weight metric cards and a
 * capture inventory. A reader had to work out for themselves that two of the
 * findings were HIGH and which sessions they belonged to. The score was the
 * largest thing on the page, which is exactly backwards: a score summarises,
 * a finding is the substance.
 *
 * `AttentionHeadline` states the conclusion at the top of the page;
 * `PriorityFindings` lists the individual findings further down, so the two
 * are not the same block repeated at two sizes.
 *
 * Nothing here is computed. Severity, priority, rule and rank all come from
 * the engine; these components only decide what to show first.
 */
import { Link } from 'react-router-dom'

import type { FindingSummary, InvestigationSummary, SessionSummary } from '../lib/api'
import { IconAlert, IconArrowRight, IconCheck, IconClock, IconPacket } from './icons'

const ATTENTION = new Set(['CRITICAL', 'HIGH'])
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

/** Band thresholds are the engine's; this only maps a band to a colour. */
const BAND_COLOUR: Record<string, string> = {
  STRONG: '#34d399',
  ADEQUATE: '#22d3ee',
  WEAK: '#fb923c',
  POOR: '#fb7185',
}
function bandOf(score: number): string {
  return score >= 90 ? 'STRONG' : score >= 75 ? 'ADEQUATE' : score >= 50 ? 'WEAK' : 'POOR'
}

/**
 * One bar per scored session, weakest first.
 *
 * This is what makes the headline score legible: the investigation reports the
 * weakest capture, and this shows how far the rest sit from it. A session the
 * engine could not score is drawn as an explicit unscored slot rather than
 * omitted, so the strip always has as many slots as there are sessions.
 */
function SessionPostureStrip({ sessions }: { sessions: SessionSummary[] }) {
  if (sessions.length === 0) return null
  const ordered = [...sessions].sort(
    (a, b) => (a.posture_score ?? 101) - (b.posture_score ?? 101),
  )
  const scored = ordered.filter((s) => s.posture_score !== null)
  if (scored.length === 0) return null
  const low = Math.min(...scored.map((s) => s.posture_score as number))
  const high = Math.max(...scored.map((s) => s.posture_score as number))

  return (
    <div data-testid="session-posture-strip">
      <div className="label mb-1.5">Per-session posture, weakest first</div>
      <div className="flex h-[74px] items-end gap-[3px] border-b border-ink-780">
        {ordered.map((session) => {
          const score = session.posture_score
          if (score === null) {
            return (
              <span
                key={session.session_id}
                title={`${session.session_id}: not scored`}
                className="flex h-full min-w-[8px] flex-1 items-end justify-center rounded-t-sm
                           border border-dashed border-ink-700 pb-1 text-3xs text-mist-500"
              >
                ?
              </span>
            )
          }
          const tint = BAND_COLOUR[bandOf(score)]
          return (
            <Link
              key={session.session_id}
              to={`/sessions/${session.session_id}`}
              title={`${session.session_id} — ${score}/100, ${session.finding_count} finding(s)`}
              className="relative flex min-w-[8px] flex-1 items-start justify-center rounded-t-sm
                         pt-1 text-3xs font-semibold tabular-nums transition-[filter] hover:brightness-125"
              style={{
                height: `${Math.max(10, score)}%`,
                background: `linear-gradient(180deg, ${tint}e6 0%, ${tint}40 100%)`,
                color: '#04080f',
              }}
            >
              {score}
              <span className="sr-only">{` — session ${session.session_id}`}</span>
            </Link>
          )
        })}
      </div>
      <p className="hint mt-1.5 !text-3xs">
        {scored.length} of {sessions.length} session{sessions.length === 1 ? '' : 's'} scored;
        {' '}lowest {low}, highest {high}. The investigation headline reports the weakest.
      </p>
    </div>
  )
}

/** The findings promoted to the top of the page, in the engine's own order. */
export function urgentFirst(findings: FindingSummary[]): FindingSummary[] {
  const urgent = findings.filter((f) => ATTENTION.has(f.severity))
  return urgent.length > 0 ? urgent : findings
}

export function AttentionHeadline({
  inv, sessions, loading,
}: {
  inv: InvestigationSummary
  sessions: SessionSummary[]
  loading?: boolean
}) {
  const total = inv.finding_count
  const counts = inv.severity_counts ?? {}
  // Counted from the investigation totals, not from the page of findings the
  // dashboard happens to have fetched: a headline that said "6" while the
  // severity chips beside it said "7 HIGH" would be wrong, not merely terse.
  const urgentCount = [...ATTENTION].reduce((sum, s) => sum + (counts[s] ?? 0), 0)

  // Nothing failed. Say so precisely: no rule failed on the evidence
  // available, which is not the same as "this infrastructure is secure".
  if (total === 0 && !loading) {
    return (
      <section className="hero hero-grid flex flex-col justify-center px-4 py-5"
               data-testid="needs-attention">
        <span className="label text-sev-ok">Assessment complete</span>
        <h1 className="mt-2 flex items-start gap-2 text-2xl font-semibold leading-tight text-mist-50">
          <span className="mt-1 shrink-0 text-sev-ok" aria-hidden="true">
            <IconCheck size={22} />
          </span>
          <span data-testid="attention-headline">No findings were raised</span>
        </h1>
        <p className="hint mt-2 max-w-xl !text-sm">
          No rule failed on the evidence available. That is a statement about
          what these captures could show, not a conclusion that the analysed
          systems are secure.
        </p>
        <div className="my-4">
          <SessionPostureStrip sessions={sessions} />
        </div>
        <div className="flex flex-wrap gap-2">
          <Link className="btn" to="/sessions">Review sessions</Link>
          <Link className="btn" to="/reports">Export report</Link>
        </div>
      </section>
    )
  }

  const headline =
    urgentCount > 0
      ? `${urgentCount} high-priority cryptographic ${urgentCount === 1 ? 'issue requires' : 'issues require'} attention`
      : `${total} ${total === 1 ? 'finding' : 'findings'} to review`
  const present = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0)

  return (
    <section className="hero hero-grid flex flex-col justify-between px-4 py-5"
             data-testid="needs-attention">
      <div>
        <span className="label inline-flex items-center gap-1.5 text-sev-high">
          <IconAlert size={13} />
          Requires attention
        </span>
        <h1
          className="mt-2 max-w-2xl text-[28px] font-semibold leading-[1.15] tracking-[-0.02em] text-mist-50"
          data-testid="attention-headline"
        >
          {headline}
        </h1>
        <p className="hint mt-2 max-w-xl !text-sm">
          Ranked by the engine&rsquo;s priority matrix. Every one is backed by a
          packet in the capture it came from &mdash; open a finding to see it.
        </p>
      </div>

      <div className="my-4 min-h-0">
        <SessionPostureStrip sessions={sessions} />
      </div>

      <div>
        {present.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {present.map((s) => (
              <Link
                key={s}
                to={`/findings?severity=${s}`}
                className={`tag tag-${s} !px-2 !py-1 transition-transform hover:-translate-y-px`}
              >
                <span className="tabular-nums">{counts[s]}</span> {s}
              </Link>
            ))}
          </div>
        )}
        <div className="mt-3 flex flex-wrap gap-2">
          <Link className="btn btn-primary" to="/findings">
            Review all {total} findings
            <IconArrowRight size={14} />
          </Link>
          <Link className="btn" to="/timeline">
            <IconClock size={13} />
            Evidence timeline
          </Link>
        </div>
      </div>
    </section>
  )
}

export function PriorityFindings({
  findings, total, loading,
}: {
  findings: FindingSummary[]
  total: number
  loading?: boolean
}) {
  if (loading || total === 0) return null
  const top = urgentFirst(findings).slice(0, 5)
  if (top.length === 0) return null

  return (
    <section className="section rule-findings" data-testid="priority-findings">
      <div className="section-head">
        <h2 className="section-title">Priority findings</h2>
        <Link className="btn btn-ghost text-xs" to="/findings">
          All {total}
          <IconArrowRight size={13} />
        </Link>
      </div>

      <ul className="divide-y divide-ink-820">
        {top.map((finding) => (
          <li key={finding.finding_id}>
            <Link
              to={`/findings/${finding.finding_id}`}
              className="row-link group flex flex-wrap items-start gap-x-2.5 gap-y-1 px-3 py-2.5"
              data-testid="attention-item"
            >
              <span className={`tag tag-${finding.severity} mt-0.5 shrink-0`}>
                {finding.severity}
              </span>
              {finding.priority && (
                <span className="chip mt-0.5 shrink-0">{finding.priority}</span>
              )}

              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium text-mist-100">
                  {finding.title}
                </span>
                <span className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5">
                  <span className="chip-mono">{finding.rule_id}</span>
                  {finding.session_id && (
                    <span className="hint">
                      session <span className="font-mono">{finding.session_id}</span>
                    </span>
                  )}
                  {finding.category && (
                    <span className="hint inline-flex items-center gap-1">
                      <IconPacket size={12} />
                      {finding.category.replace(/_/g, ' ').toLowerCase()}
                    </span>
                  )}
                </span>
              </span>

              <span className="mt-0.5 inline-flex shrink-0 items-center gap-1 text-xs text-accent
                               opacity-70 transition-opacity group-hover:opacity-100">
                Inspect evidence
                <IconArrowRight size={13} />
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  )
}
