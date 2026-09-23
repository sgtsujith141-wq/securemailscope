/**
 * The hero of the investigation overview: what needs attention, first.
 *
 * Before this, the workspace opened with four equal-weight metric cards and a
 * capture inventory. A reader had to work out for themselves that two of the
 * findings were HIGH and which sessions they belonged to. The score was the
 * largest thing on the page, which is exactly backwards: a score summarises,
 * a finding is the substance.
 *
 * Nothing here is computed. Severity, priority, rule and evidence counts all
 * come from the engine; this component only decides what to show first.
 */
import { Link } from 'react-router-dom'

import type { FindingSummary } from '../lib/api'
import { IconAlert, IconArrowRight, IconCheck, IconPacket } from './icons'

const ATTENTION = new Set(['CRITICAL', 'HIGH'])

export function NeedsAttention({
  findings,
  total,
  loading,
}: {
  findings: FindingSummary[]
  total: number
  loading?: boolean
}) {
  if (loading) return null

  const urgent = findings.filter((f) => ATTENTION.has(f.severity))
  const top = (urgent.length > 0 ? urgent : findings).slice(0, 4)

  // Nothing failed. Say so precisely: no rule failed on the evidence
  // available, which is not the same as "this infrastructure is secure".
  if (total === 0) {
    return (
      <section className="section" data-testid="needs-attention">
        <div className="section-body flex items-start gap-2">
          <span className="text-sev-ok mt-0.5 shrink-0" aria-hidden="true">
            <IconCheck size={18} />
          </span>
          <div>
            <p className="text-sm font-semibold text-sev-ok">
              No findings were raised
            </p>
            <p className="hint mt-0.5">
              No rule failed on the evidence available. That is a statement
              about what these captures could show, not a conclusion that the
              analysed systems are secure.
            </p>
          </div>
        </div>
      </section>
    )
  }

  const headline =
    urgent.length > 0
      ? `${urgent.length} high-priority ${urgent.length === 1 ? 'issue requires' : 'issues require'} attention`
      : `${total} ${total === 1 ? 'finding' : 'findings'} to review`

  return (
    <section className="section" data-testid="needs-attention">
      <div className="section-head">
        <div className="flex items-center gap-1.5">
          <span
            className={urgent.length > 0 ? 'text-sev-high' : 'text-mist-400'}
            aria-hidden="true"
          >
            <IconAlert size={15} />
          </span>
          <h2 className="section-title" data-testid="attention-headline">
            {headline}
          </h2>
        </div>
        <Link className="btn btn-ghost text-xs" to="/findings">
          All {total} findings
          <IconArrowRight size={13} />
        </Link>
      </div>

      <ul className="divide-y divide-ink-800">
        {top.map((finding) => (
          <li key={finding.finding_id}>
            <Link
              to={`/findings/${finding.finding_id}`}
              className="row-link flex flex-wrap items-start gap-x-2.5 gap-y-1 px-3 py-2.5"
              data-testid="attention-item"
            >
              <span className={`tag tag-${finding.severity} mt-0.5 shrink-0`}>
                {finding.severity}
              </span>
              {finding.priority && (
                <span className="chip mt-0.5 shrink-0">{finding.priority}</span>
              )}

              <span className="min-w-0 flex-1">
                <span className="block text-sm text-mist-100 font-medium">
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

              <span className="text-accent text-xs inline-flex items-center gap-1 mt-0.5 shrink-0">
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
