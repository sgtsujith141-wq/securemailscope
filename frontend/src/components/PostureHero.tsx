/**
 * The posture visualisation that sits on the right of the investigation hero.
 *
 * Replaces four identical metric boxes with one region that reads as the
 * headline of the investigation: the score as a real arc whose stroke length
 * *is* the number, the band beneath it, and the supporting counts below.
 *
 * Nothing here is computed. Every number comes from the engine; this decides
 * only how prominently to show it. An unavailable score renders as the reason
 * it is unavailable, never as a zero -- a reader cannot tell a real zero from
 * a missing one.
 */
import type { ReactNode } from 'react'

import type { InvestigationSummary } from '../lib/api'

const BAND_COLOUR: Record<string, string> = {
  STRONG: '#34d399',
  ADEQUATE: '#22d3ee',
  WEAK: '#fb923c',
  POOR: '#fb7185',
}

/** A 270-degree arc. Stroke length is the score, so the shape is the data. */
function ScoreArc({ score, band }: { score: number; band: string | null }) {
  const radius = 56
  const circumference = 2 * Math.PI * radius
  const sweep = 0.75
  const track = circumference * sweep
  const filled = track * (score / 100)
  const colour = BAND_COLOUR[band ?? ''] ?? '#60a5fa'
  const id = `arc-${band ?? 'none'}`

  return (
    <svg
      width="148" height="148" viewBox="0 0 148 148"
      role="img"
      aria-label={`Posture score ${score} out of 100${band ? `, band ${band}` : ''}`}
      className="shrink-0"
    >
      <defs>
        {/* A two-stop gradient along the arc, so the stroke has depth without
            the glow becoming decoration in its own right. */}
        <linearGradient id={id} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor={colour} stopOpacity="0.55" />
          <stop offset="100%" stopColor={colour} stopOpacity="1" />
        </linearGradient>
      </defs>
      <g transform="rotate(135 74 74)">
        <circle
          cx="74" cy="74" r={radius} fill="none"
          stroke="#16202f" strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${track} ${circumference}`}
        />
        <circle
          cx="74" cy="74" r={radius} fill="none"
          stroke={`url(#${id})`} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
          style={{
            transition: 'stroke-dasharray 260ms ease-out',
            filter: `drop-shadow(0 0 6px ${colour}55)`,
          }}
        />
      </g>
      <text
        x="74" y="72" textAnchor="middle" className="fill-mist-50"
        style={{ fontSize: 38, fontWeight: 600, letterSpacing: '-0.03em' }}
      >
        {score}
      </text>
      <text
        x="74" y="91" textAnchor="middle" className="fill-mist-400"
        style={{ fontSize: 10.5, letterSpacing: '0.08em' }}
      >
        / 100
      </text>
    </svg>
  )
}

function Stat({ label, value, note, testId }: {
  label: string
  value: ReactNode
  note?: string
  /** Set where an end-to-end suite reads this value back. */
  testId?: string
}) {
  return (
    <div data-testid={testId} className="min-w-0">
      <div className="label">{label}</div>
      <div className="mt-1 text-xl font-semibold leading-none tabular-nums">{value}</div>
      {note && <div className="hint mt-1 !text-3xs">{note}</div>}
    </div>
  )
}

export function PostureHero({ inv }: { inv: InvestigationSummary }) {
  const scored = inv.posture_score !== null

  return (
    <section className="hero hero-grid flex flex-col items-center px-3 py-4"
             data-testid="posture-hero">
      {scored ? (
        <div className="flex flex-col items-center" data-testid="posture-score">
          <ScoreArc score={inv.posture_score as number} band={inv.score_band} />
          {inv.score_band && (
            <span
              className="-mt-3 rounded-full px-2.5 py-0.5 text-2xs font-bold tracking-[0.14em]"
              style={{
                color: BAND_COLOUR[inv.score_band] ?? '#60a5fa',
                background: `${BAND_COLOUR[inv.score_band] ?? '#60a5fa'}1f`,
                border: `1px solid ${BAND_COLOUR[inv.score_band] ?? '#60a5fa'}55`,
              }}
            >
              {inv.score_band}
            </span>
          )}
          <span className="label mt-2">Posture score</span>
        </div>
      ) : (
        <div
          className="flex h-[148px] w-[148px] items-center justify-center rounded-full
                     border border-dashed border-ink-700 px-3 text-center"
          data-testid="posture-score"
        >
          <span className="text-2xs leading-snug text-mist-300">
            {inv.status === 'COMPLETED' ? 'INSUFFICIENT EVIDENCE' : 'NOT ANALYSED'}
          </span>
        </div>
      )}

      <div className="mt-4 grid w-full grid-cols-2 gap-x-3 gap-y-3 border-t border-ink-780 pt-3">
        <Stat
          label="Assessment coverage"
          value={
            inv.coverage_ratio !== null
              ? `${(inv.coverage_ratio * 100).toFixed(0)}%`
              : <span className="text-sm text-mist-300">UNKNOWN</span>
          }
          note="of the applicable policy the evidence let us evaluate"
        />
        <Stat
          label="Captures"
          value={inv.analysed_capture_count}
          note={inv.failed_capture_count > 0
            ? `${inv.failed_capture_count} failed`
            : 'all analysed'}
        />
        <Stat label="Sessions observed" value={inv.session_count} testId="session-count" />
        <Stat
          label="Findings"
          testId="finding-count"
          value={
            inv.finding_count === 0
              ? <span className="text-sm text-sev-ok">NONE</span>
              : inv.finding_count
          }
        />
      </div>

      {/* Keeps the headline from being read as an average across captures. */}
      {scored && inv.capture_count > 1 && inv.score_scope && (
        <p className="hint mt-3 w-full break-all border-l-2 border-ink-740 pl-2 !text-3xs">
          {inv.score_scope}
        </p>
      )}
    </section>
  )
}
