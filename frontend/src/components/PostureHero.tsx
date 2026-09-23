/**
 * The investigation hero.
 *
 * Replaces four identical metric boxes with one region that reads as the
 * headline of the investigation: the score as a real arc, the severity
 * distribution as a proportional strip, and the supporting counts beside it.
 *
 * Nothing here is computed. Every number comes from the engine; this decides
 * only how prominently to show it. An unavailable score renders as the reason
 * it is unavailable, never as a zero.
 */
import type { InvestigationSummary } from '../lib/api'

const BAND_COLOUR: Record<string, string> = {
  STRONG: '#4ecd8a',
  ADEQUATE: '#5ccfc2',
  WEAK: '#ff9f4a',
  POOR: '#ff6b63',
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
const SEVERITY_COLOUR: Record<string, string> = {
  CRITICAL: '#ff6b63',
  HIGH: '#ff9f4a',
  MEDIUM: '#f0c94b',
  LOW: '#5ccfc2',
  INFO: '#6ba6f7',
}

/** A 270-degree arc. Stroke length is the score, so the shape is the data. */
function ScoreArc({ score, band }: { score: number; band: string | null }) {
  const radius = 52
  const circumference = 2 * Math.PI * radius
  const sweep = 0.75
  const track = circumference * sweep
  const filled = track * (score / 100)
  const colour = BAND_COLOUR[band ?? ''] ?? '#6ba6f7'

  return (
    <svg
      width="132"
      height="132"
      viewBox="0 0 132 132"
      role="img"
      aria-label={`Posture score ${score} out of 100${band ? `, band ${band}` : ''}`}
      className="shrink-0"
    >
      <g transform="rotate(135 66 66)">
        <circle
          cx="66" cy="66" r={radius} fill="none"
          stroke="#1d2b3e" strokeWidth="9" strokeLinecap="round"
          strokeDasharray={`${track} ${circumference}`}
        />
        <circle
          cx="66" cy="66" r={radius} fill="none"
          stroke={colour} strokeWidth="9" strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
          style={{ transition: 'stroke-dasharray 220ms ease-out' }}
        />
      </g>
      <text
        x="66" y="64" textAnchor="middle"
        className="fill-mist-50"
        style={{ fontSize: 33, fontWeight: 600, letterSpacing: '-0.02em' }}
      >
        {score}
      </text>
      <text
        x="66" y="82" textAnchor="middle" className="fill-mist-400"
        style={{ fontSize: 10.5, letterSpacing: '0.06em' }}
      >
        / 100
      </text>
    </svg>
  )
}

function SeverityStrip({ counts }: { counts: Record<string, number> }) {
  const present = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0)
  const total = present.reduce((sum, s) => sum + (counts[s] ?? 0), 0)
  if (total === 0) return null

  return (
    <div>
      <div className="sevbar" role="img" aria-label={
        present.map((s) => `${counts[s]} ${s.toLowerCase()}`).join(', ')
      }>
        {present.map((s) => (
          <span
            key={s}
            style={{
              width: `${((counts[s] ?? 0) / total) * 100}%`,
              background: SEVERITY_COLOUR[s],
            }}
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-2.5 gap-y-1 mt-1.5">
        {present.map((s) => (
          <span key={s} className="inline-flex items-center gap-1 text-2xs text-mist-300">
            <span
              className="h-2 w-2 rounded-sm shrink-0"
              style={{ background: SEVERITY_COLOUR[s] }}
              aria-hidden="true"
            />
            <span className="font-semibold tabular-nums text-mist-100">{counts[s]}</span>
            {s}
          </span>
        ))}
      </div>
    </div>
  )
}

function Stat({ label, value, note, testId }: {
  label: string
  value: React.ReactNode
  note?: string
  /** Set where an end-to-end suite reads this value back. */
  testId?: string
}) {
  return (
    <div data-testid={testId}>
      <div className="label">{label}</div>
      <div className="text-2xl font-semibold tabular-nums leading-none mt-1">{value}</div>
      {note && <div className="hint mt-1">{note}</div>}
    </div>
  )
}

export function PostureHero({ inv }: { inv: InvestigationSummary }) {
  const scored = inv.posture_score !== null
  const counts = inv.severity_counts ?? {}

  return (
    <section className="hero" data-testid="posture-hero">
      <div className="p-3 lg:p-4 grid gap-4 lg:grid-cols-[auto_1fr]">
        <div className="flex items-center gap-3">
          {scored ? (
            <div className="flex flex-col items-center" data-testid="posture-score">
              <ScoreArc score={inv.posture_score as number} band={inv.score_band} />
              {inv.score_band && (
                <span
                  className="text-2xs font-bold tracking-[0.12em] -mt-2"
                  style={{ color: BAND_COLOUR[inv.score_band] ?? '#6ba6f7' }}
                >
                  {inv.score_band}
                </span>
              )}
              <span className="label mt-1.5">Posture score</span>
            </div>
          ) : (
            <div
              className="w-[132px] h-[132px] rounded-full border border-dashed border-ink-700
                         flex items-center justify-center text-center px-2"
              data-testid="posture-score"
            >
              <span className="text-2xs text-mist-300 leading-snug">
                {inv.status === 'COMPLETED' ? 'INSUFFICIENT EVIDENCE' : 'NOT ANALYSED'}
              </span>
            </div>
          )}

          <div className="space-y-2.5">
            <Stat
              label="Assessment coverage"
              value={
                inv.coverage_ratio !== null
                  ? `${(inv.coverage_ratio * 100).toFixed(0)}%`
                  : <span className="text-base text-mist-300">UNKNOWN</span>
              }
              note="of the applicable policy the evidence let us evaluate"
            />
            <Stat label="Captures" value={inv.analysed_capture_count}
                  note={inv.failed_capture_count > 0
                    ? `${inv.failed_capture_count} failed`
                    : undefined} />
          </div>
        </div>

        <div className="min-w-0 space-y-3 lg:border-l lg:border-ink-780 lg:pl-4">
          <div className="grid grid-cols-2 gap-3">
            <Stat label="Sessions observed" value={inv.session_count}
                  testId="session-count" />
            <Stat
              label="Findings"
              testId="finding-count"
              value={
                inv.finding_count === 0
                  ? <span className="text-base text-sev-ok">NO FINDINGS</span>
                  : inv.finding_count
              }
            />
          </div>

          {inv.finding_count > 0 && (
            <div className="max-w-md">
              <div className="label mb-1.5">Severity distribution</div>
              <SeverityStrip counts={counts} />
            </div>
          )}

          {scored && inv.capture_count > 1 && inv.score_scope && (
            <p className="hint break-all border-l-2 border-ink-740 pl-2">
              {inv.score_scope}
            </p>
          )}
        </div>
      </div>
    </section>
  )
}
