/**
 * The second row of the investigation dashboard.
 *
 * Four modules of genuinely different shape -- a stacked bar, a legend list, a
 * severity ladder and a definition list -- so the row reads as four answers
 * rather than four identical boxes.
 *
 * Nothing is computed beyond counting rows the engine already produced, and a
 * value the analysis did not observe is counted as UNKNOWN rather than folded
 * into a total that would imply it was seen.
 */
import type { ReactNode } from 'react'

import type { InvestigationSummary, SessionSummary } from '../lib/api'
import { IconAlert, IconLock, IconSessions, IconShield } from './icons'

const VERSION_COLOUR: Record<string, string> = {
  'TLS 1.3': '#34d399',
  'TLS 1.2': '#22d3ee',
  'TLS 1.1': '#fbbf24',
  'TLS 1.0': '#fb7185',
  'SSL 3.0': '#fb7185',
  'SSL 2.0': '#fb7185',
  UNKNOWN: '#64748b',
}
const PROTOCOL_COLOUR: Record<string, string> = {
  SMTP: '#60a5fa',
  IMAP: '#a78bfa',
  POP3: '#e879b9',
  UNKNOWN: '#64748b',
}
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
const SEVERITY_COLOUR: Record<string, string> = {
  CRITICAL: '#fb7185',
  HIGH: '#fb923c',
  MEDIUM: '#fbbf24',
  LOW: '#22d3ee',
  INFO: '#60a5fa',
}

function tally(values: (string | null)[]): [string, number][] {
  const counts = new Map<string, number>()
  for (const raw of values) {
    const key = raw && raw.trim() ? raw : 'UNKNOWN'
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  // Highest first, then alphabetically, so the order is stable between
  // renders of the same data rather than dependent on insertion order.
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
}

function Module({
  title, icon: Icon, tint, children, footer,
}: {
  title: string
  icon: typeof IconLock
  /** Drawn as a 2px rule along the top edge; never as a background fill. */
  tint: string
  children: ReactNode
  footer?: ReactNode
}) {
  return (
    <section className="module">
      <span className="module-rule" style={{ background: tint }} aria-hidden="true" />
      <header className="flex items-center gap-1.5 px-2.5 pt-2.5 pb-2">
        <span style={{ color: tint }} aria-hidden="true"><Icon size={14} /></span>
        <h3 className="label !text-mist-200">{title}</h3>
      </header>
      <div className="px-2.5 flex-1">{children}</div>
      <p className="hint px-2.5 pt-2 pb-2.5 !text-3xs">{footer}</p>
    </section>
  )
}

/** A stacked proportional bar with a labelled legend beneath it. */
function Distribution({
  rows, palette, empty,
}: {
  rows: [string, number][]
  palette: Record<string, string>
  empty: string
}) {
  const total = rows.reduce((sum, [, n]) => sum + n, 0)
  if (total === 0) return <p className="hint">{empty}</p>
  return (
    <>
      <div
        className="flex h-2 w-full gap-px overflow-hidden rounded-full bg-ink-820"
        role="img"
        aria-label={rows.map(([k, n]) => `${n} ${k}`).join(', ')}
      >
        {rows.map(([key, n]) => (
          <span
            key={key}
            style={{ width: `${(n / total) * 100}%`, background: palette[key] ?? '#64748b' }}
          />
        ))}
      </div>
      <ul className="mt-2 space-y-1">
        {rows.map(([key, n]) => (
          <li key={key} className="flex items-center gap-1.5 text-xs">
            <span
              className="h-2 w-2 shrink-0 rounded-sm"
              style={{ background: palette[key] ?? '#64748b' }}
              aria-hidden="true"
            />
            <span className="min-w-0 flex-1 truncate text-mist-200">{key}</span>
            <span className="tabular-nums font-semibold text-mist-100">{n}</span>
            <span className="w-9 text-right tabular-nums text-mist-400">
              {Math.round((n / total) * 100)}%
            </span>
          </li>
        ))}
      </ul>
    </>
  )
}

/**
 * Severity as a ladder of bars rather than a pie: five known categories whose
 * order carries meaning, which a pie chart destroys.
 */
function SeverityLadder({ counts, total }: {
  counts: Record<string, number>
  total: number
}) {
  const present = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0)
  if (present.length === 0) {
    return <p className="hint">No rule failed on the evidence available.</p>
  }
  const peak = Math.max(...present.map((s) => counts[s] ?? 0))
  return (
    <>
    <div className="mb-2.5 flex items-baseline gap-1.5">
      <span className="text-3xl font-semibold leading-none tabular-nums">{total}</span>
      <span className="text-sm text-mist-400">
        finding{total === 1 ? '' : 's'}
      </span>
    </div>
    <ul className="space-y-1.5">
      {present.map((s) => (
        <li key={s} className="flex items-center gap-2">
          <span className="w-14 shrink-0 text-3xs font-semibold tracking-wide"
                style={{ color: SEVERITY_COLOUR[s] }}>
            {s}
          </span>
          <span className="sevbar flex-1">
            <span style={{
              width: `${((counts[s] ?? 0) / peak) * 100}%`,
              background: SEVERITY_COLOUR[s],
            }} />
          </span>
          <span className="w-5 shrink-0 text-right text-xs font-semibold tabular-nums">
            {counts[s]}
          </span>
        </li>
      ))}
    </ul>
    </>
  )
}

export function CryptoModules({
  inv, sessions, sessionsShown, sessionsTotal,
}: {
  inv: InvestigationSummary
  sessions: SessionSummary[]
  sessionsShown: number
  sessionsTotal: number
}) {
  const versions = tally(sessions.map((s) => s.tls_version))
  const protocols = tally(sessions.map((s) => s.protocol))

  const withTls = sessions.filter((s) => s.tls_version).length
  // `certificate_visibility` records *why* a certificate is absent, so these
  // two rows mean different things: one chain was read, the other provably
  // cannot be read passively. Adding them together would erase that.
  const certObserved = sessions.filter((s) => s.certificate_visibility === 'OBSERVED').length
  const certEncrypted = sessions.filter(
    (s) => s.certificate_visibility === 'ENCRYPTED_TLS13',
  ).length
  const withFindings = sessions.filter((s) => s.finding_count > 0).length

  // Every module below counts the sessions actually loaded. When that is not
  // all of them, each footer says so rather than implying full coverage.
  const partial = sessionsShown < sessionsTotal
  const scope = partial
    ? `Across the first ${sessionsShown} of ${sessionsTotal} sessions.`
    : `Across all ${sessionsTotal} observed session${sessionsTotal === 1 ? '' : 's'}.`

  return (
    <div className="grid gap-2.5 md:grid-cols-2 xl:grid-cols-4" data-testid="crypto-modules">
      <Module title="TLS posture" icon={IconLock} tint="#22d3ee"
              footer={<>Negotiated version per session. {scope}</>}>
        <Distribution rows={versions} palette={VERSION_COLOUR}
                      empty="No sessions were observed." />
      </Module>

      <Module title="Severity distribution" icon={IconAlert} tint="#fb923c"
              footer="Across the whole investigation. Bar length is relative to the largest category.">
        <SeverityLadder counts={inv.severity_counts ?? {}} total={inv.finding_count} />
      </Module>

      <Module title="Protocol map" icon={IconSessions} tint="#a78bfa"
              footer={<>Identified from the dialogue, never from the port number. {scope}</>}>
        <Distribution rows={protocols} palette={PROTOCOL_COLOUR}
                      empty="No sessions were observed." />
      </Module>

      <Module title="Cryptographic health" icon={IconShield} tint="#34d399"
              footer="A session with no finding is not a session proved safe.">
        <dl className="space-y-1.5">
          {[
            ['Sessions with TLS', `${withTls} / ${sessionsShown}`],
            ['Certificate chain read', String(certObserved)],
            ['Encrypted under TLS 1.3', String(certEncrypted)],
            ['Sessions with findings', String(withFindings)],
          ].map(([k, v]) => (
            <div key={k} className="flex items-baseline justify-between gap-2 border-b border-ink-820 pb-1 last:border-0">
              <dt className="truncate text-xs text-mist-300">{k}</dt>
              <dd className="shrink-0 text-sm font-semibold tabular-nums text-mist-100">{v}</dd>
            </div>
          ))}
        </dl>
      </Module>
    </div>
  )
}
