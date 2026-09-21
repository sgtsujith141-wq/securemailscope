/**
 * The shared component vocabulary.
 *
 * Two rules run through all of it:
 *
 * 1. **Unknown is rendered as unknown.** `Value` shows an explicit "unknown"
 *    or "not available" rather than an empty cell or a zero, because a reader
 *    cannot tell a real zero from a missing one.
 * 2. **No decorative state.** Every spinner corresponds to a request actually
 *    in flight, and progress is only shown as a proportion when the backend
 *    reports one.
 */
import type { ReactNode } from 'react'

export function Panel({ title, children, actions, className = '' }: {
  title?: string
  children: ReactNode
  actions?: ReactNode
  className?: string
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-ink-600">
          {title && <h2 className="text-sm font-semibold text-mist-100">{title}</h2>}
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  )
}

export function Metric({ label, value, note, tone = 'default' }: {
  label: string
  value: ReactNode
  note?: ReactNode
  tone?: 'default' | 'unknown'
}) {
  return (
    <div className="panel px-4 py-3">
      <div className="label">{label}</div>
      <div className={`text-2xl font-semibold mt-1 ${tone === 'unknown' ? 'text-mist-300 text-base' : ''}`}>
        {value}
      </div>
      {note && <div className="text-[11px] text-mist-300 mt-1">{note}</div>}
    </div>
  )
}

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: 'text-sev-critical border-sev-critical/50 bg-sev-critical/10',
  HIGH: 'text-sev-high border-sev-high/50 bg-sev-high/10',
  MEDIUM: 'text-sev-medium border-sev-medium/50 bg-sev-medium/10',
  LOW: 'text-sev-low border-sev-low/50 bg-sev-low/10',
  INFO: 'text-sev-info border-sev-info/50 bg-sev-info/10',
}

export function SeverityTag({ severity }: { severity: string }) {
  const cls = SEVERITY_CLASS[severity] ?? 'text-mist-300 border-ink-600 bg-ink-700'
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded border text-[10px] font-semibold tracking-wide ${cls}`}>
      {severity}
    </span>
  )
}

export function StatusTag({ status }: { status: string }) {
  const tone =
    status === 'COMPLETED' ? 'text-sev-ok border-sev-ok/40 bg-sev-ok/10'
    : status === 'FAILED' ? 'text-sev-critical border-sev-critical/40 bg-sev-critical/10'
    : status === 'RUNNING' || status === 'QUEUED' ? 'text-sev-info border-sev-info/40 bg-sev-info/10'
    : 'text-mist-300 border-ink-600 bg-ink-700'
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded border text-[10px] font-semibold ${tone}`}>
      {status}
    </span>
  )
}

/**
 * Renders a possibly-absent value honestly.
 *
 * `kind` distinguishes the reasons something is missing, because they mean
 * different things: an encrypted TLS 1.3 certificate is NOT AVAILABLE, a
 * truncated capture leaves a field UNKNOWN, and a rule that does not apply is
 * NOT APPLICABLE. Collapsing all three to a dash would lose the distinction
 * the engine worked to preserve.
 */
export function Value({ value, kind = 'unknown', mono = false }: {
  value: ReactNode | null | undefined
  kind?: 'unknown' | 'not-available' | 'not-applicable' | 'none'
  mono?: boolean
}) {
  if (value === null || value === undefined || value === '') {
    const text =
      kind === 'not-available' ? 'NOT AVAILABLE'
      : kind === 'not-applicable' ? 'NOT APPLICABLE'
      : kind === 'none' ? 'none'
      : 'UNKNOWN'
    return <span className="text-mist-400 text-[11px] tracking-wide">{text}</span>
  }
  return <span className={mono ? 'mono' : undefined}>{value}</span>
}

export function Loading({ what }: { what: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-mist-300 py-6" role="status">
      <span className="h-3 w-3 rounded-full border-2 border-mist-400 border-t-transparent animate-spin" />
      Loading {what}…
    </div>
  )
}

export function Empty({ title, detail, action }: { title: string; detail?: string; action?: ReactNode }) {
  return (
    <div className="text-center py-10 px-4">
      <p className="text-sm text-mist-200 font-medium">{title}</p>
      {detail && <p className="text-[13px] text-mist-300 mt-1 max-w-lg mx-auto">{detail}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function Failure({ title, detail, onRetry }: { title: string; detail?: string; onRetry?: () => void }) {
  return (
    <div className="panel border-sev-critical/40 bg-sev-critical/5 p-4" role="alert">
      <p className="text-sm font-medium text-sev-critical">{title}</p>
      {detail && <p className="text-[13px] text-mist-200 mt-1">{detail}</p>}
      {onRetry && <button className="btn mt-3" onClick={onRetry}>Try again</button>}
    </div>
  )
}

export function Note({ children, tone = 'default' }: { children: ReactNode; tone?: 'default' | 'warn' }) {
  return (
    <p className={`text-[12px] leading-relaxed border-l-2 pl-3 py-1 my-2 ${
      tone === 'warn' ? 'border-sev-high/50 text-sev-high/90' : 'border-ink-600 text-mist-300'
    }`}>
      {children}
    </p>
  )
}

export function Pagination({ page, onOffset }: {
  page: { total: number; offset: number; limit: number; items: unknown[] }
  onOffset: (offset: number) => void
}) {
  const from = page.total === 0 ? 0 : page.offset + 1
  const to = page.offset + page.items.length
  return (
    <div className="flex items-center justify-between gap-3 pt-3 text-[12px] text-mist-300">
      <span>
        {from}–{to} of {page.total}
      </span>
      <div className="flex gap-2">
        <button className="btn py-1 px-2" disabled={page.offset === 0}
                onClick={() => onOffset(Math.max(0, page.offset - page.limit))}>
          Previous
        </button>
        <button className="btn py-1 px-2" disabled={to >= page.total}
                onClick={() => onOffset(page.offset + page.limit)}>
          Next
        </button>
      </div>
    </div>
  )
}
