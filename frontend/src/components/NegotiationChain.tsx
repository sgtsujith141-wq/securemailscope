/**
 * The TLS negotiation, drawn as the chain it is (§14).
 *
 * A handshake is a sequence of decisions, and a reader's question is which
 * link is weak. A grid of eight equal fields cannot answer that; this can,
 * because each link is tinted by the findings the engine raised against that
 * part of the session -- never by a judgement made here.
 *
 * A link the capture did not show is drawn as UNKNOWN, dashed and grey. It is
 * never given the colour of a passing link.
 */
import type { ReactNode } from 'react'

import type { FindingSummary } from '../lib/api'
import { IconArrowRight } from './icons'

/** Which finding categories bear on which link of the chain. */
const LINK_CATEGORY: Record<string, string[]> = {
  version: ['TLS_PROTOCOL'],
  cipher: ['CIPHER_SUITE'],
  exchange: ['KEY_EXCHANGE'],
  certificate: ['CERTIFICATE'],
  transport: ['EMAIL_TRANSPORT'],
}
const RANK = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
const TONE: Record<string, { fg: string; bg: string; border: string }> = {
  CRITICAL: { fg: '#fb7185', bg: 'rgba(251,113,133,0.10)', border: 'rgba(251,113,133,0.45)' },
  HIGH: { fg: '#fb923c', bg: 'rgba(251,146,60,0.10)', border: 'rgba(251,146,60,0.45)' },
  MEDIUM: { fg: '#fbbf24', bg: 'rgba(251,191,36,0.10)', border: 'rgba(251,191,36,0.42)' },
  LOW: { fg: '#22d3ee', bg: 'rgba(34,211,238,0.08)', border: 'rgba(34,211,238,0.38)' },
  INFO: { fg: '#60a5fa', bg: 'rgba(96,165,250,0.08)', border: 'rgba(96,165,250,0.38)' },
  OK: { fg: '#34d399', bg: 'rgba(52,211,153,0.08)', border: 'rgba(52,211,153,0.38)' },
}

function worst(findings: FindingSummary[], key: string): string | null {
  const categories = LINK_CATEGORY[key] ?? []
  const relevant = findings.filter((f) => categories.includes(f.category))
  if (relevant.length === 0) return null
  return relevant
    .map((f) => f.severity)
    .reduce((a, b) => (RANK.indexOf(b) > RANK.indexOf(a) ? b : a))
}

function Link({ label, value, severity, unknownNote }: {
  label: string
  value: ReactNode
  severity: string | null
  unknownNote?: string
}) {
  const known = value !== null && value !== undefined && value !== ''
  const tone = !known ? null : TONE[severity ?? 'OK']
  return (
    <div
      className={`min-w-0 flex-1 rounded-md px-2.5 py-2 ${known ? 'border' : 'border border-dashed border-ink-700'}`}
      style={known && tone
        ? { background: tone.bg, borderColor: tone.border }
        : undefined}
    >
      <div className="label">{label}</div>
      <div className="mono mt-1 !text-[12px] !text-mist-100 break-all">
        {known ? value : <span className="!text-mist-400">UNKNOWN</span>}
      </div>
      {known && severity && (
        <span className="mt-1 inline-block text-3xs font-bold tracking-wide"
              style={{ color: tone?.fg }}>
          {severity}
        </span>
      )}
      {!known && unknownNote && <p className="hint mt-1 !text-3xs">{unknownNote}</p>}
    </div>
  )
}

export function NegotiationChain({
  entryPoint, version, cipherSuite, keyExchange, certificate, findings,
}: {
  entryPoint: string | null | undefined
  version: string | null | undefined
  cipherSuite: string | null | undefined
  keyExchange: string | null | undefined
  /** The engine's `certificate_visibility`, rendered as given. */
  certificate: string | null | undefined
  findings: FindingSummary[]
}) {
  const links: [string, ReactNode, string | null, string?][] = [
    ['Entry point', entryPoint, worst(findings, 'transport'),
     'How TLS began was not observable in this capture.'],
    ['Version', version, worst(findings, 'version')],
    ['Cipher suite', cipherSuite, worst(findings, 'cipher')],
    ['Key exchange', keyExchange, worst(findings, 'exchange')],
    ['Certificate', certificate, worst(findings, 'certificate')],
  ]
  return (
    <div className="flex flex-col items-stretch gap-1.5 lg:flex-row lg:items-center"
         data-testid="negotiation-chain">
      {links.map(([label, value, severity, note], index) => (
        <div key={label} className="flex min-w-0 flex-1 items-center gap-1.5">
          <Link label={label} value={value} severity={severity} unknownNote={note} />
          {index < links.length - 1 && (
            <span className="hidden shrink-0 text-mist-600 lg:block" aria-hidden="true">
              <IconArrowRight size={14} />
            </span>
          )}
        </div>
      ))}
    </div>
  )
}
