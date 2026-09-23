/** The evidence timeline (§15). Real capture timestamps, real packet links. */
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api'
import { formatClock, formatDay, useAsync } from '../lib/hooks'
import { useInvestigationContext } from '../lib/context'
import { Empty, Failure, Loading, Note, Pagination, Panel } from '../components/ui'

/** Evidence status drives the dot colour; it is never decorative. */
const EVENT_TINT: Record<string, string> = {
  OBSERVED: '#22d3ee',
  INFERRED: '#a78bfa',
  UNKNOWN: '#64748b',
  NOT_AVAILABLE: '#64748b',
}

const EVENT_TYPES = [
  'SESSION_FIRST_PACKET', 'PROTOCOL_IDENTIFIED', 'UPGRADE_ADVERTISED', 'UPGRADE_REQUESTED',
  'UPGRADE_ACCEPTED', 'UPGRADE_REJECTED', 'CLIENT_HELLO', 'SERVER_HELLO',
  'CRYPTO_PARAMETERS_SELECTED', 'CERTIFICATE_OBSERVED', 'TLS_ALERT',
  'AUTHENTICATION_OBSERVED', 'SECURITY_FINDING', 'CONFIGURATION_DRIFT',
]

export function Timeline() {
  const { selected } = useInvestigationContext()
  const [offset, setOffset] = useState(0)
  const [eventType, setEventType] = useState('')
  const [sessionId, setSessionId] = useState('')

  const detail = useAsync(
    () => (selected ? api.getInvestigation(selected) : Promise.resolve(null)),
    [selected],
  )
  const page = useAsync(
    () =>
      selected
        ? api.getTimeline(selected, {
            offset, limit: 50,
            event_type: eventType || undefined,
            session_id: sessionId || undefined,
          })
        : Promise.resolve(null),
    [selected, offset, eventType, sessionId],
  )

  if (!selected) {
    return <Empty title="No investigation selected"
                  action={<Link className="btn btn-primary" to="/investigations">Investigations</Link>} />
  }

  const multiCapture = (detail.data?.captures.length ?? 0) > 1

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Evidence timeline</h1>
        <p className="text-[13px] text-mist-300 mt-0.5">
          Events in capture-timestamp order. Every entry links to the packets that
          established it.
        </p>
      </header>

      {multiCapture && (
        <Note tone="warn">
          This investigation spans several captures. Timestamps come from each capturing
          host's own clock; no synchronisation is assumed, measured or corrected for, so
          ordering <strong>across</strong> captures may not reflect real-world chronology.
          Within one capture the order is meaningful.
        </Note>
      )}

      <Panel>
        <div className="flex flex-wrap gap-2">
          <select className="input" value={eventType} data-testid="event-type-filter"
                  aria-label="Filter timeline by event type"
                  onChange={(e) => { setEventType(e.target.value); setOffset(0) }}>
            <option value="">All event types</option>
            {EVENT_TYPES.map((t) => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
          </select>
          <input className="input flex-1 min-w-[180px]" placeholder="Filter by session id"
                 aria-label="Filter timeline by session id"
                 value={sessionId} data-testid="timeline-session-filter"
                 onChange={(e) => { setSessionId(e.target.value); setOffset(0) }} />
        </div>
      </Panel>

      <Panel>
        {page.loading && <Loading what="timeline" />}
        {page.error && <Failure title="Could not load the timeline" detail={page.error} onRetry={page.reload} />}
        {page.data && page.data.items.length === 0 && (
          <Empty title="No timeline events match" detail="Adjust the filters above." />
        )}
        {page.data && page.data.items.length > 0 && (
          <>
            {/* A rail, not a table: the left border is the thread of the
                investigation, each dot is one event, and the dot's colour is
                the evidence status the engine assigned -- so a reader can see
                at a glance which entries were observed in a packet and which
                were inferred. */}
            <ol className="relative ml-1 border-l border-ink-740" data-testid="timeline-list">
              {page.data.items.map((event, index) => {
                const previous = index > 0 ? page.data!.items[index - 1] : null
                const newDay = formatDay(event.timestamp) !== formatDay(previous?.timestamp)
                const tint = EVENT_TINT[event.evidence_status] ?? '#64748b'
                return (
                  <li key={event.event_id} className="relative pb-3 pl-5">
                    {newDay && (
                      <div className="mb-2 -ml-5 flex items-center gap-2">
                        <span className="label !text-mist-300">{formatDay(event.timestamp)}</span>
                        <span className="h-px flex-1 bg-ink-820" aria-hidden="true" />
                      </div>
                    )}
                    <span
                      className="absolute -left-[5px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-ink-900"
                      style={{ background: tint, boxShadow: `0 0 0 3px ${tint}22` }}
                      aria-hidden="true"
                    />
                    <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                      <span className="mono !text-[11px] !text-mist-400 tabular-nums">
                        {formatClock(event.timestamp)}
                      </span>
                      <span className="text-[12px] font-semibold text-mist-100">
                        {event.event_type.replace(/_/g, ' ').toLowerCase()}
                      </span>
                      <span className="text-3xs font-semibold" style={{ color: tint }}>
                        {event.evidence_status}
                      </span>
                      {event.session_id && (
                        <Link className="mono !text-[11px] text-sev-info hover:underline"
                              to={`/sessions/${event.session_id}`}>
                          {event.session_id}
                        </Link>
                      )}
                      <span className="ml-auto text-3xs text-mist-500 tabular-nums">
                        #{event.order_index}
                      </span>
                    </div>
                    <p className="mt-0.5 text-[12px] text-mist-300">{event.description}</p>
                    {event.packet_numbers.length > 0 && (
                      <p className="hint mt-0.5 !text-3xs">
                        packets {event.packet_numbers.join(', ')} · capture{' '}
                        <span className="mono !text-3xs">{event.capture_id.slice(0, 24)}…</span>
                      </p>
                    )}
                  </li>
                )
              })}
            </ol>
            <Pagination page={page.data} onOffset={setOffset} />
            <Note>
              Events sharing a timestamp keep a documented, stable order: capture, session,
              event rank, then packet number. Several handshake messages routinely arrive
              in one packet.
            </Note>
          </>
        )}
      </Panel>
    </div>
  )
}
