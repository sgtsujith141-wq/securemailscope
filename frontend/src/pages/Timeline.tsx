/** The evidence timeline (§15). Real capture timestamps, real packet links. */
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api'
import { formatTime, useAsync } from '../lib/hooks'
import { useInvestigationContext } from '../lib/context'
import { Empty, Failure, Loading, Note, Pagination, Panel } from '../components/ui'

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
                  onChange={(e) => { setEventType(e.target.value); setOffset(0) }}>
            <option value="">All event types</option>
            {EVENT_TYPES.map((t) => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
          </select>
          <input className="input flex-1 min-w-[180px]" placeholder="Filter by session id"
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
            <ol className="space-y-1" data-testid="timeline-list">
              {page.data.items.map((event) => (
                <li key={event.event_id}
                    className="grid grid-cols-[auto_150px_1fr] gap-3 items-start py-2 border-b border-ink-700 last:border-0">
                  <span className="text-[11px] text-mist-400 mono pt-0.5 w-8 text-right">
                    {event.order_index}
                  </span>
                  <span className="mono text-[11px] text-mist-300 pt-0.5">
                    {event.timestamp ? formatTime(event.timestamp).slice(11, 26) : 'unknown'}
                  </span>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[12px] font-medium">{event.event_type.replace(/_/g, ' ')}</span>
                      <span className="text-[10px] text-mist-400 border border-ink-600 rounded px-1">
                        {event.evidence_status}
                      </span>
                      {event.session_id && (
                        <Link className="mono text-[11px] text-sev-info hover:underline"
                              to={`/sessions/${event.session_id}`}>
                          {event.session_id}
                        </Link>
                      )}
                    </div>
                    <p className="text-[12px] text-mist-300 mt-0.5">{event.description}</p>
                    {event.packet_numbers.length > 0 && (
                      <p className="text-[11px] text-mist-400 mt-0.5">
                        Packets {event.packet_numbers.join(', ')} · capture{' '}
                        <span className="mono">{event.capture_id.slice(0, 24)}…</span>
                      </p>
                    )}
                  </div>
                </li>
              ))}
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
