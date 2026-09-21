/**
 * The reusable evidence link (§12).
 *
 * A packet reference that leads nowhere is worse than no link at all: it
 * implies the evidence can be inspected when it cannot. So this component only
 * renders a control when there is something real to show, and what it shows is
 * the validated metadata the engine recorded — capture, session, packet
 * number, timestamp, stream offset, the observation it came from and its
 * evidence status.
 *
 * It never shows payload bytes. The engine does not produce them for a report
 * and there is nothing here that could.
 */
import { useState } from 'react'
import { Link } from 'react-router-dom'
import type { EvidenceRef } from '../lib/api'
import { formatTime } from '../lib/hooks'
import { Value } from './ui'

export function EvidenceLink({ evidence, limitations = [] }: {
  evidence: EvidenceRef[]
  limitations?: string[]
}) {
  const [open, setOpen] = useState(false)

  if (evidence.length === 0) {
    return (
      <span className="text-[11px] text-mist-400" data-testid="evidence-none">
        No packet evidence was recorded for this item.
      </span>
    )
  }

  return (
    <div className="mt-2">
      <button
        className="btn py-1 px-2 text-[12px]"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        data-testid="evidence-toggle"
      >
        {open ? 'Hide' : 'Show'} evidence · {evidence.length} packet
        {evidence.length === 1 ? '' : 's'}
      </button>

      {open && (
        <div className="mt-2 panel bg-ink-900/60 p-3" data-testid="evidence-panel">
          <table className="w-full">
            <thead>
              <tr>
                <th className="th">Packet</th>
                <th className="th">Capture timestamp</th>
                <th className="th">Stream offset</th>
                <th className="th">Source observation</th>
                <th className="th">Status</th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((item, index) => (
                <tr key={`${item.packet_number}-${index}`}>
                  <td className="td mono">#{item.packet_number}</td>
                  <td className="td mono">{formatTime(item.timestamp)}</td>
                  <td className="td mono">
                    <Value value={item.stream_offset} kind="not-applicable" />
                  </td>
                  <td className="td text-[12px] text-mist-200">{item.source_observation}</td>
                  <td className="td text-[11px] text-mist-300">{item.evidence_status}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="text-[11px] text-mist-300 mt-3 space-y-1">
            <div>
              Capture <span className="mono">{evidence[0].capture_id}</span>
            </div>
            {evidence[0].session_id && (
              <div>
                Session{' '}
                <Link className="mono text-sev-info hover:underline"
                      to={`/sessions/${evidence[0].session_id}`}>
                  {evidence[0].session_id}
                </Link>
              </div>
            )}
            <p className="pt-1">
              Packet metadata only. Reconstructed payload bytes are never included in a
              report or shown in this interface.
            </p>
            {limitations.map((limitation) => (
              <p key={limitation} className="text-mist-400">{limitation}</p>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
