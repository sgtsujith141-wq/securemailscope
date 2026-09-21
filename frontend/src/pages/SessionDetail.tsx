/** One session, in full (§11). UNKNOWN and NOT AVAILABLE are shown as such. */
import { Link, useParams } from 'react-router-dom'
import { api } from '../lib/api'
import { formatTime, useAsync } from '../lib/hooks'
import { EvidenceLink } from '../components/EvidenceLink'
import { Empty, Failure, Loading, Note, Panel, SeverityTag, Value } from '../components/ui'

function Field({ label, value, kind = 'unknown', mono = false }: {
  label: string; value: unknown; kind?: 'unknown' | 'not-available' | 'not-applicable'; mono?: boolean
}) {
  return (
    <div>
      <dt className="label">{label}</dt>
      <dd className="mt-1 text-[13px]">
        <Value value={value as never} kind={kind} mono={mono} />
      </dd>
    </div>
  )
}

export function SessionDetailPage() {
  const { sessionId } = useParams()
  const detail = useAsync(
    () => (sessionId ? api.getSession(sessionId) : Promise.resolve(null)),
    [sessionId],
  )

  if (detail.loading) return <Loading what="session" />
  if (detail.error) return <Failure title="Session not available" detail={detail.error} onRetry={detail.reload} />
  if (!detail.data) return <Empty title="Session not found" />

  const { session, findings } = detail.data
  const raw = detail.data.detail as Record<string, any>
  const tls = raw?.tls as Record<string, any> | null
  const protocol = raw?.protocol as Record<string, any> | null
  const streams = raw?.streams as Record<string, any> | undefined
  const ml = raw?.ml as Record<string, any> | undefined
  const isTls13 = session.tls_version === 'TLS 1.3'

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Session detail</h1>
          <p className="mono text-[12px] text-mist-400 mt-0.5">{session.session_id}</p>
        </div>
        <Link className="btn" to="/sessions">Back to sessions</Link>
      </header>

      <Panel title="Connection">
        <dl className="grid gap-3 sm:grid-cols-3 lg:grid-cols-4">
          <Field label="Client" value={session.client} mono />
          <Field label="Server" value={session.server} mono />
          <Field label="Capture" value={session.capture_id} mono />
          <Field label="Packets" value={session.packet_count} />
          <Field label="Completeness" value={session.completeness} />
          <Field label="Protocol" value={session.protocol} />
          <Field label="Detection status" value={session.detection_status} />
          <Field label="Upgrade state" value={raw?.protocol?.upgrade?.state} kind="not-applicable" />
        </dl>
      </Panel>

      <Panel title="TCP reconstruction">
        {!streams ? <Empty title="No stream summary recorded" /> : (
          <table className="w-full">
            <thead>
              <tr><th className="th">Direction</th><th className="th">Packets</th><th className="th">Bytes</th>
                  <th className="th">Segments</th><th className="th">Gaps</th><th className="th">Retrans.</th>
                  <th className="th">Out of order</th></tr>
            </thead>
            <tbody>
              {['client_to_server', 'server_to_client'].map((key) => {
                const s = streams[key]
                if (!s) return null
                return (
                  <tr key={key}>
                    <td className="td">{key.replace(/_/g, ' → ').replace('client', 'client').replace('server', 'server')}</td>
                    <td className="td">{s.packet_count}</td>
                    <td className="td">{s.bytes_reconstructed}</td>
                    <td className="td">{s.segment_count}</td>
                    <td className="td">{s.gap_count > 0 ? <span className="text-sev-high">{s.gap_count}</span> : 0}</td>
                    <td className="td">{s.retransmission_count}</td>
                    <td className="td">{s.out_of_order_count}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
        <Note>
          Counts and offsets only. Reconstructed payload bytes never leave the engine and
          are never displayed.
        </Note>
      </Panel>

      {protocol && (
        <Panel title="Email protocol observations">
          <dl className="grid gap-3 sm:grid-cols-3">
            <Field label="Protocol" value={protocol.detection?.protocol} />
            <Field label="Detection" value={protocol.detection?.status} />
            <Field label="Parse state" value={protocol.parse_state} />
          </dl>
          {protocol.detection?.explanation && (
            <p className="text-[12px] text-mist-300 mt-3">{protocol.detection.explanation}</p>
          )}
          {protocol.upgrade && (
            <div className="mt-4">
              <h3 className="label mb-2">STARTTLS / STLS transition</h3>
              <dl className="grid gap-3 sm:grid-cols-3">
                <Field label="Mechanism" value={protocol.upgrade.mechanism} />
                <Field label="State" value={protocol.upgrade.state} />
                <Field label="Response code" value={protocol.upgrade.response_code} kind="not-applicable" />
              </dl>
            </div>
          )}
          {Array.isArray(protocol.authentication) && protocol.authentication.length > 0 && (
            <Note tone="warn">
              {protocol.authentication.length} authentication attempt(s) observed. No
              username, password, token or SASL payload is recorded anywhere.
            </Note>
          )}
        </Panel>
      )}

      <Panel title="TLS negotiation">
        {!tls ? (
          <Empty title="This session carried no TLS" />
        ) : (
          <>
            <dl className="grid gap-3 sm:grid-cols-3 lg:grid-cols-4">
              <Field label="Entry point" value={tls.entry_point} />
              <Field label="Handshake state" value={tls.handshake_state} />
              <Field label="Negotiated version" value={session.tls_version} />
              <Field label="Cipher suite" value={session.cipher_suite} mono />
              <Field label="Key exchange" value={tls.key_exchange?.method} />
              <Field label="Named group" value={tls.key_exchange?.selected_group?.name} kind="not-applicable" />
              <Field label="Forward secrecy" value={tls.forward_secrecy?.status} />
              <Field label="SNI" value={tls.server_name_indication} kind="not-applicable" />
            </dl>
            {Array.isArray(tls.limitations) && tls.limitations.length > 0 && (
              <div className="mt-3 space-y-1">
                {tls.limitations.map((l: string) => (
                  <p key={l} className="text-[11px] text-mist-400">{l}</p>
                ))}
              </div>
            )}
          </>
        )}
      </Panel>

      <Panel title="Certificate intelligence">
        {isTls13 && session.certificate_visibility !== 'OBSERVED' ? (
          <Note>
            <strong>NOT AVAILABLE.</strong> TLS 1.3 encrypts the Certificate message, so no
            certificate can be observed from a passive capture without decryption material
            this tool does not accept. This is a property of the protocol, not a gap in the
            capture.
          </Note>
        ) : !tls?.certificates?.certificates?.length ? (
          <Empty title="No certificate was observed" detail="The handshake may have been truncated before the Certificate message." />
        ) : (
          <div className="space-y-3">
            {tls.certificates.certificates.map((cert: any) => (
              <div key={cert.sha256_fingerprint} className="panel bg-ink-900/50 p-3">
                <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  <Field label="Subject" value={cert.subject} mono />
                  <Field label="Issuer" value={cert.issuer} mono />
                  <Field label="Key" value={`${cert.public_key?.algorithm ?? 'unknown'} ${cert.public_key?.size_bits ?? ''}`} />
                  <Field label="Signature hash" value={cert.signature_hash_algorithm} />
                  <Field label="Not before" value={formatTime(cert.not_valid_before)} />
                  <Field label="Not after" value={formatTime(cert.not_valid_after)} />
                </dl>
                <p className="mono text-[10px] text-mist-400 mt-2">
                  SHA-256 {cert.sha256_fingerprint}
                </p>
              </div>
            ))}
            {tls.certificates.validation && (
              <table className="w-full">
                <thead>
                  <tr>
                    <th className="th">Check</th><th className="th">Result</th>
                    <th className="th">Explanation</th>
                  </tr>
                </thead>
                <tbody>
                  {['certificate_observed', 'validity_dates_checked', 'chain_verified',
                    'hostname_verified', 'revocation_checked'].map((key) => {
                    // Each entry is a check object, not a bare status string.
                    const check = tls.certificates.validation[key] as
                      | { status?: string; explanation?: string }
                      | undefined
                    return (
                      <tr key={key}>
                        <td className="td">{key.replace(/_/g, ' ')}</td>
                        <td className="td text-[12px]">
                          <Value value={check?.status} kind="not-available" />
                        </td>
                        <td className="td text-[11px] text-mist-300">
                          <Value value={check?.explanation} kind="none" />
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        )}
      </Panel>

      <Panel title={`Security findings (${findings.length})`}>
        {findings.length === 0 ? (
          <Empty title="NO FINDINGS" detail="No rule failed on this session's evidence. That is not a statement that the session is secure." />
        ) : (
          <div className="space-y-3">
            {findings.map((finding) => (
              <FindingBlock key={finding.finding_id} findingId={finding.finding_id}
                            title={finding.title} severity={finding.severity}
                            ruleId={finding.rule_id} confidence={finding.confidence} />
            ))}
          </div>
        )}
      </Panel>

      {ml && (
        <Panel title="Machine-learning observations">
          {!ml.anomaly ? <Empty title="No ML result for this session" /> : (
            <>
              <dl className="grid gap-3 sm:grid-cols-3">
                <Field label="Anomaly status" value={ml.anomaly.status} />
                <Field label="Score" value={ml.anomaly.raw_score} kind="not-applicable" />
                <Field label="Decision threshold" value={ml.anomaly.decision_threshold} kind="not-applicable" />
              </dl>
              <p className="text-[12px] text-mist-300 mt-3">{ml.anomaly.explanation}</p>
              {ml.classification && (
                <Note tone="warn">
                  Risk classification: <strong>{ml.classification.predicted_class ?? 'none'}</strong> —
                  status {ml.classification.status}. This is not a confirmed threat and the
                  scores are not calibrated probabilities.
                </Note>
              )}
            </>
          )}
        </Panel>
      )}
    </div>
  )
}

function FindingBlock({ findingId, title, severity, ruleId, confidence }: {
  findingId: string; title: string; severity: string; ruleId: string; confidence: string
}) {
  const detail = useAsync(() => api.getFinding(findingId), [findingId])
  return (
    <div className="panel bg-ink-900/50 p-3" data-testid="session-finding">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityTag severity={severity} />
        <strong className="text-[13px]">{title}</strong>
        <span className="mono text-[11px] text-mist-400">{ruleId}</span>
        <span className="text-[11px] text-mist-400">confidence {confidence}</span>
      </div>
      {detail.data && (
        <>
          <p className="text-[12px] text-mist-200 mt-2">{detail.data.description}</p>
          <EvidenceLink evidence={detail.data.evidence} limitations={detail.data.limitations} />
        </>
      )}
      {detail.loading && <Loading what="evidence" />}
    </div>
  )
}
