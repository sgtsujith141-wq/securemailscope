/** The investigation detail page (§10). */
import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api'
import { formatBytes, formatTime, useAsync } from '../lib/hooks'
import { useInvestigationContext } from '../lib/context'
import { NeedsAttention } from '../components/NeedsAttention'
import { Empty, Failure, Loading, Metric, Note, Panel, StatusTag, Value } from '../components/ui'

export function InvestigationWorkspace({ investigationId }: { investigationId: string }) {
  const { select } = useInvestigationContext()
  const detail = useAsync(() => api.getInvestigation(investigationId), [investigationId])
  // The highest-ranked findings, for the attention hero. Ranked by the
  // engine's own priority matrix -- this page does no ordering of its own.
  const topFindings = useAsync(
    () => api.listFindings(investigationId, { offset: 0, limit: 6 }),
    [investigationId],
  )

  useEffect(() => { select(investigationId) }, [investigationId, select])

  if (detail.loading) return <Loading what="investigation" />
  if (detail.error) {
    return <Failure title="Investigation not available" detail={detail.error} onRetry={detail.reload} />
  }
  if (!detail.data) return <Empty title="Investigation not found" />

  const { investigation: inv, captures, jobs, ml } = detail.data
  const failed = captures.filter((c) => c.status === 'FAILED' || c.failure_reason)

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{inv.name}</h1>
          <p className="mono text-[12px] text-mist-400 mt-0.5">{inv.investigation_id}</p>
        </div>
        <div className="flex items-center gap-2">
          <StatusTag status={inv.status} />
          <Link className="btn" to="/reports">Reports</Link>
        </div>
      </header>

      <p className="text-sm text-mist-300">{detail.data.scope_statement}</p>

      {/* What needs attention comes before the summary numbers. A score
          summarises; a finding is the substance. */}
      <NeedsAttention
        findings={topFindings.data?.items ?? []}
        total={inv.finding_count}
        loading={topFindings.loading}
      />

      <div className="grid gap-2 grid-cols-2 lg:grid-cols-4">
        <Metric label="Captures analysed" value={inv.analysed_capture_count}
                note={inv.failed_capture_count > 0 ? `${inv.failed_capture_count} failed` : undefined} />
        <Metric label="Sessions" value={inv.session_count} testId="session-count" />
        <Metric
          label="Findings"
          testId="finding-count"
          value={inv.finding_count === 0 ? <span className="text-sev-ok text-base">NO FINDINGS</span> : inv.finding_count}
          tone={inv.finding_count === 0 ? 'unknown' : 'default'} />
        <Metric
          label="Posture score"
          testId="posture-score"
          value={inv.posture_score === null
            ? <span className="text-mist-300 text-base">{inv.status === 'COMPLETED' ? 'INSUFFICIENT EVIDENCE' : 'NOT ANALYSED'}</span>
            : <>{inv.posture_score}<span className="text-mist-400 text-sm">/100</span></>}
          note={inv.posture_score === null ? inv.score_status ?? undefined
            : `${inv.score_band} · coverage ${inv.coverage_ratio !== null ? (inv.coverage_ratio * 100).toFixed(0) + '%' : 'unknown'}`}
          detail={inv.posture_score !== null && inv.capture_count > 1
            ? inv.score_scope ?? undefined
            : undefined}
          tone={inv.posture_score === null ? 'unknown' : 'default'} />
      </div>

      {inv.finding_count > 0 && (
        <Note tone="warn">
          The score summarises weighted control coverage. It does not supersede an
          individual finding — open <Link className="underline" to="/findings">security findings</Link> to
          see each one with its evidence.
        </Note>
      )}

      {failed.length > 0 && (
        <Panel title="Partial batch failures">
          <table className="w-full">
            <thead><tr><th className="th">Capture</th><th className="th">Status</th><th className="th">Reason</th></tr></thead>
            <tbody>
              {failed.map((c) => (
                <tr key={c.capture_id}>
                  <td className="td">{c.original_name}</td>
                  <td className="td"><StatusTag status={c.status} /></td>
                  <td className="td text-[12px] text-mist-300">{c.failure_reason ?? 'not stated'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Note tone="warn">
            Results elsewhere on this page do not cover these captures.
          </Note>
        </Panel>
      )}

      <Panel title="Capture inventory">
        <table className="w-full">
          <thead>
            <tr>
              <th className="th">Capture</th><th className="th">Format</th><th className="th">Size</th>
              <th className="th">Packets</th><th className="th">Sessions</th><th className="th">Status</th>
              <th className="th">First packet</th>
            </tr>
          </thead>
          <tbody>
            {captures.map((c) => (
              <tr key={c.capture_id}>
                <td className="td">{c.original_name}<div className="mono text-mist-400 text-[11px]">{c.capture_id}</div></td>
                <td className="td">{c.file_format ?? 'unknown'}</td>
                <td className="td">{formatBytes(c.file_size_bytes)}</td>
                <td className="td">{c.packet_count}</td>
                <td className="td">{c.session_count}</td>
                <td className="td"><StatusTag status={c.status} /></td>
                <td className="td text-[12px] text-mist-300">{formatTime(c.first_packet_timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Assessment">
          <dl className="grid grid-cols-2 gap-3 text-[13px]">
            <div><dt className="label">Policy</dt><dd className="mt-1"><Value value={detail.data.policy_id} /></dd></div>
            <div><dt className="label">Policy version</dt><dd className="mt-1 mono"><Value value={detail.data.policy_version} /></dd></div>
            <div><dt className="label">Policy fingerprint</dt><dd className="mt-1 mono"><Value value={detail.data.policy_fingerprint} /></dd></div>
            <div><dt className="label">Coverage</dt>
              <dd className="mt-1"><Value value={inv.coverage_ratio === null ? null : `${(inv.coverage_ratio * 100).toFixed(0)}%`} /></dd></div>
          </dl>
          <div className="flex gap-2 mt-4">
            <Link className="btn" to="/sessions">Sessions</Link>
            <Link className="btn" to="/findings">Findings</Link>
          </div>
        </Panel>

        <Panel title="Cryptographic intelligence">
          <dl className="grid grid-cols-2 gap-3 text-[13px]">
            <div><dt className="label">Fingerprints</dt><dd className="mt-1">{detail.data.fingerprint_count}</dd></div>
            <div><dt className="label">Server entities</dt><dd className="mt-1">{detail.data.entity_count}</dd></div>
            <div><dt className="label">Drift observations</dt><dd className="mt-1">{detail.data.drift_count}</dd></div>
            <div><dt className="label">Correlations</dt><dd className="mt-1">{detail.data.correlation_count}</dd></div>
          </dl>
          <div className="flex gap-2 mt-4">
            <Link className="btn" to="/intelligence">Intelligence</Link>
            <Link className="btn" to="/timeline">Timeline ({detail.data.timeline_event_count})</Link>
          </div>
        </Panel>
      </div>

      <Panel title="Machine-learning analysis">
        {!ml ? (
          <Empty title="No ML results" detail="The analysis completed without a machine-learning model. Every forensic and assessment result above is complete." />
        ) : (
          <>
            <dl className="grid gap-3 sm:grid-cols-3 text-[13px]">
              <div><dt className="label">Status</dt><dd className="mt-1">{ml.ml_status}</dd></div>
              <div><dt className="label">Anomaly detector</dt>
                <dd className="mt-1 mono">{ml.anomaly_algorithm ?? 'none'}</dd></div>
              <div><dt className="label">Classifier</dt>
                <dd className="mt-1">{ml.classification_validation_status}</dd></div>
            </dl>
            {!ml.anomaly_detector_is_ml && ml.anomaly_algorithm && (
              <Note>
                The selected detector is a deterministic frequency table, not a
                machine-learning model.
              </Note>
            )}
            <Link className="btn mt-3 inline-flex" to="/ml">ML analysis</Link>
          </>
        )}
      </Panel>

      <Panel title="Analysis jobs">
        {jobs.length === 0 ? <Empty title="No jobs recorded" /> : (
          <table className="w-full">
            <thead>
              <tr><th className="th">Job</th><th className="th">Status</th><th className="th">Progress</th>
                  <th className="th">Stage</th><th className="th">Finished</th></tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.job_id}>
                  <td className="td mono text-[11px]">{job.job_id}</td>
                  <td className="td"><StatusTag status={job.status} /></td>
                  <td className="td">{job.captures_done}/{job.captures_total}</td>
                  <td className="td text-[12px] text-mist-300">
                    {job.stage ?? '—'}
                    {job.error && <div className="text-sev-critical mt-1">{job.error}</div>}
                  </td>
                  <td className="td text-[12px] text-mist-300">{formatTime(job.finished_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {detail.data.warnings.length > 0 && (
          <div className="mt-3 space-y-1">
            {detail.data.warnings.map((w) => (
              <p key={w} className="text-[12px] text-sev-high">{w}</p>
            ))}
          </div>
        )}
      </Panel>
    </div>
  )
}
