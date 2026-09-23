/**
 * The investigation dashboard.
 *
 * Composed as a command surface rather than a grid of equal cards:
 *
 *   1. a hero that states the conclusion beside the posture visualisation,
 *   2. four cryptographic modules of different shape,
 *   3. priority findings beside the evidence timeline rail,
 *   4. cryptographic intelligence beside the report hand-off,
 *
 * and only then the inventories a reader consults rather than reads. Every
 * value is one the engine produced; this page performs no analysis.
 */
import { useEffect } from 'react'
import { Link } from 'react-router-dom'

import { api } from '../lib/api'
import { formatBytes, formatTime, useAsync } from '../lib/hooks'
import { useInvestigationContext } from '../lib/context'
import { CryptoModules } from '../components/CryptoModules'
import {
  IntelligencePreview, ReportHandoff, TimelinePreview,
} from '../components/DashboardRows'
import { AttentionHeadline, PriorityFindings } from '../components/NeedsAttention'
import { PostureHero } from '../components/PostureHero'
import { Empty, Failure, Loading, Note, Panel, StatusTag, Value } from '../components/ui'

/** How many sessions the dashboard modules aggregate over. The API caps a
 *  page at 500; where an investigation holds more, each module says which
 *  subset it describes rather than implying full coverage. */
const SESSION_WINDOW = 500

export function InvestigationWorkspace({ investigationId }: { investigationId: string }) {
  const { select } = useInvestigationContext()
  const detail = useAsync(() => api.getInvestigation(investigationId), [investigationId])
  // The highest-ranked findings, for the attention hero. Ranked by the
  // engine's own priority matrix -- this page does no ordering of its own.
  const topFindings = useAsync(
    () => api.listFindings(investigationId, { offset: 0, limit: 8 }),
    [investigationId],
  )
  const sessions = useAsync(
    () => api.listSessions(investigationId, { offset: 0, limit: SESSION_WINDOW }),
    [investigationId],
  )
  const timeline = useAsync(
    () => api.getTimeline(investigationId, { offset: 0, limit: 6 }),
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
  const sessionItems = sessions.data?.items ?? []

  return (
    <div className="space-y-3">
      <header className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
        <div className="min-w-0">
          <h1 className="truncate text-base font-semibold text-mist-100">{inv.name}</h1>
          <p className="mono mt-0.5 !text-3xs !text-mist-500">{inv.investigation_id}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <StatusTag status={inv.status} />
          <Link className="btn" to="/sessions">Sessions</Link>
          <Link className="btn" to="/reports">Reports</Link>
        </div>
      </header>

      {/* ---- row 1: what needs attention, and the posture beside it ------- */}
      <div className="grid gap-3 xl:grid-cols-[1.65fr_1fr]">
        <AttentionHeadline inv={inv} sessions={sessionItems} loading={sessions.loading} />
        <PostureHero inv={inv} />
      </div>

      {inv.finding_count > 0 && (
        <Note tone="warn">
          The score summarises weighted control coverage. It does not supersede an
          individual finding — open <Link className="underline" to="/findings">findings</Link> to
          see each one with its evidence.
        </Note>
      )}

      {/* ---- row 2: four cryptographic modules --------------------------- */}
      {sessions.loading ? <Loading what="sessions" /> : (
        <CryptoModules
          inv={inv}
          sessions={sessionItems}
          sessionsShown={sessionItems.length}
          sessionsTotal={sessions.data?.total ?? sessionItems.length}
        />
      )}

      {/* ---- row 3: the findings themselves, beside the evidence rail ---- */}
      <div className="grid gap-3 xl:grid-cols-[1.65fr_1fr]">
        <div className="space-y-3">
          <PriorityFindings
            findings={topFindings.data?.items ?? []}
            total={inv.finding_count}
            loading={topFindings.loading}
          />
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
        </div>
        <TimelinePreview
          entries={timeline.data?.items ?? []}
          total={detail.data.timeline_event_count}
          loading={timeline.loading}
        />
      </div>

      {/* ---- row 4: intelligence, and the hand-off out of the tool -------- */}
      <div className="grid gap-3 xl:grid-cols-2">
        <IntelligencePreview detail={detail.data} />
        <ReportHandoff
          investigationId={inv.investigation_id}
          schemaNote={detail.data.scope_statement}
        />
      </div>

      {/* ---- the inventories a reader consults rather than reads ---------- */}
      <Panel area="investigate" title="Capture inventory">
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

      <div className="grid gap-3 lg:grid-cols-2">
        <Panel area="findings" title="Assessment policy">
          <dl className="grid grid-cols-2 gap-3 text-[13px]">
            <div><dt className="label">Policy</dt><dd className="mt-1"><Value value={detail.data.policy_id} /></dd></div>
            <div><dt className="label">Policy version</dt><dd className="mt-1 mono"><Value value={detail.data.policy_version} /></dd></div>
            <div className="col-span-2"><dt className="label">Policy fingerprint</dt><dd className="mt-1 mono"><Value value={detail.data.policy_fingerprint} /></dd></div>
          </dl>
        </Panel>

        <Panel area="intelligence" title="Machine-learning analysis">
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
              <Link className="btn mt-3 inline-flex" to="/ml">ML &amp; analytics</Link>
            </>
          )}
        </Panel>
      </div>

      <Panel area="investigate" title="Analysis jobs">
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
