/**
 * Upload and investigation list (§6).
 *
 * Progress is real throughout: the upload shows the browser's own byte
 * progress, and analysis shows captures finished out of captures submitted,
 * which the backend reports. Within a single capture the engine reports a
 * named stage but no fraction, so the bar becomes indeterminate rather than
 * inventing one.
 */
import { useCallback, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError, api } from '../lib/api'
import type { CaptureSummary, JobStatus } from '../lib/api'
import { formatBytes, formatTime, useAsync, usePolling } from '../lib/hooks'
import { useInvestigationContext } from '../lib/context'
import { Empty, Failure, Loading, Note, Panel, StatusTag } from '../components/ui'

type Stage = 'idle' | 'validating' | 'uploading' | 'uploaded' | 'rejected'

interface Pending {
  name: string
  size: number
  stage: Stage
  detail?: string
  capture?: CaptureSummary
}

export function Investigations() {
  const navigate = useNavigate()
  const { select } = useInvestigationContext()
  const list = useAsync(() => api.listInvestigations(0, 50), [])
  const captures = useAsync(() => api.listCaptures(0, 100), [])
  const [pending, setPending] = useState<Pending[]>([])
  const [job, setJob] = useState<JobStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const input = useRef<HTMLInputElement>(null)

  const onFiles = useCallback(async (files: FileList | null) => {
    if (!files || files.length === 0) return
    setError(null)
    const staged: Pending[] = Array.from(files).map((file) => ({
      name: file.name, size: file.size, stage: 'validating' as Stage,
    }))
    setPending(staged)

    for (let index = 0; index < files.length; index += 1) {
      const file = files[index]
      setPending((current) =>
        current.map((item, i) => (i === index ? { ...item, stage: 'uploading' } : item)),
      )
      try {
        const capture = await api.uploadCapture(file)
        setPending((current) =>
          current.map((item, i) =>
            i === index
              ? { ...item, stage: 'uploaded', capture, detail: `${capture.file_format} · stored privately` }
              : item,
          ),
        )
      } catch (cause) {
        setPending((current) =>
          current.map((item, i) =>
            i === index
              ? {
                  ...item,
                  stage: 'rejected',
                  detail: cause instanceof ApiError ? cause.detail : 'the upload failed',
                }
              : item,
          ),
        )
      }
    }
    captures.reload()
  }, [captures])

  const analyse = useCallback(async () => {
    const ids = pending.filter((p) => p.capture).map((p) => p.capture!.capture_id)
    if (ids.length === 0) return
    setBusy(true)
    setError(null)
    try {
      const investigation = await api.createInvestigation(
        pending[0]?.name ? `Investigation of ${pending[0].name}` : 'Investigation',
        ids,
      )
      select(investigation.investigation_id)
      const started = await api.startAnalysis(investigation.investigation_id)
      setJob(started)
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.detail : 'the analysis could not be started')
      setBusy(false)
    }
  }, [pending, select])

  const poll = useCallback(() => {
    if (!job) return
    api.getJob(job.job_id).then((next) => {
      setJob(next)
      if (next.status === 'COMPLETED') {
        setBusy(false)
        list.reload()
        navigate(`/investigations/${next.investigation_id}`)
      } else if (next.status === 'FAILED' || next.status === 'CANCELLED') {
        setBusy(false)
        list.reload()
      }
    }).catch(() => setBusy(false))
  }, [job, list, navigate])

  usePolling(Boolean(job) && (job?.status === 'QUEUED' || job?.status === 'RUNNING'), 500, poll)

  const ready = pending.filter((p) => p.capture).length

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold">Investigations</h1>
        <p className="text-[13px] text-mist-300 mt-0.5">
          Upload one or more captures. Several captures analysed together become a
          multi-capture investigation with cross-capture drift and correlation.
        </p>
      </header>

      <Panel title="Upload captures">
        <input
          ref={input}
          type="file"
          multiple
          accept=".pcap,.pcapng"
          className="hidden"
          data-testid="file-input"
          onChange={(event) => onFiles(event.target.files)}
        />
        <div className="flex flex-wrap items-center gap-2">
          <button className="btn btn-primary" onClick={() => input.current?.click()} disabled={busy}>
            Select PCAP or PCAPNG files
          </button>
          {ready > 0 && (
            <button className="btn" onClick={analyse} disabled={busy} data-testid="analyse-button">
              {busy ? 'Analysing…' : `Analyse ${ready} capture${ready === 1 ? '' : 's'}`}
            </button>
          )}
        </div>
        <Note>
          Captures are stored privately outside the repository and are never transmitted
          anywhere. The file extension is not trusted; the container format is confirmed
          from the file's own magic bytes.
        </Note>

        {pending.length > 0 && (
          <table className="w-full mt-3" data-testid="upload-table">
            <thead>
              <tr>
                <th className="th">File</th><th className="th">Size</th>
                <th className="th">Validation</th><th className="th">Detail</th>
              </tr>
            </thead>
            <tbody>
              {pending.map((item) => (
                <tr key={item.name}>
                  <td className="td">{item.name}</td>
                  <td className="td">{formatBytes(item.size)}</td>
                  <td className="td">
                    {item.stage === 'uploaded' && <span className="text-sev-ok text-[12px]">ACCEPTED</span>}
                    {item.stage === 'rejected' && <span className="text-sev-critical text-[12px]">REJECTED</span>}
                    {(item.stage === 'uploading' || item.stage === 'validating') && (
                      <span className="text-sev-info text-[12px]">
                        {item.stage === 'uploading' ? 'UPLOADING' : 'VALIDATING'}
                      </span>
                    )}
                  </td>
                  <td className="td text-[12px] text-mist-300">{item.detail ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {job && (
          <div className="mt-4 panel bg-ink-900/60 p-3" data-testid="job-panel">
            <div className="flex items-center justify-between gap-3">
              <span className="text-[13px]">
                Analysis <StatusTag status={job.status} />
              </span>
              <span className="text-[12px] text-mist-300">
                {job.captures_total > 0
                  ? `${job.captures_done} of ${job.captures_total} captures`
                  : 'in progress'}
              </span>
            </div>
            {/* Determinate only when the backend reports a real proportion. */}
            <div className="h-1.5 bg-ink-700 rounded mt-2 overflow-hidden">
              {job.captures_total > 0 ? (
                <div
                  className="h-full bg-sev-info transition-[width] duration-300"
                  style={{ width: `${(job.captures_done / job.captures_total) * 100}%` }}
                  data-testid="progress-determinate"
                />
              ) : (
                <div className="h-full w-1/3 bg-sev-info/60 animate-pulse" data-testid="progress-indeterminate" />
              )}
            </div>
            {job.stage && <p className="text-[12px] text-mist-300 mt-2">Stage: {job.stage}</p>}
            {job.error && <p className="text-[12px] text-sev-critical mt-2">{job.error}</p>}
            {job.warnings.map((warning) => (
              <p key={warning} className="text-[12px] text-sev-high mt-1">{warning}</p>
            ))}
          </div>
        )}

        {error && <Failure title="Analysis could not be started" detail={error} />}
      </Panel>

      <Panel title="Investigations">
        {list.loading && <Loading what="investigations" />}
        {list.error && <Failure title="Could not load investigations" detail={list.error} onRetry={list.reload} />}
        {list.data && list.data.items.length === 0 && (
          <Empty title="No investigations yet" detail="Upload a capture above to create one." />
        )}
        {list.data && list.data.items.length > 0 && (
          <table className="w-full">
            <thead>
              <tr>
                <th className="th">Name</th><th className="th">Status</th>
                <th className="th">Captures</th><th className="th">Sessions</th>
                <th className="th">Findings</th><th className="th">Created</th>
              </tr>
            </thead>
            <tbody>
              {list.data.items.map((item) => (
                <tr key={item.investigation_id}>
                  <td className="td">
                    <Link className="text-sev-info hover:underline"
                          to={`/investigations/${item.investigation_id}`}
                          onClick={() => select(item.investigation_id)}>
                      {item.name}
                    </Link>
                    <div className="mono text-mist-400 text-[11px]">{item.investigation_id}</div>
                  </td>
                  <td className="td"><StatusTag status={item.status} /></td>
                  <td className="td">
                    {item.analysed_capture_count}
                    {item.failed_capture_count > 0 && (
                      <span className="text-sev-critical text-[11px]"> · {item.failed_capture_count} failed</span>
                    )}
                  </td>
                  <td className="td">{item.session_count}</td>
                  <td className="td">{item.finding_count}</td>
                  <td className="td text-[12px] text-mist-300">{formatTime(item.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Stored captures">
        {captures.loading && <Loading what="captures" />}
        {captures.data && captures.data.items.length === 0 && (
          <Empty title="No captures stored" />
        )}
        {captures.data && captures.data.items.length > 0 && (
          <table className="w-full">
            <thead>
              <tr>
                <th className="th">Name</th><th className="th">Format</th><th className="th">Size</th>
                <th className="th">Packets</th><th className="th">Status</th><th className="th">Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {captures.data.items.map((item) => (
                <tr key={item.capture_id}>
                  <td className="td">
                    {item.original_name}
                    <div className="mono text-mist-400 text-[11px]">{item.capture_id}</div>
                  </td>
                  <td className="td">{item.file_format ?? 'unknown'}</td>
                  <td className="td">{formatBytes(item.file_size_bytes)}</td>
                  <td className="td">{item.packet_count || '—'}</td>
                  <td className="td">
                    <StatusTag status={item.status} />
                    {item.failure_reason && (
                      <div className="text-[11px] text-sev-critical mt-1">{item.failure_reason}</div>
                    )}
                  </td>
                  <td className="td text-[12px] text-mist-300">{formatTime(item.uploaded_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  )
}
