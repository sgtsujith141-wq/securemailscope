/**
 * Typed client for the local API.
 *
 * The token is fetched at runtime from the dev-server proxy or supplied by the
 * host page. It is never written into committed source, which is why there is
 * no default value here and no `.env` file in the repository.
 */

export interface Page<T> { items: T[]; total: number; offset: number; limit: number }

export interface Health {
  status: string
  tool_name: string
  tool_version: string
  report_schema_version: string
  database_schema_version: number
  ml_available: boolean
  ml_status: string
  analyzer_works_without_ml: boolean
}

export interface CaptureSummary {
  capture_id: string
  original_name: string
  file_size_bytes: number
  file_format: string | null
  packet_count: number
  session_count: number
  status: string
  failure_reason: string | null
  uploaded_at: string
  first_packet_timestamp: string | null
  last_packet_timestamp: string | null
}

export interface InvestigationSummary {
  investigation_id: string
  name: string
  status: string
  created_at: string
  updated_at: string
  capture_count: number
  analysed_capture_count: number
  failed_capture_count: number
  session_count: number
  finding_count: number
  /** null means no score is available, which is not the same as zero. */
  posture_score: number | null
  score_status: string | null
  score_band: string | null
  /** What the headline score describes; names the weakest capture and range. */
  score_scope: string | null
  coverage_ratio: number | null
  severity_counts: Record<string, number>
  protocol_counts: Record<string, number>
}

export interface JobStatus {
  job_id: string
  investigation_id: string
  status: string
  stage: string | null
  captures_total: number
  captures_done: number
  created_at: string
  started_at: string | null
  finished_at: string | null
  error: string | null
  warnings: string[]
}

export interface MLSummary {
  ml_status: string
  feature_schema_version: string | null
  anomaly_algorithm: string | null
  /** False for the deterministic rarity baseline M6 selected. */
  anomaly_detector_is_ml: boolean
  anomaly_model_id: string | null
  anomaly_model_version: string | null
  classifier_model_id: string | null
  classification_validation_status: string
  anomalous_session_count: number
  not_evaluable_session_count: number
  evaluation_available: boolean
}

export interface InvestigationDetail {
  investigation: InvestigationSummary
  captures: CaptureSummary[]
  jobs: JobStatus[]
  policy_id: string | null
  policy_version: string | null
  policy_fingerprint: string | null
  fingerprint_count: number
  entity_count: number
  drift_count: number
  correlation_count: number
  timeline_event_count: number
  ml: MLSummary | null
  warnings: string[]
  scope_statement: string
}

export interface SessionSummary {
  session_id: string
  investigation_id: string
  capture_id: string
  client: string
  server: string
  protocol: string | null
  detection_status: string | null
  tls_version: string | null
  cipher_suite: string | null
  key_exchange: string | null
  certificate_visibility: string | null
  completeness: string | null
  packet_count: number
  finding_count: number
  posture_score: number | null
  score_status: string | null
  coverage_ratio: number | null
}

export interface EvidenceRef {
  capture_id: string
  session_id: string | null
  packet_number: number
  timestamp: string | null
  stream_offset: number | null
  source_observation: string
  evidence_status: string
}

export interface FindingSummary {
  finding_id: string
  investigation_id: string
  capture_id: string
  session_id: string
  rule_id: string
  title: string
  severity: string
  confidence: string
  category: string
  evaluation_status: string
  priority: string | null
  rank: number | null
}

export interface FindingDetail {
  finding: FindingSummary
  description: string
  technical_impact: string
  policy_version: string | null
  standards_references: string[]
  remediation_ids: string[]
  limitations: string[]
  evidence: EvidenceRef[]
}

export interface SessionDetail {
  session: SessionSummary
  findings: FindingSummary[]
  // Shape mirrors the engine's own models; rendered defensively.
  detail: Record<string, unknown>
}

export interface TimelineEntry {
  event_id: string
  event_type: string
  timestamp: string | null
  capture_id: string
  session_id: string | null
  description: string
  evidence_status: string
  packet_numbers: number[]
  order_index: number
}

export interface Settings {
  max_upload_bytes: number
  max_capture_bytes: number
  max_packets: number
  max_total_sessions: number
  assess_security: boolean
  minimum_score_coverage_percent: number
  enable_ml: boolean
  default_report_format: string
  retain_captures: boolean
  requires_reanalysis: string[]
  storage_root: string
  storage_usage_bytes: number
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public detail: string,
  ) {
    super(detail)
    this.name = 'ApiError'
  }
}

let token: string | null = null
export function setToken(value: string | null): void {
  token = value
}

function headers(extra?: Record<string, string>): Record<string, string> {
  const base: Record<string, string> = { ...extra }
  if (token) base['x-securemailscope-token'] = token
  return base
}

async function parse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let detail = `request failed with status ${response.status}`
    try {
      const body = await response.json()
      if (body?.detail) detail = typeof body.detail === 'string' ? body.detail : detail
    } catch {
      // A non-JSON error body is not itself an error worth surfacing; the
      // status code already says what happened.
    }
    throw new ApiError(response.status, detail)
  }
  return (await response.json()) as T
}

async function get<T>(path: string): Promise<T> {
  return parse<T>(await fetch(path, { headers: headers() }))
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  return parse<T>(
    await fetch(path, {
      method: 'POST',
      headers: headers({ 'content-type': 'application/json' }),
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  )
}

function query(
  params: Record<string, string | number | boolean | undefined | null>,
): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '' && value !== null) search.set(key, String(value))
  }
  const text = search.toString()
  return text ? `?${text}` : ''
}

export const api = {
  health: () => get<Health>('/api/health'),

  listCaptures: (offset = 0, limit = 50) =>
    get<Page<CaptureSummary>>(`/api/captures${query({ offset, limit })}`),

  uploadCapture: async (file: File): Promise<CaptureSummary> => {
    const form = new FormData()
    form.append('file', file)
    return parse<CaptureSummary>(
      await fetch('/api/captures', { method: 'POST', headers: headers(), body: form }),
    )
  },

  createInvestigation: (name: string, captureIds: string[]) =>
    post<InvestigationSummary>('/api/investigations', { name, capture_ids: captureIds }),

  startAnalysis: (id: string) => post<JobStatus>(`/api/investigations/${id}/analyze`),

  listInvestigations: (offset = 0, limit = 25) =>
    get<Page<InvestigationSummary>>(`/api/investigations${query({ offset, limit })}`),

  getInvestigation: (id: string) => get<InvestigationDetail>(`/api/investigations/${id}`),

  getJob: (jobId: string) => get<JobStatus>(`/api/jobs/${jobId}`),

  listSessions: (
    id: string,
    options: {
      offset?: number
      limit?: number
      search?: string
      protocol?: string
      tls_version?: string
      capture_id?: string
      has_findings?: boolean
      sort?: string
      direction?: 'asc' | 'desc'
    } = {},
  ) => get<Page<SessionSummary>>(`/api/investigations/${id}/sessions${query(options)}`),

  // `investigationId` scopes the lookup. Session and finding ids are digests
  // of their own content, so the same capture analysed in two investigations
  // produces the same id in both; without the scope the backend returns
  // whichever copy it finds first.
  getSession: (sessionId: string, investigationId?: string | null) =>
    get<SessionDetail>(
      `/api/sessions/${sessionId}${query({ investigation_id: investigationId })}`,
    ),

  listFindings: (
    id: string,
    options: {
      offset?: number
      limit?: number
      severity?: string
      category?: string
      rule_id?: string
      session_id?: string
      capture_id?: string
      evaluation_status?: string
    } = {},
  ) => get<Page<FindingSummary>>(`/api/investigations/${id}/findings${query(options)}`),

  getFinding: (findingId: string, investigationId?: string | null) =>
    get<FindingDetail>(
      `/api/findings/${findingId}${query({ investigation_id: investigationId })}`,
    ),

  getIntelligence: (id: string, section?: string) =>
    get<Record<string, unknown>>(`/api/investigations/${id}/intelligence${query({ section })}`),

  getTimeline: (
    id: string,
    options: { offset?: number; limit?: number; event_type?: string; session_id?: string; capture_id?: string } = {},
  ) => get<Page<TimelineEntry>>(`/api/investigations/${id}/timeline${query(options)}`),

  getML: (id: string) => get<Record<string, unknown>>(`/api/investigations/${id}/ml`),

  getSettings: () => get<Settings>('/api/settings'),
  updateSettings: (payload: Partial<Settings>) => post<Settings>('/api/settings', payload),

  exportUrl: (id: string, format: 'json' | 'html' | 'pdf') =>
    `/api/investigations/${id}/export/${format}`,

  download: async (id: string, format: 'json' | 'html' | 'pdf'): Promise<Blob> => {
    const response = await fetch(api.exportUrl(id, format), { headers: headers() })
    if (!response.ok) throw new ApiError(response.status, 'the export could not be generated')
    return await response.blob()
  },
}
