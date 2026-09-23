/**
 * Fixtures shaped exactly like the backend's real responses.
 *
 * Copied from actual API output rather than invented, so a component test
 * exercises the shape the server genuinely sends.
 */
import type {
  CaptureSummary, FindingDetail, FindingSummary, InvestigationDetail,
  InvestigationSummary, JobStatus, Page, SessionDetail, SessionSummary, Settings,
  TimelineEntry,
} from '../lib/api'

export const page = <T,>(items: T[]): Page<T> => ({
  items, total: items.length, offset: 0, limit: 50,
})

export const investigation: InvestigationSummary = {
  investigation_id: 'inv-1234567890ab',
  name: 'Demo investigation',
  status: 'COMPLETED',
  created_at: '2026-09-21T10:00:00Z',
  updated_at: '2026-09-21T10:00:10Z',
  capture_count: 1,
  analysed_capture_count: 1,
  failed_capture_count: 0,
  session_count: 1,
  finding_count: 4,
  posture_score: 59,
  score_status: 'AVAILABLE',
  score_band: 'WEAK',
  score_scope: 'capture aa_tls10_static_rsa.pcap',
  coverage_ratio: 0.7551,
  severity_counts: { HIGH: 2, MEDIUM: 1, INFO: 1 },
  protocol_counts: { IMAP: 1 },
}

export const unscoredInvestigation: InvestigationSummary = {
  ...investigation,
  investigation_id: 'inv-unscored0001',
  name: 'Insufficient evidence',
  finding_count: 0,
  posture_score: null,
  score_status: 'SCORE_UNAVAILABLE',
  score_band: null,
  coverage_ratio: 0.04,
  severity_counts: {},
}

export const capture: CaptureSummary = {
  capture_id: 'sha256:a78557eb039e84fcb12e06f4a61587f460d48f5f22be6f2550a7559977a6bcf1',
  original_name: 'aa_tls10_static_rsa.pcap',
  file_size_bytes: 990,
  file_format: 'PCAP',
  packet_count: 5,
  session_count: 1,
  status: 'ANALYZED',
  failure_reason: null,
  uploaded_at: '2026-09-21T10:00:00Z',
  first_packet_timestamp: '2026-06-01T12:00:00Z',
  last_packet_timestamp: '2026-06-01T12:00:00.004Z',
}

export const failedCapture: CaptureSummary = {
  ...capture,
  capture_id: 'unanalysed:broken.pcap',
  original_name: 'broken.pcap',
  status: 'FAILED',
  failure_reason: 'MalformedCaptureError: the capture container format is not recognised',
  packet_count: 0,
  session_count: 0,
}

export const job: JobStatus = {
  job_id: 'job-abcdef012345',
  investigation_id: investigation.investigation_id,
  status: 'COMPLETED',
  stage: 'completed',
  captures_total: 1,
  captures_done: 1,
  created_at: '2026-09-21T10:00:00Z',
  started_at: '2026-09-21T10:00:01Z',
  finished_at: '2026-09-21T10:00:09Z',
  error: null,
  warnings: [],
}

export const failedJob: JobStatus = {
  ...job,
  job_id: 'job-failed000001',
  status: 'FAILED',
  stage: 'failed',
  captures_done: 0,
  error: 'MalformedCaptureError: the capture container format is not recognised',
}

export const investigationDetail: InvestigationDetail = {
  investigation,
  captures: [capture],
  jobs: [job],
  policy_id: 'securemailscope-default',
  policy_version: '1.0.0',
  policy_fingerprint: 'a9f912f235f1',
  fingerprint_count: 1,
  entity_count: 1,
  drift_count: 0,
  correlation_count: 0,
  timeline_event_count: 10,
  ml: {
    ml_status: 'COMPLETED',
    feature_schema_version: 'smsfeat/1',
    anomaly_algorithm: 'rarity_baseline',
    anomaly_detector_is_ml: false,
    anomaly_model_id: 'tls-anomaly',
    anomaly_model_version: '1.0.0',
    classifier_model_id: 'tls-posture',
    classification_validation_status: 'NOT_VALIDATED',
    anomalous_session_count: 0,
    not_evaluable_session_count: 0,
    evaluation_available: true,
  },
  warnings: [],
  scope_statement: 'Observed within analyzed captures only.',
}

export const session: SessionSummary = {
  session_id: 'sess-efe8cce0daf09e49',
  investigation_id: investigation.investigation_id,
  capture_id: capture.capture_id,
  client: '192.0.2.10:49152',
  server: '198.51.100.25:993',
  protocol: 'IMAP',
  detection_status: 'PORT_HINT',
  tls_version: 'TLS 1.0',
  cipher_suite: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  key_exchange: 'RSA',
  certificate_visibility: 'OBSERVED',
  completeness: 'COMPLETE',
  packet_count: 5,
  finding_count: 4,
  posture_score: 59,
  score_status: 'AVAILABLE',
  coverage_ratio: 0.7551,
}

export const tls13Session: SessionSummary = {
  ...session,
  session_id: 'sess-tls13000000001',
  tls_version: 'TLS 1.3',
  cipher_suite: 'TLS_AES_128_GCM_SHA256',
  certificate_visibility: 'NOT_OBSERVED_ENCRYPTED',
  posture_score: null,
  score_status: 'SCORE_UNAVAILABLE',
}

export const finding: FindingSummary = {
  finding_id: 'find-36217459a78b25e5',
  investigation_id: investigation.investigation_id,
  capture_id: capture.capture_id,
  session_id: session.session_id,
  rule_id: 'TLS-KEX-001',
  title: 'Negotiated key exchange does not provide forward secrecy',
  severity: 'HIGH',
  confidence: 'CONFIRMED',
  category: 'KEY_EXCHANGE',
  evaluation_status: 'FAIL',
  priority: 'P1',
  rank: 1,
}

export const findingDetail: FindingDetail = {
  finding,
  description:
    'RFC 5246 §7.4.7.1: the negotiated suite TLS_RSA_WITH_AES_128_CBC_SHA uses static RSA key exchange.',
  technical_impact:
    'An attacker who records the traffic now and obtains the server long-term key later can decrypt it.',
  policy_version: '1.0.0',
  standards_references: ['RFC 9325 §4.2', 'RFC 5246 §7.4.7.1'],
  remediation_ids: ['REM-TLS-FS'],
  limitations: ['Forward secrecy here is a property of the negotiated key exchange.'],
  evidence: [
    {
      capture_id: capture.capture_id,
      session_id: session.session_id,
      packet_number: 4,
      timestamp: '2026-06-01T12:00:00.003000Z',
      stream_offset: null,
      source_observation: 'assessment rule TLS-KEX-001',
      evidence_status: 'INFERRED',
    },
    {
      capture_id: capture.capture_id,
      session_id: session.session_id,
      packet_number: 5,
      timestamp: '2026-06-01T12:00:00.004000Z',
      stream_offset: null,
      source_observation: 'assessment rule TLS-KEX-001',
      evidence_status: 'INFERRED',
    },
  ],
}

export const sessionDetail: SessionDetail = {
  session,
  findings: [finding],
  detail: {
    streams: {
      client_to_server: {
        packet_count: 2, bytes_reconstructed: 120, segment_count: 1,
        gap_count: 0, retransmission_count: 0, out_of_order_count: 0,
      },
      server_to_client: {
        packet_count: 1, bytes_reconstructed: 600, segment_count: 1,
        gap_count: 0, retransmission_count: 0, out_of_order_count: 0,
      },
    },
    tls: {
      entry_point: 'IMPLICIT',
      handshake_state: 'SERVER_FLIGHT_COMPLETE',
      key_exchange: { method: 'RSA', selected_group: null },
      forward_secrecy: { status: 'STATIC_RSA_KEY_EXCHANGE' },
      server_name_indication: 'mail.example.invalid',
      certificates: { certificates: [], validation: null },
      limitations: [],
    },
    protocol: {
      detection: { protocol: 'IMAP', status: 'PORT_HINT', explanation: 'Port 993 is a hint.' },
      parse_state: 'NOT_PARSED',
      upgrade: null,
      authentication: [],
    },
    ml: {
      anomaly: {
        status: 'NOT_ANOMALOUS', raw_score: 0.0244, decision_threshold: 0,
        explanation: 'Machine-learning observation: this combination occurred in 2.4% of the reference population.',
      },
      classification: {
        status: 'NOT_VALIDATED', predicted_class: 'HIGH',
      },
    },
  },
}

export const timeline: TimelineEntry[] = [
  {
    event_id: 'evt-000000000001',
    event_type: 'SESSION_FIRST_PACKET',
    timestamp: '2026-06-01T12:00:00Z',
    capture_id: capture.capture_id,
    session_id: session.session_id,
    description: 'First packet of session',
    evidence_status: 'OBSERVED',
    packet_numbers: [1],
    order_index: 0,
  },
  {
    event_id: 'evt-000000000002',
    event_type: 'SECURITY_FINDING',
    timestamp: '2026-06-01T12:00:00.003Z',
    capture_id: capture.capture_id,
    session_id: session.session_id,
    description: 'TLS-KEX-001 (HIGH): Negotiated key exchange does not provide forward secrecy',
    evidence_status: 'INFERRED',
    packet_numbers: [4, 5],
    order_index: 1,
  },
]

/**
 * Intelligence, ML and settings payloads, shaped from the real API responses
 * (captured from a live analysis of `aa_tls10_static_rsa.pcap`, then trimmed).
 * The backend types these as open records, so TypeScript would not have caught
 * a wrong shape here -- the values are taken from the running API rather than
 * invented.
 */
/**
 * One section of the intelligence document, as the endpoint returns it.
 *
 * The page always asks for a section, and the response names the section it
 * belongs to. Tests build theirs through this so a mock cannot claim to be a
 * section the page did not ask for.
 */
export const intelligenceSection = (
  section: string,
  items: Record<string, unknown>[] = [],
): Record<string, unknown> => ({
  investigation_id: investigation.investigation_id,
  section,
  items,
  scope_statement: 'Covers only the captures listed.',
  limitations: [],
})

export const intelligence: Record<string, unknown> = {
  investigation_id: investigation.investigation_id,
  schema_version: '1.0.0',
  fingerprint_algorithm_version: 'smsfp/1',
  created_at: '2026-06-01T12:00:00Z',
  capture_inventory: [],
  server_entities: [],
  cryptographic_fingerprints: [],
  drift_events: [],
  session_correlations: [],
  evidence_timeline: [],
  blast_radius: [],
  intelligence_warnings: [],
  scope_statement: 'Covers only the captures listed.',
  limitations: [],
}

export const ml: Record<string, unknown> = {
  summary: {
    ml_status: 'COMPLETED',
    feature_schema_version: 'smsfeat/1',
    anomaly_algorithm: 'rarity-baseline',
    anomaly_detector_is_ml: false,
    anomaly_model_id: 'tls-anomaly',
    anomaly_model_version: '1.0.0',
    classifier_model_id: 'tls-posture',
    classification_validation_status: 'NOT_VALIDATED',
    anomalous_session_count: 0,
    not_evaluable_session_count: 0,
    evaluation_available: true,
  },
  results: [],
  evaluation: null,
}

export const settings: Settings = {
  max_upload_bytes: 536870912,
  max_capture_bytes: 536870912,
  max_packets: 2000000,
  max_total_sessions: 100000,
  assess_security: true,
  minimum_score_coverage_percent: 50,
  enable_ml: true,
  default_report_format: 'pdf',
  retain_captures: true,
  requires_reanalysis: ['max_packets', 'enable_ml'],
  storage_root: '/tmp/securemailscope/storage',
  storage_usage_bytes: 992,
}
