/**
 * The first screen a new user sees.
 *
 * The product failed a first-time user before this existed: the empty state
 * said "No captures have been analysed yet" and stopped, which explains the
 * database but not the product. This explains what SecureMailScope does, what
 * it accepts, and what the four steps are -- then gets out of the way.
 *
 * No invented counts, no sample data, no marketing. When there is nothing to
 * show, the honest thing to show is what to do next.
 */
import { Link } from 'react-router-dom'

import {
  IconArrowRight, IconDownload, IconFingerprint, IconPacket, IconSearch,
  IconUpload,
} from './icons'

const STEPS = [
  {
    n: '1',
    title: 'Upload',
    detail: 'Add one or more authorized PCAP or PCAPNG captures.',
    icon: IconUpload,
  },
  {
    n: '2',
    title: 'Analyze',
    detail: 'Sessions are reconstructed and TLS evidence is examined locally.',
    icon: IconPacket,
  },
  {
    n: '3',
    title: 'Investigate',
    detail: 'Read findings and trace each one back to the packets behind it.',
    icon: IconSearch,
  },
  {
    n: '4',
    title: 'Export',
    detail: 'Produce a JSON, offline HTML or PDF investigation report.',
    icon: IconDownload,
  },
]

const SUPPORTED = [
  'SMTP', 'IMAP', 'POP3', 'STARTTLS / STLS', 'TLS 1.0–1.3', 'X.509',
]

export function FirstRun() {
  return (
    <div className="max-w-4xl mx-auto py-6" data-testid="first-run">
      <div className="flex items-center gap-2 mb-2">
        <span
          className="inline-flex h-8 w-8 items-center justify-center rounded-lg
                     bg-accent/15 text-accent"
          aria-hidden="true"
        >
          <IconFingerprint size={19} />
        </span>
        <h1 className="text-2xl font-semibold tracking-tight">SecureMailScope</h1>
      </div>

      <p className="text-lg text-mist-100">
        Investigate cryptographic security directly from captured email traffic.
      </p>

      <p className="text-sm text-mist-300 mt-2 max-w-2xl leading-relaxed">
        Upload authorized PCAP/PCAPNG captures. SecureMailScope reconstructs
        email sessions, examines observable TLS evidence, identifies security
        weaknesses, and links every finding back to the packets that establish
        it.
      </p>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Link
          className="btn btn-primary btn-lg"
          to="/investigations"
          data-testid="start-investigation"
        >
          <IconUpload size={15} />
          Start investigation
          <IconArrowRight size={15} />
        </Link>
        <span className="hint">
          Nothing leaves this machine. No host is contacted and no capture is
          transmitted.
        </span>
      </div>

      <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4 mt-6">
        {STEPS.map((step) => (
          <li key={step.n} className="surface p-2.5">
            <div className="flex items-center gap-1.5 mb-1">
              <span
                className="inline-flex h-5 w-5 items-center justify-center rounded
                           bg-ink-800 text-accent text-2xs font-bold"
              >
                {step.n}
              </span>
              <step.icon size={14} className="text-mist-400" />
              <span className="text-sm font-semibold">{step.title}</span>
            </div>
            <p className="hint">{step.detail}</p>
          </li>
        ))}
      </ol>

      <div className="surface mt-3 p-2.5">
        <span className="label">Analyses</span>
        <div className="flex flex-wrap gap-1 mt-1.5">
          {SUPPORTED.map((item) => (
            <span key={item} className="chip">{item}</span>
          ))}
        </div>
        <p className="hint mt-2">
          Analysis is passive and evidence-first. Where a capture cannot show
          something — a TLS 1.3 certificate is encrypted, for instance — the
          result says so rather than guessing or leaving a blank.
        </p>
      </div>
    </div>
  )
}
