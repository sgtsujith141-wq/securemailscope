/** Settings (§22). Only controls the backend genuinely acts on. */
import { useEffect, useState } from 'react'
import { ApiError, api } from '../lib/api'
import type { Settings } from '../lib/api'
import { formatBytes, useAsync } from '../lib/hooks'
import { Failure, Loading, Note, Panel } from '../components/ui'

export function SettingsPage() {
  const loaded = useAsync(() => api.getSettings(), [])
  const [draft, setDraft] = useState<Settings | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => { if (loaded.data) setDraft(loaded.data) }, [loaded.data])

  if (loaded.loading) return <Loading what="settings" />
  if (loaded.error) return <Failure title="Could not load settings" detail={loaded.error} onRetry={loaded.reload} />
  if (!draft) return null

  const set = <K extends keyof Settings>(key: K, value: Settings[K]) => {
    setDraft({ ...draft, [key]: value })
    setSaved(false)
  }

  async function save() {
    if (!draft) return
    setSaving(true)
    setError(null)
    try {
      const next = await api.updateSettings({
        max_upload_bytes: draft.max_upload_bytes,
        max_capture_bytes: draft.max_capture_bytes,
        max_packets: draft.max_packets,
        max_total_sessions: draft.max_total_sessions,
        assess_security: draft.assess_security,
        minimum_score_coverage_percent: draft.minimum_score_coverage_percent,
        enable_ml: draft.enable_ml,
        default_report_format: draft.default_report_format,
        retain_captures: draft.retain_captures,
      })
      setDraft(next)
      setSaved(true)
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.detail : 'the settings could not be saved')
    } finally {
      setSaving(false)
    }
  }

  const NumberField = ({ label, field, hint }: { label: string; field: keyof Settings; hint?: string }) => (
    <label className="block">
      <span className="label">{label}</span>
      <input
        className="input w-full mt-1"
        type="number"
        min={1}
        value={String(draft[field])}
        data-testid={`setting-${String(field)}`}
        onChange={(e) => set(field, Number(e.target.value) as never)}
      />
      {hint && <span className="text-[11px] text-mist-400 mt-1 block">{hint}</span>}
    </label>
  )

  const Toggle = ({ label, field, hint }: { label: string; field: keyof Settings; hint?: string }) => (
    <label className="flex items-start gap-2 cursor-pointer">
      <input type="checkbox" className="mt-1" checked={Boolean(draft[field])}
             data-testid={`setting-${String(field)}`}
             onChange={(e) => set(field, e.target.checked as never)} />
      <span>
        <span className="text-[13px]">{label}</span>
        {hint && <span className="text-[11px] text-mist-400 block">{hint}</span>}
      </span>
    </label>
  )

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Settings</h1>
        <p className="text-[13px] text-mist-300 mt-0.5">
          Only settings the backend acts on are shown here.
        </p>
      </header>

      <Panel title="Upload and analysis limits">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <NumberField label="Max upload bytes" field="max_upload_bytes"
                       hint="Enforced while the upload streams, not after." />
          <NumberField label="Max capture bytes" field="max_capture_bytes" />
          <NumberField label="Max packets" field="max_packets" />
          <NumberField label="Max total sessions" field="max_total_sessions" />
        </div>
      </Panel>

      <Panel title="Assessment and ML">
        <div className="space-y-3">
          <Toggle label="Run the security assessment"
                  field="assess_security"
                  hint="Forensic observations are reported either way." />
          <NumberField label="Minimum score coverage (%)" field="minimum_score_coverage_percent"
                       hint="Below this, no score is produced at all rather than a misleading number." />
          <Toggle label="Run the machine-learning layer"
                  field="enable_ml"
                  hint="The analyzer is fully functional with this off." />
        </div>
      </Panel>

      <Panel title="Reports and retention">
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="block">
            <span className="label">Default report format</span>
            <select className="input w-full mt-1" value={draft.default_report_format}
                    data-testid="setting-default_report_format"
                    onChange={(e) => set('default_report_format', e.target.value)}>
              {['json', 'html', 'pdf'].map((f) => <option key={f} value={f}>{f.toUpperCase()}</option>)}
            </select>
          </label>
          <Toggle label="Retain uploaded captures"
                  field="retain_captures"
                  hint="Captures are stored privately outside the repository. Deleting one is an explicit action and never happens automatically." />
        </div>
        <dl className="grid gap-3 sm:grid-cols-2 mt-4 text-[12px]">
          <div><dt className="label">Private storage location</dt>
               <dd className="mono mt-1 text-mist-300">{draft.storage_root}</dd></div>
          <div><dt className="label">Storage in use</dt>
               <dd className="mt-1 text-mist-300">{formatBytes(draft.storage_usage_bytes)}</dd></div>
        </dl>
      </Panel>

      <Note tone="warn">
        Changing {draft.requires_reanalysis.join(', ')} affects future analyses only.
        Existing investigations are never silently rewritten — re-run an analysis to apply
        a changed setting to it.
      </Note>

      <div className="flex items-center gap-3">
        <button className="btn btn-primary" onClick={save} disabled={saving} data-testid="save-settings">
          {saving ? 'Saving…' : 'Save settings'}
        </button>
        {saved && <span className="text-[12px] text-sev-ok">Saved.</span>}
      </div>
      {error && <Failure title="Settings were not saved" detail={error} />}
    </div>
  )
}
