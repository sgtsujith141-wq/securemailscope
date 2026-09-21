/**
 * The ML interface (§16).
 *
 * M6's findings are preserved exactly, and the page is structured around them:
 *
 *  - A deterministic **rarity baseline** was selected. It is not a
 *    machine-learning model and is never labelled as one.
 *  - **Isolation Forest** was trained and evaluated, and lost. It is shown as
 *    an experimental candidate, clearly not the detector in use.
 *  - The **supervised classifier** is NOT_VALIDATED. Its predictions are never
 *    presented as confirmed threats.
 *
 * Every benchmark number is read from the versioned evaluation artifact the
 * backend serves. None is written into this file, so the UI cannot drift from
 * the model that produced them.
 */
import { Link } from 'react-router-dom'
import { api } from '../lib/api'
import { useAsync } from '../lib/hooks'
import { useInvestigationContext } from '../lib/context'
import { Empty, Failure, Loading, Note, Panel, Value } from '../components/ui'

function Metrics({ metrics }: { metrics: Record<string, any> | undefined }) {
  if (!metrics) return <span className="text-mist-400 text-[11px]">not reported</span>
  const format = (value: unknown) =>
    value === null || value === undefined ? 'undefined' : typeof value === 'number' ? value.toFixed(4) : String(value)
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[12px] mt-2">
      <div><span className="label">Precision</span><div className="mono">{format(metrics.precision)}</div></div>
      <div><span className="label">Recall</span><div className="mono">{format(metrics.recall)}</div></div>
      <div><span className="label">F1</span><div className="mono">{format(metrics.f1)}</div></div>
      <div><span className="label">False-positive rate</span><div className="mono">{format(metrics.false_positive_rate)}</div></div>
      <div className="col-span-2 sm:col-span-4 text-[11px] text-mist-400">
        TP {metrics.true_positives} · FP {metrics.false_positives} · TN {metrics.true_negatives} ·
        FN {metrics.false_negatives}
      </div>
    </div>
  )
}

export function MLAnalysis() {
  const { selected } = useInvestigationContext()
  const data = useAsync(() => (selected ? api.getML(selected) : Promise.resolve(null)), [selected])

  if (!selected) {
    return <Empty title="No investigation selected"
                  action={<Link className="btn btn-primary" to="/investigations">Investigations</Link>} />
  }
  if (data.loading) return <Loading what="ML analysis" />
  if (data.error) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-semibold">ML analysis</h1>
        <Failure title="No ML results for this investigation" detail={data.error} onRetry={data.reload} />
        <Note>
          The forensic and assessment results are complete without machine learning. Its
          absence removes nothing from the analysis.
        </Note>
      </div>
    )
  }

  const summary = data.data?.summary as Record<string, any> | null
  const evaluation = data.data?.evaluation as Record<string, any> | null
  const results = (data.data?.results as Record<string, any>[]) ?? []

  const anomalySelection = evaluation?.anomaly_selection as Record<string, any> | undefined
  const anomalyMetrics = evaluation?.anomaly_metrics as Record<string, any> | undefined
  const classification = evaluation?.classification_metrics as Record<string, any> | undefined
  const classificationSelection = evaluation?.classification_selection as Record<string, any> | undefined

  const perSession = results.flatMap((block) => (block.anomaly_results ?? []) as Record<string, any>[])
  const classifications = results.flatMap((block) => (block.risk_classification ?? []) as Record<string, any>[])

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold">ML analysis</h1>
        <p className="text-[13px] text-mist-300 mt-0.5">
          Status: {summary?.ml_status ?? 'unknown'}. All results below are advisory and
          modify no finding, score or observation.
        </p>
      </header>

      {!summary && (
        <Empty title="MODEL_UNAVAILABLE"
               detail="No machine-learning model is installed. The forensic and assessment results are complete and unaffected." />
      )}

      {/* 1. The detector actually in use. */}
      <Panel title="Deterministic rarity analysis — the detector in use">
        {!summary?.anomaly_algorithm ? (
          <Empty title="No anomaly detector available" />
        ) : summary.anomaly_detector_is_ml ? (
          <Note tone="warn">
            The selected detector is <span className="mono">{summary.anomaly_algorithm}</span>,
            a trained model. See the experimental section below.
          </Note>
        ) : (
          <>
            <Note>
              The selected detector is <span className="mono">{summary.anomaly_algorithm}</span> —
              a <strong>deterministic frequency table, not a machine-learning model</strong>.
              It scores how often a session's (version, encryption, key exchange)
              combination occurred in a recorded reference population. M6 selected it over
              the Isolation Forest candidate because it performed better on held-out
              evaluation.
            </Note>
            <dl className="grid gap-3 sm:grid-cols-4 text-[13px] mt-3">
              <div><dt className="label">Model id</dt><dd className="mono mt-1">{summary.anomaly_model_id}</dd></div>
              <div><dt className="label">Version</dt><dd className="mono mt-1">{summary.anomaly_model_version}</dd></div>
              <div><dt className="label">Feature schema</dt><dd className="mono mt-1">{summary.feature_schema_version}</dd></div>
              <div><dt className="label">Unusual sessions</dt><dd className="mt-1">{summary.anomalous_session_count}</dd></div>
            </dl>
            {anomalyMetrics?.rarity_baseline_test && (
              <div className="mt-3">
                <p className="label">Held-out evaluation</p>
                <Metrics metrics={anomalyMetrics.rarity_baseline_test} />
              </div>
            )}
            <Note>
              An anomaly is a configuration unusual relative to the recorded reference
              population. It is <strong>not</strong> a vulnerability, an attack, or evidence
              of intent — a rare configuration is often the strongest one present.
            </Note>
          </>
        )}
      </Panel>

      {/* 2. The model that was trained and did not win. */}
      <Panel title="Experimental anomaly model — not in use">
        {!anomalySelection ? (
          <Empty title="No evaluation record available"
                 detail="Benchmark numbers are read from the versioned evaluation artifact and are not shown when it is absent." />
        ) : (
          <>
            <Note tone="warn">
              <strong>Isolation Forest was trained and evaluated, and was not selected.</strong>{' '}
              It is recorded here for transparency and is <strong>not</strong> the detector
              producing the results above. Selection was made on the validation split, by
              measurement.
            </Note>
            <div className="grid gap-4 sm:grid-cols-2 mt-3">
              <div>
                <p className="label">Isolation Forest — held-out test</p>
                <Metrics metrics={anomalyMetrics?.isolation_forest_test} />
              </div>
              <div>
                <p className="label">Rarity baseline — held-out test</p>
                <Metrics metrics={anomalyMetrics?.rarity_baseline_test} />
              </div>
            </div>
            <p className="text-[12px] text-mist-300 mt-3">
              Selection rule: {anomalySelection.selection_rule}. Selected:{' '}
              <span className="mono">{anomalySelection.selected}</span>, on{' '}
              {anomalySelection.selected_on}.
            </p>
          </>
        )}
      </Panel>

      {/* 3. The classifier, with its status everywhere. */}
      <Panel title="Supervised risk classifier">
        <Note tone="warn">
          Status <strong>{summary?.classification_validation_status ?? 'MODEL_UNAVAILABLE'}</strong>.
          The label this model predicts is a project-authored rubric over synthetic
          servers. Predictions are <strong>not confirmed threats</strong> and the scores
          are <strong>not calibrated probabilities</strong> — no calibration was fitted or
          validated.
        </Note>
        {classification?.test && (
          <div className="mt-3">
            <p className="label">Held-out test</p>
            <div className="text-[12px] mt-2">
              <span className="mono">macro-F1 {Number(classification.test.macro_f1).toFixed(4)}</span>
              {' · '}
              <span className="mono">accuracy {Number(classification.test.accuracy).toFixed(4)}</span>
              {classification.baseline_most_frequent_test && (
                <span className="text-mist-300">
                  {' '}· baseline macro-F1{' '}
                  {Number(classification.baseline_most_frequent_test.macro_f1).toFixed(4)}
                </span>
              )}
            </div>
            {classificationSelection && (
              <p className="text-[11px] text-mist-400 mt-1">
                Model: <span className="mono">{classificationSelection.selected}</span>,
                selected on {classificationSelection.selected_on}.
              </p>
            )}
            <table className="w-full mt-3">
              <thead><tr>
                <th className="th">Class</th><th className="th">Precision</th>
                <th className="th">Recall</th><th className="th">F1</th><th className="th">Support</th>
              </tr></thead>
              <tbody>
                {Object.entries(classification.test.per_class ?? {}).map(([label, values]: [string, any]) => (
                  <tr key={label}>
                    <td className="td">{label}</td>
                    <td className="td mono">{values.precision === null ? 'undefined' : values.precision.toFixed(3)}</td>
                    <td className="td mono">{values.recall === null ? 'undefined' : values.recall.toFixed(3)}</td>
                    <td className="td mono">{values.f1 === null ? 'undefined' : values.f1.toFixed(3)}</td>
                    <td className="td">{classification.test.support?.[label] ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {evaluation?.dataset && (
          <p className="text-[11px] text-mist-400 mt-3">
            Measured on {(evaluation.dataset as any).generated_sessions} synthetic sessions
            from {(evaluation.dataset as any).independent_groups} independent groups. These
            are controlled-environment measurements, not real-world detection performance.
          </p>
        )}
      </Panel>

      <Panel title="Per-session results">
        {perSession.length === 0 ? (
          <Empty title="No per-session ML results" />
        ) : (
          <table className="w-full" data-testid="ml-session-table">
            <thead><tr>
              <th className="th">Session</th><th className="th">Anomaly status</th>
              <th className="th">Score</th><th className="th">Threshold</th>
              <th className="th">Classification</th><th className="th">Explanation</th>
            </tr></thead>
            <tbody>
              {perSession.map((item) => {
                const classified = classifications.find((c) => c.session_id === item.session_id)
                return (
                  <tr key={item.session_id}>
                    <td className="td">
                      <Link className="mono text-sev-info hover:underline" to={`/sessions/${item.session_id}`}>
                        {item.session_id}
                      </Link>
                    </td>
                    <td className="td text-[12px]">
                      <span className={
                        item.status === 'ANOMALOUS' ? 'text-sev-high'
                        : item.status === 'NOT_EVALUABLE' ? 'text-mist-300'
                        : 'text-sev-ok'}>
                        {item.status}
                      </span>
                    </td>
                    <td className="td mono text-[11px]">
                      <Value value={item.raw_score === null ? null : item.raw_score} kind="not-applicable" />
                    </td>
                    <td className="td mono text-[11px]">
                      <Value value={item.decision_threshold === null ? null : item.decision_threshold}
                             kind="not-applicable" />
                    </td>
                    <td className="td text-[11px]">
                      {classified ? (
                        <>
                          <div>{classified.predicted_class ?? '—'}</div>
                          <div className="text-mist-400">{classified.status}</div>
                        </>
                      ) : <span className="text-mist-400">—</span>}
                    </td>
                    <td className="td text-[11px] text-mist-300 max-w-md">{item.explanation}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </Panel>

      {perSession.some((item) => (item.feature_explanations ?? []).length > 0) && (
        <Panel title="Feature evidence">
          {perSession.filter((i) => (i.feature_explanations ?? []).length > 0).map((item) => (
            <div key={item.session_id} className="mb-4 last:mb-0">
              <p className="mono text-[11px] text-mist-300 mb-1">{item.session_id}</p>
              <table className="w-full">
                <thead><tr>
                  <th className="th">Feature</th><th className="th">Observed value</th>
                  <th className="th">Reference frequency</th><th className="th">Source observation</th>
                </tr></thead>
                <tbody>
                  {(item.feature_explanations ?? []).map((f: any) => (
                    <tr key={f.feature}>
                      <td className="td text-[12px]">{f.feature}</td>
                      <td className="td mono text-[11px]">{f.observed_value}</td>
                      <td className="td mono text-[11px]">
                        {f.reference_frequency === null ? 'not recorded' : `${(f.reference_frequency * 100).toFixed(1)}%`}
                      </td>
                      <td className="td text-[11px] text-mist-300">{f.provenance}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
          <Note>
            Frequencies describe the model's synthetic training population. They are
            correlational: no feature is claimed to cause a verdict.
          </Note>
        </Panel>
      )}
    </div>
  )
}
