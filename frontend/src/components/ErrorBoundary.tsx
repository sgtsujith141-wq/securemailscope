/**
 * A last line of defence against a blank page.
 *
 * A forensic tool that renders nothing is worse than one that says it failed:
 * an analyst cannot tell an empty investigation from a crashed component, and
 * might conclude there is no evidence when there is. This boundary turns a
 * rendering error into a visible, reportable failure state that names the
 * component and offers a way back.
 */
import { Component } from 'react'
import type { ErrorInfo, ReactNode } from 'react'

interface Props { children: ReactNode }
interface State { error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Console only. Nothing is transmitted anywhere.
    console.error('SecureMailScope rendering error', error, info.componentStack)
  }

  render(): ReactNode {
    const { error } = this.state
    if (!error) return this.props.children
    return (
      <div className="panel border-sev-critical/40 bg-sev-critical/5 p-5" role="alert">
        <p className="text-sm font-medium text-sev-critical">This view failed to render.</p>
        <p className="text-[13px] text-mist-200 mt-1">
          The analysis data is intact — this is a fault in the interface, not in the
          evidence. The underlying results remain available through the API and the
          exported reports.
        </p>
        <p className="mono text-[11px] text-mist-400 mt-3">{error.message}</p>
        <button className="btn mt-4" onClick={() => this.setState({ error: null })}>
          Try again
        </button>
      </div>
    )
  }
}
