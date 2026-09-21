import { NavLink, Navigate, Route, Routes, useParams } from 'react-router-dom'
import { Overview } from './pages/Overview'
import { Investigations } from './pages/Investigations'
import { InvestigationWorkspace } from './pages/InvestigationWorkspace'
import { Sessions } from './pages/Sessions'
import { SessionDetailPage } from './pages/SessionDetail'
import { Findings } from './pages/Findings'
import { Intelligence } from './pages/Intelligence'
import { Timeline } from './pages/Timeline'
import { MLAnalysis } from './pages/MLAnalysis'
import { Reports } from './pages/Reports'
import { SettingsPage } from './pages/Settings'
import { useInvestigationContext, InvestigationProvider } from './lib/context'
import { ErrorBoundary } from './components/ErrorBoundary'

const NAV = [
  { to: '/', label: 'Overview', end: true },
  { to: '/investigations', label: 'Investigations' },
  { to: '/sessions', label: 'Sessions' },
  { to: '/findings', label: 'Security findings' },
  { to: '/intelligence', label: 'Cryptographic intelligence' },
  { to: '/timeline', label: 'Evidence timeline' },
  { to: '/ml', label: 'ML analysis' },
  { to: '/reports', label: 'Reports' },
  { to: '/settings', label: 'Settings' },
]

function Shell({ children }: { children: React.ReactNode }) {
  const { selected } = useInvestigationContext()
  return (
    <div className="min-h-screen flex flex-col lg:flex-row">
      <nav className="lg:w-60 shrink-0 border-b lg:border-b-0 lg:border-r border-ink-600 bg-ink-900">
        <div className="px-4 py-4 border-b border-ink-600">
          <p className="font-semibold tracking-tight">SecureMailScope</p>
          <p className="text-[11px] text-mist-300 mt-0.5">
            Passive cryptographic posture assessment
          </p>
        </div>
        <ul className="p-2 flex lg:block gap-1 overflow-x-auto">
          {NAV.map((item) => (
            <li key={item.to}>
              <NavLink
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `block px-3 py-2 rounded-md text-[13px] whitespace-nowrap transition-colors ${
                    isActive ? 'bg-ink-700 text-mist-100 font-medium' : 'text-mist-300 hover:bg-ink-800'
                  }`
                }
              >
                {item.label}
              </NavLink>
            </li>
          ))}
        </ul>
        {selected && (
          <div className="px-4 py-3 border-t border-ink-600 text-[11px] text-mist-300">
            <div className="label mb-1">Selected investigation</div>
            <div className="mono text-mist-200">{selected}</div>
          </div>
        )}
      </nav>
      <main className="flex-1 min-w-0 p-4 lg:p-6 max-w-[1500px]">
        <ErrorBoundary>{children}</ErrorBoundary>
      </main>
    </div>
  )
}

function NotFound() {
  return (
    <div className="panel p-8 text-center">
      <p className="text-sm font-medium">This page does not exist.</p>
      <p className="text-[13px] text-mist-300 mt-1">
        The address may be mistyped, or the investigation may have been removed.
      </p>
      <NavLink className="btn mt-4 inline-flex" to="/">Back to overview</NavLink>
    </div>
  )
}

/** Direct navigation to an investigation selects it, then shows it. */
function InvestigationRoute() {
  const { investigationId } = useParams()
  if (!investigationId) return <Navigate to="/investigations" replace />
  return <InvestigationWorkspace investigationId={investigationId} />
}

export default function App() {
  return (
    <InvestigationProvider>
      <Shell>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/investigations" element={<Investigations />} />
          <Route path="/investigations/:investigationId" element={<InvestigationRoute />} />
          <Route path="/sessions" element={<Sessions />} />
          <Route path="/sessions/:sessionId" element={<SessionDetailPage />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/findings/:findingId" element={<Findings />} />
          <Route path="/intelligence" element={<Intelligence />} />
          <Route path="/timeline" element={<Timeline />} />
          <Route path="/ml" element={<MLAnalysis />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Shell>
    </InvestigationProvider>
  )
}
