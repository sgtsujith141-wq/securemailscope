import { NavLink, Navigate, Route, Routes, useParams } from 'react-router-dom'

import { ErrorBoundary } from './components/ErrorBoundary'
import {
  IconAlert, IconChart, IconClock, IconFingerprint, IconFolder, IconGrid,
  IconReport, IconSessions, IconSettings,
} from './components/icons'
import { InvestigationProvider, useInvestigationContext } from './lib/context'
import { Findings } from './pages/Findings'
import { Intelligence } from './pages/Intelligence'
import { InvestigationWorkspace } from './pages/InvestigationWorkspace'
import { Investigations } from './pages/Investigations'
import { MLAnalysis } from './pages/MLAnalysis'
import { Overview } from './pages/Overview'
import { Reports } from './pages/Reports'
import { SessionDetailPage } from './pages/SessionDetail'
import { Sessions } from './pages/Sessions'
import { SettingsPage } from './pages/Settings'
import { Timeline } from './pages/Timeline'

type NavEntry = {
  to: string
  label: string
  icon: typeof IconFolder
  end?: boolean
}

/**
 * Navigation follows the investigation workflow, not the module structure.
 *
 * The first group is what you do: manage investigations, triage findings,
 * compare captures, produce a report. The second group is where you look
 * inside the investigation you have selected, and it only appears once there
 * is one -- an empty "Sessions" page tells a first-time user nothing.
 *
 * Every route the application has ever served is preserved, so existing links
 * and bookmarks keep working. Only the grouping and presentation changed.
 */
const PRIMARY: NavEntry[] = [
  { to: '/investigations', label: 'Investigations', icon: IconFolder },
  { to: '/findings', label: 'Findings', icon: IconAlert },
  { to: '/intelligence', label: 'Intelligence', icon: IconFingerprint },
  { to: '/reports', label: 'Reports', icon: IconReport },
]

const WITHIN: NavEntry[] = [
  { to: '/', label: 'Overview', icon: IconGrid, end: true },
  { to: '/sessions', label: 'Sessions', icon: IconSessions },
  { to: '/timeline', label: 'Evidence timeline', icon: IconClock },
  { to: '/ml', label: 'ML & analytics', icon: IconChart },
]

function NavLinks({ entries }: { entries: NavEntry[] }) {
  return (
    <ul className="space-y-0.5">
      {entries.map((entry) => (
        <li key={entry.to}>
          <NavLink
            to={entry.to}
            end={entry.end}
            className={({ isActive }) =>
              `nav-item ${isActive ? 'nav-item-active' : ''}`
            }
          >
            <entry.icon className="shrink-0 opacity-80" />
            <span className="truncate">{entry.label}</span>
          </NavLink>
        </li>
      ))}
    </ul>
  )
}

function Shell({ children }: { children: React.ReactNode }) {
  const { selected } = useInvestigationContext()
  return (
    <div className="min-h-screen flex flex-col lg:flex-row">
      <nav
        aria-label="Main"
        className="lg:w-[228px] shrink-0 border-b lg:border-b-0 lg:border-r
                   border-ink-800 bg-ink-950 lg:min-h-screen flex flex-col"
      >
        <div className="px-2.5 py-3 border-b border-ink-800">
          <div className="flex items-center gap-1.5">
            <span
              className="inline-flex h-6 w-6 items-center justify-center rounded
                         bg-accent/15 text-accent"
              aria-hidden="true"
            >
              <IconFingerprint size={15} />
            </span>
            <div className="min-w-0">
              <p className="font-semibold tracking-tight text-sm leading-tight">
                SecureMailScope
              </p>
              <p className="text-2xs text-mist-400 leading-tight mt-px">
                Cryptographic investigation
              </p>
            </div>
          </div>
        </div>

        <div className="p-1.5 flex-1 overflow-y-auto">
          <NavLinks entries={PRIMARY} />

          {selected ? (
            <>
              <span className="nav-group">Selected investigation</span>
              <NavLinks entries={WITHIN} />
              <p
                className="mono text-2xs text-mist-500 px-2.5 pt-1.5 leading-tight"
                data-testid="selected-investigation"
              >
                {selected}
              </p>
            </>
          ) : (
            <p className="hint px-2.5 pt-3">
              Select an investigation to inspect its sessions, timeline and
              analytics.
            </p>
          )}
        </div>

        <div className="p-1.5 border-t border-ink-800">
          <NavLinks
            entries={[{ to: '/settings', label: 'Settings', icon: IconSettings }]}
          />
        </div>
      </nav>

      <main className="flex-1 min-w-0 p-2.5 lg:p-4 max-w-[1560px]">
        <ErrorBoundary>{children}</ErrorBoundary>
      </main>
    </div>
  )
}

function NotFound() {
  return (
    <div className="surface p-6 text-center max-w-md mx-auto mt-8">
      <p className="text-base font-semibold">This page does not exist.</p>
      <p className="hint mt-1">
        The address may be mistyped, or the investigation may have been removed.
      </p>
      <NavLink className="btn mt-3 inline-flex" to="/investigations">
        Back to investigations
      </NavLink>
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
