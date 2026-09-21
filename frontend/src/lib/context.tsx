/**
 * The selected investigation, kept in one place.
 *
 * Persisted to sessionStorage so a refresh does not lose the context the user
 * is working in, which §4 asks for. sessionStorage rather than localStorage:
 * the selection belongs to this browsing session, not to the machine.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

interface Ctx {
  selected: string | null
  select: (id: string | null) => void
}

const InvestigationCtx = createContext<Ctx>({ selected: null, select: () => {} })

const KEY = 'sms.selectedInvestigation'

export function InvestigationProvider({ children }: { children: ReactNode }) {
  const [selected, setSelected] = useState<string | null>(() => {
    try {
      return window.sessionStorage.getItem(KEY)
    } catch {
      // Private browsing or a blocked storage partition. The app works
      // without persistence; it just forgets the selection on refresh.
      return null
    }
  })

  const select = useCallback((id: string | null) => {
    setSelected(id)
  }, [])

  useEffect(() => {
    try {
      if (selected) window.sessionStorage.setItem(KEY, selected)
      else window.sessionStorage.removeItem(KEY)
    } catch {
      // See above.
    }
  }, [selected])

  const value = useMemo(() => ({ selected, select }), [selected, select])
  return <InvestigationCtx.Provider value={value}>{children}</InvestigationCtx.Provider>
}

export function useInvestigationContext(): Ctx {
  return useContext(InvestigationCtx)
}
