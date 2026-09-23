import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from './api'

export interface Async<T> {
  data: T | null
  error: string | null
  loading: boolean
  reload: () => void
}

/**
 * Load data, tracking the three states a request really has.
 *
 * Loading, failed and loaded are distinct, and a component must be able to
 * tell "no results" from "not loaded yet" — rendering an empty table during
 * the first fetch would claim there is nothing when nothing has been asked.
 */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): Async<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [nonce, setNonce] = useState(0)
  const alive = useRef(true)

  useEffect(() => {
    alive.current = true
    setLoading(true)
    setError(null)
    fn()
      .then((value) => { if (alive.current) { setData(value); setLoading(false) } })
      .catch((cause: unknown) => {
        if (!alive.current) return
        setError(cause instanceof ApiError ? cause.detail : 'the request could not be completed')
        setLoading(false)
      })
    return () => { alive.current = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce])

  const reload = useCallback(() => setNonce((value) => value + 1), [])
  return { data, error, loading, reload }
}

/**
 * Poll while a predicate holds.
 *
 * Used for analysis jobs. It stops as soon as the job reaches a terminal
 * state, so a finished investigation does not keep a timer running.
 */
export function usePolling(active: boolean, intervalMs: number, tick: () => void): void {
  useEffect(() => {
    if (!active) return
    const handle = window.setInterval(tick, intervalMs)
    return () => window.clearInterval(handle)
  }, [active, intervalMs, tick])
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return 'unknown'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function formatTime(value: string | null | undefined): string {
  if (!value) return 'unknown'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'unknown'
  return date.toISOString().replace('T', ' ').replace('Z', ' UTC')
}

/**
 * Just the time of day, to millisecond precision.
 *
 * Slicing `formatTime` by hand produced "00:00:00.000 UT" -- the unit clipped
 * mid-word -- because the offsets were counted against a different format.
 * Taking the field from the ISO string directly cannot drift that way.
 */
export function formatClock(value: string | null | undefined): string {
  if (!value) return 'unknown'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'unknown'
  return date.toISOString().slice(11, 23)
}

/** The calendar date, for a timeline that spans more than one day. */
export function formatDay(value: string | null | undefined): string {
  if (!value) return 'unknown date'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'unknown date'
  return date.toISOString().slice(0, 10)
}
