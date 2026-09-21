import '@testing-library/jest-dom/vitest'

/**
 * jsdom does not implement ResizeObserver, which Recharts' ResponsiveContainer
 * uses to size itself. A minimal stub is enough: the tests assert on data and
 * labels, not on rendered chart geometry, which jsdom could not measure
 * anyway.
 */
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
globalThis.ResizeObserver = globalThis.ResizeObserver ?? (ResizeObserverStub as never)
