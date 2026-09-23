/**
 * One icon family, drawn inline.
 *
 * Deliberately not a package: the project audits its dependency tree and
 * reports zero known vulnerabilities, and a dozen glyphs are not worth adding
 * a supply-chain surface for. Every icon here is a 24x24 stroked path in the
 * same weight, so they sit together consistently.
 */
import type { SVGProps } from 'react'

type IconProps = SVGProps<SVGSVGElement> & { size?: number }

function Svg({ size = 16, children, ...rest }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  )
}

export const IconFolder = (p: IconProps) => (
  <Svg {...p}><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /></Svg>
)
export const IconAlert = (p: IconProps) => (
  <Svg {...p}><path d="M12 9v4M12 17h.01M10.3 3.9 2.4 17.4A2 2 0 0 0 4.1 20.4h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" /></Svg>
)
export const IconFingerprint = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 10a2 2 0 0 1 2 2c0 2.5-.3 5-1 7" />
    <path d="M8.5 12a3.5 3.5 0 0 1 7 0c0 3-.4 6-1.2 8.5" />
    <path d="M5 12a7 7 0 0 1 14 0c0 1.6-.1 3.2-.4 4.8" />
    <path d="M5.5 18.5c.7-2 1-4.2 1-6.5a5.5 5.5 0 0 1 3-4.9" />
  </Svg>
)
export const IconReport = (p: IconProps) => (
  <Svg {...p}>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
    <path d="M14 3v5h5M9 13h6M9 17h4" />
  </Svg>
)
export const IconGrid = (p: IconProps) => (
  <Svg {...p}><path d="M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z" /></Svg>
)
export const IconSessions = (p: IconProps) => (
  <Svg {...p}><path d="M4 7h16M4 12h16M4 17h10" /><circle cx="19" cy="17" r="2" /></Svg>
)
export const IconClock = (p: IconProps) => (
  <Svg {...p}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></Svg>
)
export const IconChart = (p: IconProps) => (
  <Svg {...p}><path d="M4 19V5M4 19h16M8 16v-5M12 16V8M16 16v-3" /></Svg>
)
export const IconSettings = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 14.5a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2v.2a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-2.9-1.2l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.2-2.9H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.2-2.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3h.1a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 2.9 1.2l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0 1.2 2.9h.2a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z" />
  </Svg>
)
export const IconUpload = (p: IconProps) => (
  <Svg {...p}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M12 15V3M7 8l5-5 5 5" /></Svg>
)
export const IconShield = (p: IconProps) => (
  <Svg {...p}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" /></Svg>
)
export const IconSearch = (p: IconProps) => (
  <Svg {...p}><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></Svg>
)
export const IconArrowRight = (p: IconProps) => (
  <Svg {...p}><path d="M5 12h14M13 6l6 6-6 6" /></Svg>
)
export const IconCheck = (p: IconProps) => (
  <Svg {...p}><path d="m5 13 4 4L19 7" /></Svg>
)
export const IconPacket = (p: IconProps) => (
  <Svg {...p}><path d="m12 2 9 5v10l-9 5-9-5V7z" /><path d="m12 12 9-5M12 12v10M12 12 3 7" /></Svg>
)
export const IconLock = (p: IconProps) => (
  <Svg {...p}><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></Svg>
)
export const IconDownload = (p: IconProps) => (
  <Svg {...p}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M12 3v12M7 10l5 5 5-5" /></Svg>
)
