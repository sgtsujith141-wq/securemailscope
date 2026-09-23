/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // A forensic workstation palette: very dark blue-black ground, a few
        // quiet elevations above it, and severity colour reserved for places
        // where severity actually means something.
        ink: {
          990: '#070b12', 950: '#0a0f18', 900: '#0d1420',
          850: '#111926', 800: '#15202f', 750: '#1a2636',
          700: '#213044', 650: '#293a52', 600: '#334560',
        },
        mist: {
          50: '#f4f7fc', 100: '#e3ebf6', 200: '#c3d0e3',
          300: '#94a5bf', 400: '#6c7f9c', 500: '#4f6076',
        },
        sev: {
          critical: '#f4726b', high: '#f59f5a', medium: '#e8c66a',
          low: '#6fc5bb', info: '#7cabf5', ok: '#5fc48a', unknown: '#7f8da3',
        },
        // One restrained accent. Used for the product mark, primary actions
        // and the selected navigation state -- nothing else.
        accent: { DEFAULT: '#4fd1c5', dim: '#2f8c85', wash: '#0f2b2c' },
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Inter',
               'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Cascadia Mono',
               'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': ['10px', { lineHeight: '14px', letterSpacing: '0.06em' }],
        xs: ['11.5px', { lineHeight: '16px' }],
        sm: ['13px', { lineHeight: '19px' }],
        base: ['14px', { lineHeight: '21px' }],
        lg: ['16px', { lineHeight: '23px' }],
        xl: ['19px', { lineHeight: '26px' }],
        '2xl': ['24px', { lineHeight: '31px' }],
        '3xl': ['31px', { lineHeight: '38px' }],
        '4xl': ['40px', { lineHeight: '46px' }],
      },
      spacing: {
        // An 8px rhythm, with 4px half-steps where density demands it.
        '0.5': '4px', '1': '8px', '1.5': '12px', '2': '16px', '2.5': '20px',
        '3': '24px', '4': '32px', '5': '40px', '6': '48px', '8': '64px',
      },
      borderRadius: { md: '6px', lg: '9px', xl: '13px' },
      transitionDuration: { DEFAULT: '180ms' },
    },
  },
  plugins: [],
}
