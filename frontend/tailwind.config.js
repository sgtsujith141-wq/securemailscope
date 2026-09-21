/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Calm dark navy. Security status colours are restrained and used
        // only where they carry meaning.
        ink: { 950: '#0b111c', 900: '#0f1521', 850: '#131a28', 800: '#161d2b', 700: '#1e2738', 600: '#263449' },
        mist: { 100: '#e6edf7', 200: '#c7d3e5', 300: '#93a3bb', 400: '#6b7c95' },
        sev: {
          critical: '#ff6b6b', high: '#ffa657', medium: '#ffd479',
          low: '#7fd1c1', info: '#8ab4f8', ok: '#6bcf9a', unknown: '#8b98ad',
        },
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica', 'Arial', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
