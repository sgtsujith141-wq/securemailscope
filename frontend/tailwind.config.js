/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // A deep blue-black ground with genuine separation between levels.
        // v1 put every surface within a few points of the background, which
        // read as flat however good the spacing was.
        ink: {
          990: '#05080e', 970: '#070b13', 950: '#0a1019',
          900: '#0e1622', 860: '#121c2b', 820: '#172333',
          780: '#1d2b3e', 740: '#24344a', 700: '#2c3e57',
          650: '#375070', 600: '#42608a',
        },
        mist: {
          50: '#f6f9fd', 100: '#e7effa', 200: '#c8d7ea',
          300: '#9aadc8', 400: '#7087a6', 500: '#52657f',
        },
        sev: {
          critical: '#ff6b63', high: '#ff9f4a', medium: '#f0c94b',
          low: '#5ccfc2', info: '#6ba6f7', ok: '#4ecd8a', unknown: '#7d8da3',
        },
        // Each primary area carries its own accent, used on the section rule,
        // the icon and the active nav state -- never as background fill.
        area: {
          investigate: '#22d3ee',
          findings: '#fb923c',
          intelligence: '#a78bfa',
          reports: '#60a5fa',
        },
        accent: { DEFAULT: '#22d3ee', dim: '#0e7490', deep: '#083344' },
        viz: {
          cyan: '#22d3ee', blue: '#60a5fa', violet: '#a78bfa',
          magenta: '#e879b9', amber: '#fbbf24', coral: '#fb7185',
          emerald: '#34d399', slate: '#64748b',
        },
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Inter',
               'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Cascadia Mono',
               'Consolas', 'monospace'],
      },
      fontSize: {
        '3xs': ['9.5px', { lineHeight: '13px', letterSpacing: '0.08em' }],
        '2xs': ['10.5px', { lineHeight: '14px', letterSpacing: '0.06em' }],
        xs: ['11.5px', { lineHeight: '16px' }],
        sm: ['13px', { lineHeight: '19px' }],
        base: ['14px', { lineHeight: '21px' }],
        lg: ['16.5px', { lineHeight: '24px' }],
        xl: ['20px', { lineHeight: '27px' }],
        '2xl': ['25px', { lineHeight: '32px' }],
        '3xl': ['33px', { lineHeight: '39px' }],
        '4xl': ['44px', { lineHeight: '48px', letterSpacing: '-0.02em' }],
        '5xl': ['58px', { lineHeight: '58px', letterSpacing: '-0.03em' }],
      },
      spacing: {
        '0.5': '4px', '1': '8px', '1.5': '12px', '2': '16px', '2.5': '20px',
        '3': '24px', '4': '32px', '5': '40px', '6': '48px', '8': '64px',
      },
      borderRadius: { md: '6px', lg: '10px', xl: '14px', '2xl': '18px' },
      transitionDuration: { DEFAULT: '180ms' },
      boxShadow: {
        // Depth comes from a dark outer shadow plus a 1px light top edge,
        // which is what makes a surface read as lifted rather than painted.
        panel: '0 1px 0 0 rgba(255,255,255,0.045) inset, 0 8px 24px -12px rgba(0,0,0,0.9)',
        raised: '0 1px 0 0 rgba(255,255,255,0.06) inset, 0 14px 34px -14px rgba(0,0,0,0.95)',
        hero: '0 1px 0 0 rgba(255,255,255,0.07) inset, 0 24px 60px -24px rgba(0,0,0,1)',
      },
      backgroundImage: {
        'panel-sheen': 'linear-gradient(180deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0) 42%)',
        'hero-wash': 'radial-gradient(120% 140% at 0% 0%, rgba(34,211,238,0.12) 0%, rgba(34,211,238,0) 55%)',
        // A faint technical grid, so large surfaces read as a workstation
        // rather than as a flat field of colour.
        'grid-fine':
          'linear-gradient(rgba(148,180,220,0.035) 1px, transparent 1px), linear-gradient(90deg, rgba(148,180,220,0.035) 1px, transparent 1px)',
      },
    },
  },
  plugins: [],
}
