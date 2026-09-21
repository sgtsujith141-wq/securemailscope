module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended'],
  parser: '@typescript-eslint/parser',
  parserOptions: { ecmaVersion: 'latest', sourceType: 'module' },
  plugins: ['react-hooks', '@typescript-eslint'],
  ignorePatterns: ['dist', 'node_modules', '.eslintrc.cjs', 'playwright.config.ts', 'e2e'],
  rules: {
    'react-hooks/rules-of-hooks': 'error',
    'react-hooks/exhaustive-deps': 'warn',
    '@typescript-eslint/no-explicit-any': 'warn',
  },
  overrides: [
    {
      // These three pages render documents the Python engine produces:
      // per-session detail, the intelligence document and the ML evaluation
      // record. Their shapes are defined and validated by pydantic models on
      // the server, and mirroring several hundred fields in TypeScript would
      // create a second definition that could silently drift from the first.
      //
      // The rendering is written defensively -- optional chaining and explicit
      // fallbacks throughout -- so a missing field shows as UNKNOWN rather
      // than throwing. Everything a page depends on structurally is typed in
      // src/lib/api.ts; only the free-form document bodies are `any` here.
      files: ['src/pages/SessionDetail.tsx', 'src/pages/Intelligence.tsx', 'src/pages/MLAnalysis.tsx'],
      rules: { '@typescript-eslint/no-explicit-any': 'off' },
    },
  ],
}
