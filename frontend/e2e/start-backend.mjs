/**
 * Start the real backend for end-to-end tests.
 *
 * A throwaway data directory under the system temp dir, so an e2e run never
 * touches the developer's real investigations and never writes inside the
 * repository. The token is written where the frontend launcher can read it.
 */
import { spawn } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'

const dataDir = mkdtempSync(join(tmpdir(), 'sms-e2e-'))
const python = join(process.cwd(), '..', '.venv', 'bin', 'python')

const token = execFileSync(
  python,
  ['-m', 'securemailscope.backend.server', '--print-token', '--data-dir', dataDir],
  { cwd: join(process.cwd(), '..'), encoding: 'utf8' },
).trim()

writeFileSync(join(tmpdir(), 'sms-e2e-token'), token)
writeFileSync(join(tmpdir(), 'sms-e2e-datadir'), dataDir)

const child = spawn(
  python,
  ['-m', 'securemailscope.backend.server', '--data-dir', dataDir, '--port', '8799'],
  { cwd: join(process.cwd(), '..'), stdio: 'inherit' },
)

process.on('SIGTERM', () => child.kill('SIGTERM'))
process.on('SIGINT', () => child.kill('SIGINT'))
child.on('exit', (code) => process.exit(code ?? 0))
