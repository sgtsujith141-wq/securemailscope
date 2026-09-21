/**
 * Start the real backend for end-to-end tests, under a supervisor.
 *
 * A throwaway data directory under the system temp dir, so an e2e run never
 * touches the developer's real investigations and never writes inside the
 * repository. The token is written where the frontend launcher can read it.
 *
 * The supervisor exists so a test can restart the backend without Playwright
 * tearing the whole web server down: the acceptance walkthrough has to prove
 * that an investigation survives a restart, which means the process really has
 * to stop and start again on the same data directory. A test asks for that by
 * touching the file named in `sms-e2e-restart`, and the supervisor replaces
 * the child. The supervisor itself never exits until Playwright stops it.
 */
import { spawn, execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const dataDir = mkdtempSync(join(tmpdir(), 'sms-e2e-'))
const projectRoot = join(process.cwd(), '..')

/**
 * The interpreter that has SecureMailScope installed.
 *
 * A developer checkout keeps it in `.venv`; a CI runner installs into the
 * interpreter on PATH and has no `.venv` at all. Hardcoding the first made the
 * end-to-end job fail with a bare ENOENT from `spawnSync`, which says nothing
 * about the cause. `SECUREMAILSCOPE_PYTHON` overrides both.
 */
const python = (() => {
  if (process.env.SECUREMAILSCOPE_PYTHON) return process.env.SECUREMAILSCOPE_PYTHON
  const venv = join(projectRoot, '.venv', 'bin', 'python')
  return existsSync(venv) ? venv : 'python3'
})()
const restartFlag = join(tmpdir(), 'sms-e2e-restart')

const token = execFileSync(
  python,
  ['-m', 'securemailscope.backend.server', '--print-token', '--data-dir', dataDir],
  { cwd: projectRoot, encoding: 'utf8' },
).trim()

writeFileSync(join(tmpdir(), 'sms-e2e-token'), token)
writeFileSync(join(tmpdir(), 'sms-e2e-datadir'), dataDir)
rmSync(restartFlag, { force: true })

let child = null
let stopping = false
let restarting = false

function start() {
  child = spawn(
    python,
    ['-m', 'securemailscope.backend.server', '--data-dir', dataDir, '--port', '8799'],
    { cwd: projectRoot, stdio: 'inherit' },
  )
  child.on('exit', (code) => {
    if (stopping) {
      process.exit(code ?? 0)
      return
    }
    if (restarting) {
      // Expected: the interval below asked for this and will start a new one.
      return
    }
    // An unrequested exit is a real failure and must not be papered over.
    console.error(`backend exited unexpectedly with code ${code}`)
    process.exit(code ?? 1)
  })
}

start()

// Poll for a restart request. One second is well inside the test timeout and
// costs nothing while no test is asking.
setInterval(() => {
  if (restarting || stopping || !child || !existsSync(restartFlag)) return
  rmSync(restartFlag, { force: true })
  restarting = true
  console.log('restart requested: stopping the backend')
  const previous = child
  previous.once('exit', () => {
    console.log('restarting the backend on the same data directory')
    restarting = false
    start()
  })
  previous.kill('SIGTERM')
}, 1000)

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    stopping = true
    child?.kill(signal)
    setTimeout(() => process.exit(0), 2000)
  })
}
