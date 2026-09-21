/** Start Vite with the backend's token, so the proxy can authenticate. */
import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const token = readFileSync(join(tmpdir(), 'sms-e2e-token'), 'utf8').trim()
const child = spawn('npx', ['vite', '--port', '5173', '--strictPort'], {
  stdio: 'inherit',
  env: { ...process.env, SMS_API: 'http://127.0.0.1:8799', SMS_API_TOKEN: token },
})
process.on('SIGTERM', () => child.kill('SIGTERM'))
child.on('exit', (code) => process.exit(code ?? 0))
