import { spawn } from 'node:child_process'
import { join } from 'node:path'

// An exit event and closed pipes are distinct facts. Never infer success from
// "Done", a materialized file, or a direct child's exit while pipes stay open.
export async function runProcess(command, args, { cwd, env, timeoutMs = 120_000, onEvent = () => {}, allowFailure = false, signal } = {}) {
  const start = performance.now()
  const child = spawn(command, args, {
    cwd, env, stdio: ['ignore', 'pipe', 'pipe'],
    detached: process.platform !== 'win32', windowsHide: true,
  })
  const event = (type, extra = {}) => onEvent({ type, pid: child.pid ?? null, elapsedMs: Math.round(performance.now() - start), ...extra })
  event('spawn')
  let stdout = ''
  let stderr = ''
  let exitCode = null
  let exitSignal = null
  let timedOut = false
  let aborted = false
  let spawnError
  let cleanupPromise
  const cleanup = () => {
    if (cleanupPromise) return cleanupPromise
    cleanupPromise = new Promise(resolve => {
      if (!child.pid) return resolve()
      if (process.platform === 'win32') {
        const killer = spawn(join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'taskkill.exe'), ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' })
        const killTimer = setTimeout(() => {
          killer.kill()
          event('cleanup-deadline', { treeCleanupConfirmed: false })
          resolve()
        }, 3000)
        killer.once('error', () => { clearTimeout(killTimer); resolve() })
        killer.once('close', code => {
          clearTimeout(killTimer)
          // taskkill cannot prove cleanup of orphaned descendants after the
          // original parent has exited. Keep the failure and this limitation.
          event('cleanup-tree', { code, treeCleanupConfirmed: false })
          resolve()
        })
      } else {
        try { process.kill(-child.pid, 'SIGKILL'); event('cleanup-tree', { signal: 'SIGKILL' }) } catch (error) { event('cleanup-tree', { code: error.code }) }
        resolve()
      }
    })
    return cleanupPromise
  }
  child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 2 * 1024 * 1024) { timedOut = true; void cleanup() } })
  child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 2 * 1024 * 1024) { timedOut = true; void cleanup() } })
  child.once('exit', (code, signal) => { exitCode = code; exitSignal = signal; event('exit', { code, signal }) })
  child.once('error', error => { spawnError = error; event('spawn-error', { code: error.code }) })
  const timer = setTimeout(() => { timedOut = true; event('deadline'); void cleanup() }, timeoutMs)
  const abort = () => { aborted = true; event('cancel-requested'); void cleanup() }
  signal?.addEventListener('abort', abort, { once: true })
  if (signal?.aborted) abort()
  let closeTimer
  await new Promise(resolve => {
    child.once('close', (code, signal) => { event('close', { code, signal }); resolve() })
    closeTimer = setTimeout(() => {
      timedOut = true
      event('pipes-did-not-close')
      child.stdout.destroy()
      child.stderr.destroy()
      void cleanup().then(resolve)
    }, timeoutMs + 10_000)
  })
  clearTimeout(timer)
  clearTimeout(closeTimer)
  signal?.removeEventListener('abort', abort)
  await cleanupPromise
  const result = { stdout, stderr, exitCode, exitSignal, timedOut, aborted, spawnError: spawnError?.code ?? null }
  if (!allowFailure && (timedOut || aborted || spawnError || exitCode !== 0)) {
    const error = new Error(`process failed: exit=${exitCode}, signal=${exitSignal}, deadline=${timedOut}, spawn=${spawnError?.code ?? 'ok'}\n${stderr.slice(-6000)}\n${stdout.slice(-6000)}`)
    error.result = result
    throw error
  }
  return result
}

async function processSnapshot() {
  if (process.platform === 'win32') {
    const powershell = join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    const result = await runProcess(powershell, ['-NoProfile', '-NonInteractive', '-Command', 'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId | ConvertTo-Json -Compress'], { timeoutMs: 5000 })
    const rows = JSON.parse(result.stdout)
    return (Array.isArray(rows) ? rows : [rows]).map(row => ({ pid: row.ProcessId, parent: row.ParentProcessId }))
  }
  const result = await runProcess('/bin/ps', ['-axo', 'pid=,ppid=,stat='], { timeoutMs: 5000 })
  return result.stdout.trim().split('\n').map(line => {
    const [pid, parent, state] = line.trim().split(/\s+/u)
    return { pid: Number(pid), parent: Number(parent), zombie: state.startsWith('Z') }
  })
}

export async function ownedProcessTree(rootPid) {
  const rows = await processSnapshot()
  const pids = new Set([rootPid])
  let changed = true
  while (changed) {
    changed = false
    for (const row of rows) if (pids.has(row.parent) && !pids.has(row.pid)) { pids.add(row.pid); changed = true }
  }
  return [...pids]
}

export async function waitForOwnedProcessesToExit(pids) {
  const deadline = performance.now() + 5000
  let survivors
  do {
    const alive = new Set((await processSnapshot()).filter(row => !row.zombie).map(row => row.pid))
    survivors = pids.filter(pid => alive.has(pid))
    if (survivors.length === 0) return []
    await new Promise(resolve => setTimeout(resolve, 100))
  } while (performance.now() < deadline)
  return survivors
}
