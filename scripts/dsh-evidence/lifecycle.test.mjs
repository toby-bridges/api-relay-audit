import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

test('synthetic: direct child can exit zero before an inherited output pipe closes', { timeout: 5000 }, async () => {
  const child = spawn(process.execPath, [fileURLToPath(new URL('./lifecycle-fixture.mjs', import.meta.url)), 'parent'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  })
  let holderPid
  let output = ''
  let errors = ''
  let timedOut = false
  let exitCode
  const events = []
  child.stdout.on('data', chunk => {
    output += chunk
    const pid = /holder-pid:(\d+)/.exec(output)
    if (pid) holderPid = Number(pid[1])
    if (output.includes('[synthetic] pipe owner released') && !events.includes('holder-released')) events.push('holder-released')
  })
  child.stderr.on('data', chunk => { errors += chunk })
  const cleanup = () => {
    child.kill('SIGKILL')
    if (holderPid) {
      try { process.kill(holderPid, 'SIGKILL') } catch (error) {
        if (error.code !== 'ESRCH') throw error
      }
    }
  }
  const watchdog = setTimeout(() => {
    timedOut = true
    cleanup()
    child.stdout.destroy()
    child.stderr.destroy()
  }, 2500)
  try {
    const closeCode = await new Promise((resolve, reject) => {
      child.once('error', reject)
      child.once('exit', code => { events.push('exit'); exitCode = code })
      child.once('close', code => { events.push('close'); resolve(code) })
    })
    assert.equal(timedOut, false, 'fixture exceeded its cleanup deadline')
    assert.equal(closeCode, 0)
    assert.equal(exitCode, 0)
    assert.equal(errors, '')
    assert.equal(events.indexOf('exit') < events.indexOf('holder-released'), true)
    assert.equal(events.indexOf('holder-released') < events.indexOf('close'), true)
    assert.match(output, /\[synthetic\] pipe owner active/)
  } finally {
    clearTimeout(watchdog)
    // The holder exits naturally after 350 ms; kill only if a failed run still owns it.
    if (!events.includes('close')) cleanup()
  }
})
