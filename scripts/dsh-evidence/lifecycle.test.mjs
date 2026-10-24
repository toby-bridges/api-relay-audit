import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

test('synthetic: direct child can exit zero before an inherited output pipe closes', { timeout: 5000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dsh lifecycle '))
  const releasePath = join(directory, 'release')
  const child = spawn(process.execPath, [fileURLToPath(new URL('./lifecycle-fixture.mjs', import.meta.url)), 'parent', releasePath], {
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    windowsHide: true,
  })
  let output = ''
  let errors = ''
  let timedOut = false
  let exitCode
  let releaseRequested = Promise.resolve()
  const events = []
  child.on('message', message => {
    if (message?.kind === 'holder-ready') events.push('holder-ready')
  })
  child.stdout.on('data', chunk => {
    output += chunk
    if (output.includes('[synthetic] pipe owner released') && !events.includes('holder-released')) events.push('holder-released')
  })
  child.stderr.on('data', chunk => { errors += chunk })
  const watchdog = setTimeout(() => {
    timedOut = true
    child.kill('SIGKILL')
    // The holder also has its own bounded deadline if this controller fails.
    void writeFile(releasePath, 'release\n').catch(() => {})
  }, 2500)
  try {
    const closeCode = await new Promise((resolve, reject) => {
      child.once('error', reject)
      child.once('exit', code => {
        events.push('exit')
        exitCode = code
        // Release only after the event under test; no timing guess establishes ordering.
        releaseRequested = writeFile(releasePath, 'release\n')
        releaseRequested.catch(reject)
      })
      child.once('close', code => { events.push('close'); resolve(code) })
    })
    await releaseRequested
    assert.equal(timedOut, false, 'fixture exceeded its cleanup deadline')
    assert.equal(closeCode, 0)
    assert.equal(exitCode, 0)
    assert.equal(errors, '')
    assert.equal(events.includes('holder-ready'), true, 'holder must acknowledge startup before parent exits')
    assert.equal(events.includes('holder-released'), true, 'holder must survive parent exit and release the output pipe')
    assert.equal(events.indexOf('exit') < events.indexOf('holder-released'), true, 'release must follow observed parent exit')
    assert.equal(events.indexOf('holder-released') < events.indexOf('close'), true, 'pipe close must follow holder release')
    assert.match(output, /\[synthetic\] pipe owner active/)
  } finally {
    clearTimeout(watchdog)
    await writeFile(releasePath, 'release\n').catch(() => {})
    if (!events.includes('exit')) child.kill('SIGKILL')
    if (!events.includes('close')) {
      // Let the owned holder consume the cleanup marker before removing its directory.
      await new Promise(resolve => {
        const cleanupDeadline = setTimeout(resolve, 1600)
        child.once('close', () => { clearTimeout(cleanupDeadline); resolve() })
      })
    }
    // A failed fixture cannot own a pipe indefinitely: its own deadline is 1.5 s.
    child.stdout.destroy()
    child.stderr.destroy()
    if (child.connected) child.disconnect()
    await rm(directory, { recursive: true, force: true })
  }
})
