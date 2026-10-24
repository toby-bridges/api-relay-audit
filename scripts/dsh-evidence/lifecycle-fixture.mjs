// Synthetic Node process/pipe mechanism. This does not run DSH or pnpm.
import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const releasePath = process.argv[3]
if (!releasePath || !process.send) throw new Error('Expected release path and an IPC startup channel')

if (process.argv[2] === 'holder') {
  let finished = false
  const finish = (code, message) => {
    if (finished) return
    finished = true
    clearInterval(releaseCheck)
    clearTimeout(deadline)
    process.stdout.write(message, () => {
      if (process.connected) process.disconnect()
      process.exitCode = code
    })
  }
  // Release is controlled by the observer's exit event, not an arbitrary delay.
  const releaseCheck = setInterval(() => {
    if (existsSync(releasePath)) finish(0, '[synthetic] pipe owner released\n')
  }, 10)
  const deadline = setTimeout(() => finish(3, '[synthetic] holder deadline exceeded\n'), 1500)
  process.stdout.write('[synthetic] pipe owner active\n', () => {
    process.send({ kind: 'holder-ready' }, error => {
      if (error) finish(2, '[synthetic] startup channel failed\n')
    })
  })
} else if (process.argv[2] === 'parent') {
  const holder = spawn(process.execPath, [fileURLToPath(import.meta.url), 'holder', releasePath], {
    // Windows libuv otherwise kills ordinary children when their parent's Job closes.
    detached: true,
    stdio: ['ignore', process.stdout, process.stderr, 'ipc'],
    windowsHide: true,
  })
  const deadline = setTimeout(() => {
    holder.kill('SIGKILL')
    process.exit(3)
  }, 1500)
  holder.once('error', () => { clearTimeout(deadline); process.exit(2) })
  // spawn acknowledges OS creation; this message acknowledges initialized fixture code.
  holder.once('message', message => {
    if (message?.kind !== 'holder-ready') return
    process.send({ kind: 'holder-ready' }, error => {
      clearTimeout(deadline)
      if (error) { holder.kill('SIGKILL'); process.exit(2) }
      if (holder.connected) holder.disconnect()
      holder.unref()
      if (process.connected) process.disconnect()
      process.exit(0)
    })
  })
} else {
  throw new Error('Expected parent or holder fixture mode')
}
