// Synthetic Node process/pipe mechanism. This does not run DSH or pnpm.
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

if (process.argv[2] === 'holder') {
  process.stdout.write('[synthetic] pipe owner active\n')
  setTimeout(() => process.stdout.write('[synthetic] pipe owner released\n'), 350)
} else if (process.argv[2] === 'parent') {
  const holder = spawn(process.execPath, [fileURLToPath(import.meta.url), 'holder'], {
    stdio: ['ignore', process.stdout, process.stderr],
    windowsHide: true,
  })
  holder.once('error', () => process.exit(2))
  holder.once('spawn', () => {
    process.stdout.write(`[synthetic] holder-pid:${holder.pid}\n`)
    holder.unref()
    process.exit(0)
  })
} else {
  throw new Error('Expected parent or holder fixture mode')
}
