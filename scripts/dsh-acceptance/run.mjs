import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { appendFile, copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { delimiter, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { startFixture, manifestFromTarball, filesFromTarball, SYNTHETIC_KEY } from './fixture.mjs'
import { runProcess, ownedProcessTree, waitForOwnedProcessesToExit } from './process.mjs'
import { sanitizeEvidence } from './sanitize.mjs'

const DSH_VERSION = '0.1.7-rc.2'
const PNPM_VERSION = '11.7.0'
const REGISTRY = 'https://registry.npmjs.org/'
const options = new Map()
for (let index = 2; index < process.argv.length; index += 2) options.set(process.argv[index], process.argv[index + 1])
assert.ok(options.has('--tarball') || options.has('--package-dir'), 'provide --tarball or --package-dir')
const artifacts = resolve(options.get('--artifacts') || 'dsh-acceptance-artifacts')
await mkdir(artifacts, { recursive: true })
const candidateRecord = options.has('--package-dir')
  ? JSON.parse(await readFile(join(options.get('--package-dir'), 'npm-package-manifest.json'), 'utf8'))
  : undefined
const tarballPath = options.has('--tarball') ? resolve(options.get('--tarball'))
  : resolve(options.get('--package-dir'), candidateRecord.tarball.filename)
const tarball = await readFile(tarballPath)
const manifest = manifestFromTarball(tarball)
const root = await mkdtemp(join(tmpdir(), 'DSH acceptance '))
const hostDir = join(root, 'host runtime')
const home = join(root, 'isolated home')
const profileDir = join(home, 'profiles', 'acceptance')
const workspace = join(root, 'workspace with spaces')
const bin = join(root, 'tools without Git')
const store = join(root, 'pnpm store')
const tooling = join(root, 'package manager')
const scrub = value => sanitizeEvidence(value, { roots: [[root, '<acceptance-root>'], [process.cwd(), '<checkout>']], secrets: [SYNTHETIC_KEY] })
const summary = { schema: 1, platform: process.platform, node: process.version, dsh: DSH_VERSION, pnpm: PNPM_VERSION, candidate: { name: manifest.name, version: manifest.version }, stages: [], status: 'running', scope: 'official DSH CLI package lifecycle and headless Loader/commands; excludes browser UI and historical issue #101 reproduction' }
let writeQueue = Promise.resolve()
const event = record => {
  writeQueue = writeQueue.then(() => appendFile(join(artifacts, 'events.jsonl'), scrub(JSON.stringify({ timestamp: new Date().toISOString(), ...record })) + '\n'))
}
const baseEnv = {}
for (const key of ['SystemRoot', 'WINDIR', 'COMSPEC', 'PATHEXT', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE']) {
  if (process.env[key] !== undefined) baseEnv[key] = process.env[key]
}
Object.assign(baseEnv, {
  PATH: [dirname(process.execPath), process.env.PATH].join(delimiter), HOME: home, USERPROFILE: home, APPDATA: join(home, 'appdata'), LOCALAPPDATA: join(home, 'localappdata'),
  TMPDIR: join(root, 'tmp'), TEMP: join(root, 'tmp'), TMP: join(root, 'tmp'),
  XDG_CACHE_HOME: join(root, 'cache'), XDG_CONFIG_HOME: join(root, 'config'),
  DSH_HOME: home, DSH_TELEMETRY_DISABLED: '1', CI: '1', NO_COLOR: '1',
  npm_config_userconfig: join(root, 'user.npmrc'), npm_config_globalconfig: join(root, 'global.npmrc'),
  npm_config_cache: join(root, 'npm cache'), npm_config_store_dir: store,
})
for (const dir of [hostDir, home, profileDir, workspace, bin, store, tooling, baseEnv.TEMP]) await mkdir(dir, { recursive: true })
for (const filename of ['user.npmrc', 'global.npmrc']) await writeFile(join(root, filename), '')

async function stage(name, command, args, { env = baseEnv, cwd = workspace, timeoutMs = 120_000, allowFailure = false, signal, onEvent, expectedOutcome = 'exit 0 and output pipes closed' } = {}) {
  event({ phase: name, type: 'phase-start' })
  try {
    const result = await runProcess(command, args, { cwd, env, timeoutMs, allowFailure, signal, onEvent: value => { event({ phase: name, ...value }); onEvent?.(value) } })
    await writeFile(join(artifacts, `${name}.stdout.log`), scrub(result.stdout))
    await writeFile(join(artifacts, `${name}.stderr.log`), scrub(result.stderr))
    summary.stages.push({ name, expectedOutcome, exitCode: result.exitCode, signal: result.exitSignal, timedOut: result.timedOut, aborted: result.aborted, spawnError: result.spawnError })
    return result
  } catch (error) {
    if (error.result) {
      await writeFile(join(artifacts, `${name}.stdout.log`), scrub(error.result.stdout))
      await writeFile(join(artifacts, `${name}.stderr.log`), scrub(error.result.stderr))
    }
    summary.stages.push({ name, failed: true, error: scrub(error.message) })
    throw error
  }
}

function executableOnPath(name) {
  const suffixes = process.platform === 'win32' ? ['.exe', '.cmd', '.bat', ''] : ['']
  for (const dir of (process.env.PATH || '').split(delimiter)) for (const suffix of suffixes) {
    const candidate = join(dir, `${name}${suffix}`)
    if (existsSync(candidate)) return candidate
  }
  throw new Error(`${name} is not available during bootstrap`)
}

async function addExecutable(name, original) {
  const target = join(bin, `${name}${process.platform === 'win32' ? '.exe' : ''}`)
  if (process.platform === 'win32') await copyFile(original, target)
  else await symlink(await realpath(original), target)
}

let fixture
try {
  // Node's npm is used solely to obtain this pinned pnpm package (which has no
  // lifecycle hooks). DSH and candidate installation use the resulting pnpm.
  const npmCandidates = [
    options.get('--npm-cli'),
    join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ].filter(Boolean)
  const npmCli = npmCandidates.find(existsSync)
    || await realpath(executableOnPath('npm'))
  await stage('bootstrap-pnpm', process.execPath, [npmCli, 'install', '--prefix', tooling, '--save-exact', `pnpm@${PNPM_VERSION}`, '--no-audit', '--no-fund', `--registry=${REGISTRY}`], { timeoutMs: 180_000 })
  const pnpmCli = join(tooling, 'node_modules', 'pnpm', 'bin', 'pnpm.mjs')
  const hooks = {
    // dsh-win32-process pins 3.1.1; subprocess-local and the other
    // 0.1.7-rc.2 services resolve 3.3.3 or, since 2026-10-25, 3.3.4.
    // All three execute the same reviewed cnoke local-prebuild loader
    // (`node ./cnoke.cjs -P . -D src/koffi --prebuild --release`, no
    // downloader); pnpm fails the install when a resolved version is not
    // listed here, so each new koffi patch has to be added explicitly.
    'koffi@3.1.1': true,
    'koffi@3.3.3': true,
    'koffi@3.3.4': true,
    'node-pty@1.2.0-beta.15': true,
    'protobufjs@7.6.6': true,
    '@google/genai@1.52.0': true,
    [`@deepseek-ai/dsh-subprocess-local@${DSH_VERSION}`]: true,
  }
  const policy = `packages:\n  - .\nallowBuilds:\n${Object.entries(hooks).map(([name, allow]) => `  ${JSON.stringify(name)}: ${allow}`).join('\n')}\nstoreDir: ${JSON.stringify(store)}\n`
  await writeFile(join(hostDir, 'package.json'), JSON.stringify({ name: 'dsh-acceptance-host', private: true, type: 'module' }))
  await writeFile(join(hostDir, 'pnpm-workspace.yaml'), policy)
  const services = ['app-boot', 'commands', 'credentials', 'credentials-local', 'llm', 'settings', 'subprocess', 'subprocess-local', 'session']
  await stage('bootstrap-dsh', process.execPath, [pnpmCli, '--dir', hostDir, 'add', '--save-exact', '--reporter=append-only', `--registry=${REGISTRY}`, `@deepseek-ai/dsh@${DSH_VERSION}`, ...services.map(name => `@deepseek-ai/dsh-${name}@${DSH_VERSION}`)], { timeoutMs: 480_000 })
  const cli = join(hostDir, 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')
  const dependencies = Object.fromEntries(services.map(name => [`@deepseek-ai/dsh-${name}`, DSH_VERSION]))
  await writeFile(join(profileDir, 'package.json'), JSON.stringify({ name: 'dsh-acceptance-profile', private: true, type: 'module', dependencies, dsh: { profile: { bundles: [] } } }, null, 2))
  await writeFile(join(profileDir, 'pnpm-workspace.yaml'), policy)
  await writeFile(join(profileDir, 'cordis.patch.yml'), '[]\n')
  await stage('bootstrap-profile-services', process.execPath, [pnpmCli, '--dir', profileDir, 'install', '--reporter=append-only', `--registry=${REGISTRY}`], { timeoutMs: 240_000 })

  // Install-only PATH contains explicit Node, pnpm, Python and curl. Git is
  // genuinely unavailable rather than replaced with a successful fake binary.
  await addExecutable('node', process.execPath)
  await stage('bootstrap-host-version', process.execPath, [cli, '--version'])
  const python = executableOnPath(process.platform === 'win32' ? 'python' : 'python3')
  if (process.platform === 'win32') {
    // Python's DLLs live beside its executable; retain that directory. Assert
    // below that doing so has not accidentally restored Git.
    baseEnv.PATH = [bin, dirname(python), join(baseEnv.SystemRoot, 'System32')].join(delimiter)
    await writeFile(join(bin, 'pnpm.cmd'), `@echo off\r\n"${process.execPath}" "${pnpmCli}" %*\r\n`)
  } else {
    await addExecutable('python3', python)
    await addExecutable('python', python)
    await addExecutable('curl', executableOnPath('curl'))
    await writeFile(join(bin, 'pnpm'), `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(pnpmCli)} "$@"\n`, { mode: 0o755 })
    baseEnv.PATH = bin
  }
  baseEnv.PNPM_HOME = bin
  const git = await stage('assert-git-unavailable', 'git', ['--version'], { allowFailure: true, expectedOutcome: 'spawn fails with ENOENT' })
  assert.equal(git.spawnError, 'ENOENT', 'Git must be absent from the candidate install PATH')
  const metadataPackages = new Set()
  for (const directory of [hostDir, profileDir]) {
    for (const entry of await readdir(join(directory, 'node_modules', '.pnpm'), { withFileTypes: true })) {
      if (!entry.isDirectory()) continue
      const versionSeparator = entry.name.indexOf('@', entry.name.startsWith('@') ? 1 : 0)
      if (versionSeparator > 0) metadataPackages.add(entry.name.slice(0, versionSeparator).replace('+', '/'))
    }
  }
  fixture = await startFixture({ manifest, tarball, metadataPackages, onEvent: event })
  summary.candidate.integrity = fixture.integrity
  if (candidateRecord) assert.equal(fixture.integrity, candidateRecord.tarball.integrity)
  baseEnv.DSH_ACCEPTANCE_FIXTURE_KEY = fixture.syntheticKey
  await writeFile(join(profileDir, '.npmrc'), `registry=${fixture.baseUrl}/\n@deepseek-ai:registry=${REGISTRY}\n`)
  const spec = `${manifest.name}@${manifest.version}`
  const dsh = (name, args, extra) => stage(name, process.execPath, [cli, 'plugin', '--profile', 'acceptance', ...args], extra)
  const hostCheck = fileURLToPath(new URL('./host-check.mjs', import.meta.url))
  let connectivityChecks = 0
  const load = async (name, installed) => {
    await stage(name, process.execPath, [hostCheck, hostDir, profileDir, workspace, fixture.baseUrl, installed ? 'yes' : 'no'])
    if (installed) connectivityChecks += 1
  }
  const snapshotProfile = async () => Promise.all(['package.json', 'pnpm-lock.yaml'].map(filename => readFile(join(profileDir, filename), 'utf8')))
  const assertInstalled = async () => {
    const profileManifest = JSON.parse(await readFile(join(profileDir, 'package.json'), 'utf8'))
    assert.ok(profileManifest.dsh.profile.bundles.includes(manifest.name), 'CLI did not commit the bundle layer')
    const installed = JSON.parse(await readFile(join(profileDir, 'node_modules', manifest.name, 'package.json'), 'utf8'))
    assert.equal(installed.version, manifest.version)
    const lock = await readFile(join(profileDir, 'pnpm-lock.yaml'), 'utf8')
    assert.ok(lock.includes(fixture.integrity), 'candidate SRI is missing from the resolved lockfile')
    const expected = filesFromTarball(tarball)
    for (const filename of ['audit.py', 'dsh/index.js', 'dsh/cordis.patch.yml']) {
      assert.ok(expected.has(`package/${filename}`), `candidate is missing ${filename}`)
      const actual = await readFile(join(profileDir, 'node_modules', manifest.name, filename))
      assert.equal(createHash('sha256').update(actual).digest('hex'), createHash('sha256').update(expected.get(`package/${filename}`)).digest('hex'), `installed ${filename} differs from candidate bytes`)
    }
    event({ type: 'installed-file-integrity', files: ['audit.py', 'dsh/index.js', 'dsh/cordis.patch.yml'], equalToCandidate: true })
  }
  await dsh('candidate-install', ['add', '--save-exact', '--reporter=append-only', spec])
  await assertInstalled()
  await load('installed-command', true)
  const beforeRejected = await snapshotProfile()
  const rejected = await dsh('candidate-rejected-version', ['add', '--save-exact', '--reporter=append-only', `${manifest.name}@0.0.0-acceptance-does-not-exist`], { allowFailure: true, expectedOutcome: 'nonzero package-version error, no deadline; original manifest and lockfile preserved' })
  assert.equal(rejected.timedOut, false, 'failed-version check reached a deadline instead of a package error')
  assert.equal(rejected.spawnError, null)
  assert.notEqual(rejected.exitCode, 0, 'unpublished nonexistent version unexpectedly installed')
  assert.deepEqual(await snapshotProfile(), beforeRejected, 'failed install changed the original profile manifest/lockfile')
  await assertInstalled()
  await load('failed-version-preserved-command', true)
  await dsh('candidate-retry', ['add', '--save-exact', '--reporter=append-only', spec])
  await assertInstalled()
  await load('retried-command', true)
  const beforeCancel = await snapshotProfile()
  const pause = fixture.pauseNextMetadata()
  const cancellation = new AbortController()
  let cancelPid
  const cancelledOperation = dsh('candidate-cancelled', ['add', '--prefer-online', '--save-exact', '--reporter=append-only', `${manifest.name}@0.0.0-acceptance-cancelled`], {
    allowFailure: true, signal: cancellation.signal, expectedOutcome: 'explicit cancellation; observed process tree exited; original manifest and lockfile preserved',
    onEvent: record => { if (record.type === 'spawn') cancelPid = record.pid },
  })
  let pauseTimer
  try {
    await Promise.race([pause.reached, new Promise((_, reject) => { pauseTimer = setTimeout(() => reject(new Error('real DSH install did not reach the controlled metadata cancellation point')), 20_000) })])
    clearTimeout(pauseTimer)
    const ownedPids = await ownedProcessTree(cancelPid)
    assert.ok(ownedPids.length >= 2, 'cancellation must observe a real DSH child package-manager process')
    event({ phase: 'candidate-cancelled', type: 'owned-process-tree-before-cancel', pids: ownedPids })
    cancellation.abort()
    const cancelled = await cancelledOperation
    assert.equal(cancelled.aborted, true)
    assert.equal(cancelled.timedOut, false)
    assert.notEqual(cancelled.exitCode, 0)
    const survivors = await waitForOwnedProcessesToExit(ownedPids)
    event({ phase: 'candidate-cancelled', type: 'owned-process-tree-after-cancel', survivors, treeCleanupConfirmed: survivors.length === 0 })
    assert.deepEqual(survivors, [], 'cancelled DSH operation left an observed child process alive')
  } finally {
    clearTimeout(pauseTimer)
    cancellation.abort()
    pause.release()
    await cancelledOperation
  }
  assert.deepEqual(await snapshotProfile(), beforeCancel, 'cancellation changed the original profile manifest/lockfile')
  await assertInstalled()
  await load('cancelled-preserved-command', true)
  await dsh('candidate-after-cancel-retry', ['add', '--save-exact', '--reporter=append-only', spec])
  await assertInstalled()
  await load('cancelled-retried-command', true)
  // A fixed-version update is a real package-manager operation against the same
  // candidate. It proves idempotent update/reconciliation, not a future release.
  await dsh('candidate-update', ['update', '--reporter=append-only', spec])
  await assertInstalled()
  await load('updated-command', true)
  await dsh('candidate-uninstall', ['remove', '--reporter=append-only', manifest.name])
  const removed = JSON.parse(await readFile(join(profileDir, 'package.json'), 'utf8'))
  assert.equal(removed.dependencies?.[manifest.name], undefined)
  assert.ok(!removed.dsh.profile.bundles.includes(manifest.name))
  await load('uninstalled-command', false)
  assert.deepEqual(fixture.paths.sort(), Array.from({ length: connectivityChecks }, () => ['/v1/messages', '/v1/chat/completions']).flat().sort())
  await copyFile(join(workspace, 'connectivity report.md'), join(artifacts, 'connectivity-report.md'))
  summary.status = 'passed'
  summary.assertions = { gitAbsentDuringCandidateLifecycle: true, committedBundle: true, realLoader: true, commandHelp: true, syntheticCredentialConnectivity: true, rejectedVersionPreservedInstalledPackage: true, successfulRetry: true, cancelledInstallPreservedOriginalProfile: true, observedCancelledProcessTreeExited: true, retryAfterCancellation: true, fixedVersionUpdate: true, uninstalledCommandAbsent: true, sharedCandidateIntegrity: fixture.integrity }
} catch (error) {
  summary.status = 'failed'
  summary.error = scrub(error.stack || error.message)
  process.exitCode = 1
} finally {
  if (fixture) await fixture.close()
  // Only lockfiles and dependency metadata from this synthetic run are retained.
  for (const [directory, prefix] of [[hostDir, 'host'], [profileDir, 'profile']]) {
    for (const filename of ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml']) {
      const source = join(directory, filename)
      if (existsSync(source)) await writeFile(join(artifacts, `${prefix}-${filename}`), scrub(await readFile(source, 'utf8')))
    }
  }
  await writeQueue
  summary.temporaryRootRetained = summary.status !== 'passed' || options.get('--keep-temp') === 'yes'
  if (!summary.temporaryRootRetained) {
    try {
      await rm(root, { recursive: true, force: true, maxRetries: 2, retryDelay: 250 })
      summary.temporaryRootCleanup = 'removed after all successful phases closed'
    } catch (error) {
      summary.status = 'failed'
      summary.temporaryRootRetained = true
      summary.temporaryRootCleanup = scrub(error.message)
      process.exitCode = 1
    }
  }
  await writeFile(join(artifacts, 'summary.json'), JSON.stringify(summary, null, 2) + '\n')
  console.log(JSON.stringify({ status: summary.status, platform: summary.platform, candidate: summary.candidate, stages: summary.stages.map(({ name, failed, exitCode }) => ({ name, failed, exitCode })), ...(summary.temporaryRootRetained ? { retainedTemporaryRoot: root } : {}) }, null, 2))
}
