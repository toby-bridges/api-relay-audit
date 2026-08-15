import assert from 'node:assert/strict'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'

import {
  CHILD_KEY_ENV,
  PROCESS_GRACE_MS,
  apply,
  assertWorkspacePathContained,
  executeAuditCommand,
  inject,
  parseCommandInput,
  redactSecret,
  resolveTarget,
  resolveWorkspacePath,
  tokenizeCommandInput,
} from '../index.js'

const SECRET = 'sk-dsh-secret-never-log'

function collected(text = '') {
  return {
    readFrom: () => ({ text, nextOffset: Buffer.byteLength(text), lossy: false }),
  }
}

function harness(overrides = {}) {
  const workspace = mkdtempSync(join(tmpdir(), 'dsh-api-relay-audit-'))
  const calls = { credentials: [], executable: [], spawns: [] }
  const ctx = {
    llm: {
      listConfigurableProviders: () => [{
        provider: 'relay',
        displayName: 'Relay',
        settingsNs: 'llm-pi-ai',
        settingsPath: ['providers', 'relay'],
      }],
      resolveModelInfo: async (provider, model) => ({
        provider,
        id: model,
        name: 'Claude Opus',
      }),
    },
    settings: {
      get: () => ({
        providers: {
          relay: {
            baseURL: 'https://relay.example.com/v1',
            apiKeyEnv: 'RELAY_API_KEY',
          },
        },
      }),
    },
    credentials: {
      resolve: async ref => {
        calls.credentials.push(ref)
        return { value: SECRET, source: 'test' }
      },
    },
    subprocess: {
      resolveExecutable: async (command, env, signal) => {
        calls.executable.push({ command, env, signal })
        return `/usr/bin/${command}`
      },
      spawn: spec => {
        calls.spawns.push(spec)
        const outputIndex = spec.argv.indexOf('--output')
        const report = spec.argv[outputIndex + 1]
        mkdirSync(dirname(report), { recursive: true })
        writeFileSync(report, '# fixture report\n', 'utf8')
        return {
          done: Promise.resolve({ exitCode: 0, signal: null }),
          collected: { stdout: collected(), stderr: collected() },
        }
      },
    },
  }
  Object.assign(ctx, overrides.ctx)
  const agent = overrides.agent ?? {
    options: { provider: 'relay', model: 'claude-opus-4-6' },
    session: { header: { cwd: workspace } },
  }
  const controller = new AbortController()
  const invocation = {
    commandId: 'command/1',
    agent,
    rawInput: overrides.rawInput ?? '',
    signal: controller.signal,
  }
  return {
    workspace,
    calls,
    ctx,
    agent,
    controller,
    invocation,
    cleanup: () => rmSync(workspace, { recursive: true, force: true }),
  }
}

test('tokenizes quoted values without a shell', () => {
  assert.deepEqual(
    tokenizeCommandInput(' --url "https://relay.example/v1" --model \'claude opus\' a\\ b '),
    ['--url', 'https://relay.example/v1', '--model', 'claude opus', 'a b'],
  )
  assert.throws(() => tokenizeCommandInput("--model 'claude"), /unterminated quoted/u)
})

test('extracts adapter options and preserves audit options', () => {
  assert.deepEqual(parseCommandInput([
    '--url=https://relay.example/v1',
    '--model', 'claude-opus',
    '--credential-ref', 'RELAY_KEY',
    '--profile', 'web3',
    '--fast-context',
  ].join(' ')), {
    help: false,
    url: 'https://relay.example/v1',
    model: 'claude-opus',
    credentialRef: 'RELAY_KEY',
    output: undefined,
    transparentLog: undefined,
    passthrough: ['--profile', 'web3', '--fast-context'],
  })
  for (const rawInput of ['--key secret', '--key=secret', '--key-env OTHER']) {
    assert.throws(() => parseCommandInput(rawInput), /not accepted/u)
  }
})

test('rejects every abbreviation of adapter-controlled long options', () => {
  const controlledOptions = [
    '--url',
    '--model',
    '--credential-ref',
    '--output',
    '--transparent-log',
    '--key',
    '--key-env',
  ]
  const exactOptions = new Set(controlledOptions)
  const abbreviations = new Set()

  for (const option of controlledOptions) {
    for (let length = 3; length < option.length; length += 1) {
      const prefix = option.slice(0, length)
      if (!exactOptions.has(prefix)) abbreviations.add(prefix)
    }
  }

  for (const abbreviation of abbreviations) {
    assert.throws(() => parseCommandInput(abbreviation), /abbreviation/u)
    assert.throws(() => parseCommandInput(`${abbreviation}=value`), /abbreviation/u)
  }
})

test('resolves nested DSH provider settings and partial overrides', async () => {
  const testHarness = harness()
  try {
    const parsed = parseCommandInput('--url https://override.example/v1')
    const target = await resolveTarget(
      testHarness.ctx,
      testHarness.agent,
      parsed,
      testHarness.invocation.signal,
    )
    assert.deepEqual(target, {
      provider: 'relay',
      url: 'https://override.example/v1',
      model: 'claude-opus-4-6',
      credentialRef: 'RELAY_API_KEY',
    })
  } finally {
    testHarness.cleanup()
  }
})

test('fully explicit target overrides do not require provider settings', async () => {
  const testHarness = harness()
  testHarness.ctx.llm.listConfigurableProviders = () => {
    throw new Error('provider settings must not be read')
  }
  try {
    const target = await resolveTarget(
      testHarness.ctx,
      testHarness.agent,
      parseCommandInput([
        '--url https://explicit.example/v1',
        '--model claude-explicit',
        '--credential-ref EXPLICIT_KEY',
      ].join(' ')),
      testHarness.invocation.signal,
    )
    assert.deepEqual(target, {
      provider: 'relay',
      url: 'https://explicit.example/v1',
      model: 'claude-explicit',
      credentialRef: 'EXPLICIT_KEY',
    })
  } finally {
    testHarness.cleanup()
  }
})

test('accepts a Claude metadata name for an opaque model alias', async () => {
  const testHarness = harness({
    agent: {
      options: { provider: 'relay', model: 'production-alias' },
      session: { header: { cwd: '/workspace' } },
    },
  })
  try {
    const target = await resolveTarget(
      testHarness.ctx,
      testHarness.agent,
      parseCommandInput(''),
      testHarness.invocation.signal,
    )
    assert.equal(target.model, 'production-alias')
  } finally {
    testHarness.cleanup()
  }
})

test('rejects non-Claude routes before credential or subprocess use', async () => {
  const testHarness = harness()
  testHarness.ctx.llm.resolveModelInfo = async (provider, model) => ({
    provider,
    id: model,
    name: 'GPT-5',
  })
  testHarness.invocation.agent.options.model = 'gpt-5'
  try {
    const result = await executeAuditCommand(testHarness.invocation, testHarness.ctx)
    assert.equal(result.kind, 'error')
    assert.match(result.text, /only to routes that declare a Claude model/u)
    assert.deepEqual(testHarness.calls.credentials, [])
    assert.deepEqual(testHarness.calls.spawns, [])
  } finally {
    testHarness.cleanup()
  }
})

test('requires all unresolved target fields', async () => {
  const testHarness = harness({
    agent: { options: {}, session: { header: { cwd: '/workspace' } } },
    ctx: {
      llm: {
        listConfigurableProviders: () => [],
        resolveModelInfo: async () => { throw new Error('not called') },
      },
    },
  })
  try {
    const result = await executeAuditCommand(testHarness.invocation, testHarness.ctx)
    assert.equal(result.kind, 'error')
    assert.match(result.text, /--url, --model, --credential-ref/u)
  } finally {
    testHarness.cleanup()
  }
})

test('constrains output files to the current workspace', () => {
  const workspace = join(tmpdir(), 'workspace')
  assert.equal(
    resolveWorkspacePath(workspace, 'reports/report.md', '/unused'),
    join(workspace, 'reports', 'report.md'),
  )
  assert.throws(
    () => resolveWorkspacePath(workspace, '../outside.md', '/unused'),
    /inside the current workspace/u,
  )
  assert.throws(
    () => resolveWorkspacePath(workspace, workspace, '/unused'),
    /inside the current workspace/u,
  )
})

test('rejects workspace paths that escape through a symlink', async () => {
  const workspace = mkdtempSync(join(tmpdir(), 'dsh-path-workspace-'))
  const outside = mkdtempSync(join(tmpdir(), 'dsh-path-outside-'))
  try {
    symlinkSync(outside, join(workspace, 'escape'), process.platform === 'win32' ? 'junction' : 'dir')
    const candidate = resolveWorkspacePath(workspace, 'escape/report.md', '/unused')
    await assert.rejects(
      assertWorkspacePathContained(workspace, candidate),
      /escape the current workspace through a symlink/u,
    )
  } finally {
    rmSync(workspace, { recursive: true, force: true })
    rmSync(outside, { recursive: true, force: true })
  }
})

test('spawns audit.py without putting the secret in argv or command result', async () => {
  const testHarness = harness({ rawInput: '--connectivity --fast-context' })
  try {
    const result = await executeAuditCommand(
      testHarness.invocation,
      testHarness.ctx,
      { now: new Date('2026-08-14T10:00:00.123Z'), auditScript: '/package/audit.py' },
    )
    assert.equal(result.kind, 'success')
    assert.match(result.text, /^Report: /u)
    assert.equal(result.text.includes(SECRET), false)
    assert.equal(testHarness.calls.spawns.length, 1)
    const [spawn] = testHarness.calls.spawns
    assert.equal(spawn.argv.includes(SECRET), false)
    assert.deepEqual(spawn.argv.slice(0, 3), ['/usr/bin/python3', '/package/audit.py', '--key-env'])
    assert.equal(spawn.argv.includes('--connectivity'), true)
    assert.equal(spawn.argv.includes('--fast-context'), true)
    assert.equal(spawn.env[CHILD_KEY_ENV], SECRET)
    assert.equal(spawn.signal, testHarness.invocation.signal)
    assert.equal(spawn.graceMs, PROCESS_GRACE_MS)
    assert.equal(readFileSync(spawn.argv[spawn.argv.indexOf('--output') + 1], 'utf8'), '# fixture report\n')
  } finally {
    testHarness.cleanup()
  }
})

test('uses Windows py -3 only after python3 and python fail', async () => {
  const testHarness = harness()
  testHarness.ctx.subprocess.resolveExecutable = async command => {
    testHarness.calls.executable.push({ command })
    if (command === 'py') return 'C:\\Windows\\py.exe'
    throw new Error('missing')
  }
  try {
    const result = await executeAuditCommand(
      testHarness.invocation,
      testHarness.ctx,
      { platform: 'win32', auditScript: 'C:\\package\\audit.py' },
    )
    assert.equal(result.kind, 'success')
    assert.deepEqual(
      testHarness.calls.executable.map(call => call.command),
      ['python3', 'python', 'py'],
    )
    assert.deepEqual(testHarness.calls.spawns[0].argv.slice(0, 3), [
      'C:\\Windows\\py.exe', '-3', 'C:\\package\\audit.py',
    ])
  } finally {
    testHarness.cleanup()
  }
})

test('redacts credential values from subprocess diagnostics', async () => {
  const testHarness = harness()
  testHarness.ctx.subprocess.spawn = spec => {
    testHarness.calls.spawns.push(spec)
    return {
      done: Promise.resolve({ exitCode: 2, signal: null }),
      collected: {
        stdout: collected(`stdout ${SECRET}`),
        stderr: collected(`stderr ${SECRET}`),
      },
    }
  }
  try {
    const result = await executeAuditCommand(testHarness.invocation, testHarness.ctx)
    assert.equal(result.kind, 'error')
    assert.equal(result.text.includes(SECRET), false)
    assert.match(result.text, /\[REDACTED\]/u)
    assert.equal(redactSecret(`x ${SECRET}`, SECRET), 'x [REDACTED]')
  } finally {
    testHarness.cleanup()
  }
})

test('reports cancellation and passes the invocation signal to the process', async () => {
  const testHarness = harness()
  testHarness.ctx.subprocess.spawn = spec => {
    testHarness.calls.spawns.push(spec)
    testHarness.controller.abort(new Error('user canceled'))
    return {
      done: Promise.resolve({ exitCode: null, signal: 'SIGTERM' }),
      collected: { stdout: collected(), stderr: collected() },
    }
  }
  try {
    const result = await executeAuditCommand(testHarness.invocation, testHarness.ctx)
    assert.deepEqual(result, { kind: 'error', text: 'Audit canceled; no report was generated.' })
    assert.equal(testHarness.calls.spawns[0].signal, testHarness.controller.signal)
  } finally {
    testHarness.cleanup()
  }
})

test('requires an absolute DSH workspace and a stored credential', async () => {
  const noWorkspace = harness()
  noWorkspace.invocation.agent.session.header.cwd = undefined
  try {
    const result = await executeAuditCommand(noWorkspace.invocation, noWorkspace.ctx)
    assert.match(result.text, /no absolute workspace/u)
    assert.deepEqual(noWorkspace.calls.credentials, [])
  } finally {
    noWorkspace.cleanup()
  }

  const noCredential = harness()
  noCredential.ctx.credentials.resolve = async () => undefined
  try {
    const result = await executeAuditCommand(noCredential.invocation, noCredential.ctx)
    assert.match(result.text, /missing or empty/u)
    assert.deepEqual(noCredential.calls.spawns, [])
  } finally {
    noCredential.cleanup()
  }
})

test('registers a non-recording human command with only the planned services', () => {
  let registered
  apply({ commands: { register: definition => { registered = definition } } })
  assert.deepEqual(inject, ['commands', 'credentials', 'subprocess', 'llm', 'settings'])
  assert.equal(registered.name, 'relay-audit')
  assert.equal(registered.recordInput, false)
  assert.equal(typeof registered.handler, 'function')
})

test('package metadata declares a prebuilt GitHub bundle without install hooks', () => {
  const manifest = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'))
  assert.equal(manifest.name, 'dsh-api-relay-audit')
  assert.equal(manifest.private, true)
  assert.deepEqual(manifest.dsh, { bundle: { patch: './dsh/cordis.patch.yml' } })
  assert.equal(manifest.scripts.prepare, undefined)
  assert.equal(manifest.scripts.build, undefined)
  assert.equal(manifest.files.includes('audit.py'), true)
  for (const [peer, range] of Object.entries(manifest.peerDependencies)) {
    if (peer.startsWith('@deepseek-ai/dsh-')) assert.equal(range, '0.1.0-rc.6')
  }
})
