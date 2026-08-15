/**
 * DeepSeek Harness adapter for the generated standalone API Relay Audit.
 *
 * This module deliberately owns only distribution concerns: resolve one DSH
 * provider target, resolve one credential, launch the existing audit.py, and
 * return its report path. Detection semantics remain entirely in Python.
 */

import { access, realpath } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

export const name = 'api-relay-audit'
export const inject = ['commands', 'credentials', 'subprocess', 'llm', 'settings']

export const CHILD_KEY_ENV = 'API_RELAY_AUDIT_KEY'
export const OUTPUT_LIMIT_BYTES = 64 * 1024
export const PROCESS_GRACE_MS = 5_000

const CREDENTIAL_REF = /^[A-Za-z_][A-Za-z0-9_]*$/u
const OWNED_OPTIONS = new Set([
  '--url',
  '--model',
  '--credential-ref',
  '--output',
  '--transparent-log',
])
const FORBIDDEN_OPTIONS = new Set(['--key', '--key-env'])
const CONTROLLED_OPTIONS = new Set([...OWNED_OPTIONS, ...FORBIDDEN_OPTIONS])
const AUDIT_SCRIPT = fileURLToPath(new URL('../audit.py', import.meta.url))

const USAGE = `Usage: /relay-audit [audit options]

Defaults to the current DSH provider/model and runs the full existing audit.
Use --connectivity for the lower-cost connectivity check.

Target overrides:
  --url <URL>
  --model <claude-model>
  --credential-ref <DSH_CREDENTIAL_REF>

Output paths:
  --output <workspace path>
  --transparent-log <workspace path>

Raw --key and caller-supplied --key-env are not accepted.`

function optionName(token) {
  const equals = token.indexOf('=')
  return equals === -1 ? token : token.slice(0, equals)
}

function optionInlineValue(token) {
  const equals = token.indexOf('=')
  return equals === -1 ? undefined : token.slice(equals + 1)
}

function abbreviatedControlledOptions(name) {
  if (!name.startsWith('--')) return []
  return [...CONTROLLED_OPTIONS].filter(option => option !== name && option.startsWith(name))
}

/** Split human-command input without invoking a shell. */
export function tokenizeCommandInput(rawInput) {
  const tokens = []
  let token = ''
  let quote
  let started = false

  for (let index = 0; index < rawInput.length; index += 1) {
    const character = rawInput[index]
    if (quote !== undefined) {
      if (character === quote) {
        quote = undefined
        started = true
        continue
      }
      if (character === '\\' && quote === '"') {
        const next = rawInput[index + 1]
        if (next === '"' || next === '\\' || /\s/u.test(next ?? '')) {
          token += next
          index += 1
          started = true
          continue
        }
      }
      token += character
      started = true
      continue
    }

    if (character === '"' || character === "'") {
      quote = character
      started = true
      continue
    }
    if (/\s/u.test(character)) {
      if (started) {
        tokens.push(token)
        token = ''
        started = false
      }
      continue
    }
    if (character === '\\') {
      const next = rawInput[index + 1]
      if (next === '"' || next === "'" || next === '\\' || /\s/u.test(next ?? '')) {
        token += next
        index += 1
        started = true
        continue
      }
    }
    token += character
    started = true
  }

  if (quote !== undefined) throw new Error('unterminated quoted command argument')
  if (started) tokens.push(token)
  return tokens
}

/** Parse DSH-owned options and leave existing audit.py options untouched. */
export function parseCommandInput(rawInput) {
  const tokens = tokenizeCommandInput(rawInput)
  const values = new Map()
  const passthrough = []
  let help = false

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]
    const name = optionName(token)
    if (FORBIDDEN_OPTIONS.has(name)) {
      throw new Error(`${name} is not accepted; store the key in DSH Credentials`)
    }
    const abbreviations = abbreviatedControlledOptions(name)
    if (abbreviations.length > 0) {
      throw new Error(
        `${name} is an abbreviation of adapter-controlled option ${abbreviations.join(' or ')}`,
      )
    }
    if (token === '--help' || token === '-h') {
      help = true
      continue
    }
    if (!OWNED_OPTIONS.has(name)) {
      passthrough.push(token)
      continue
    }
    if (values.has(name)) throw new Error(`${name} may be specified only once`)

    let value = optionInlineValue(token)
    if (value === undefined) {
      index += 1
      value = tokens[index]
    }
    if (value === undefined || value.length === 0 || value.startsWith('--')) {
      throw new Error(`${name} requires a value`)
    }
    values.set(name, value)
  }

  return Object.freeze({
    help,
    url: values.get('--url'),
    model: values.get('--model'),
    credentialRef: values.get('--credential-ref'),
    output: values.get('--output'),
    transparentLog: values.get('--transparent-log'),
    passthrough: Object.freeze(passthrough),
  })
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function atPath(value, path) {
  let current = value
  for (const segment of path) {
    if (!isRecord(current)) return undefined
    current = current[segment]
  }
  return current
}

function configuredProviderProfile(ctx, provider) {
  if (provider === undefined) return undefined
  const directory = ctx.llm.listConfigurableProviders()
  const entry = directory.find(candidate => candidate.provider === provider)
  if (entry === undefined) return undefined
  const section = ctx.settings.get(entry.settingsNs)
  const profile = atPath(section, entry.settingsPath)
  return isRecord(profile) ? profile : undefined
}

function validateUrl(value) {
  let url
  try {
    url = new URL(value)
  } catch {
    throw new Error('relay URL must be an absolute http(s) URL')
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('relay URL must use http or https')
  }
  if (url.username.length > 0 || url.password.length > 0) {
    throw new Error('relay URL must not contain embedded credentials')
  }
  return value
}

function assertCredentialRef(value) {
  if (!CREDENTIAL_REF.test(value)) {
    throw new Error('credential reference must be a POSIX environment-variable name')
  }
  return value
}

async function modelLooksLikeClaude(ctx, provider, model, signal) {
  const labels = [model]
  if (provider !== undefined) {
    try {
      const info = await ctx.llm.resolveModelInfo(provider, model, signal)
      labels.push(info.name, info.description ?? '')
    } catch (error) {
      if (signal.aborted) throw error
      // A custom relay alias may be absent from an advisory catalog. The id
      // remains sufficient when it explicitly declares the Claude family.
    }
  }
  return labels.some(label => /claude/iu.test(label))
}

/** Resolve the current DSH route, with explicit command values taking priority. */
export async function resolveTarget(ctx, agent, parsed, signal) {
  const provider = agent.options?.provider
  const profile = parsed.url === undefined || parsed.credentialRef === undefined
    ? configuredProviderProfile(ctx, provider)
    : undefined
  const url = parsed.url ?? (typeof profile?.baseURL === 'string' ? profile.baseURL : undefined)
  const model = parsed.model ?? agent.options?.model
  const credentialRef = parsed.credentialRef
    ?? (typeof profile?.apiKeyEnv === 'string' ? profile.apiKeyEnv : undefined)

  const missing = []
  if (url === undefined) missing.push('--url')
  if (model === undefined) missing.push('--model')
  if (credentialRef === undefined) missing.push('--credential-ref')
  if (missing.length > 0) {
    throw new Error(
      `could not resolve ${missing.join(', ')} from the current DSH provider; provide the missing override(s)`,
    )
  }

  const resolvedUrl = validateUrl(url)
  const resolvedCredentialRef = assertCredentialRef(credentialRef)
  if (!await modelLooksLikeClaude(ctx, provider, model, signal)) {
    throw new Error(
      'the current audit baseline applies only to routes that declare a Claude model; no report was generated',
    )
  }
  return Object.freeze({
    provider,
    url: resolvedUrl,
    model,
    credentialRef: resolvedCredentialRef,
  })
}

function isOutsideWorkspace(workspace, candidate) {
  const pathFromWorkspace = relative(workspace, candidate)
  return pathFromWorkspace === '..'
    || pathFromWorkspace.startsWith(`..${sep}`)
    || isAbsolute(pathFromWorkspace)
}

/** Resolve an optional user path and require that it remains in the workspace. */
export function resolveWorkspacePath(workspace, input, fallback) {
  const candidate = input === undefined ? fallback : resolve(workspace, input)
  if (candidate === workspace || isOutsideWorkspace(workspace, candidate)) {
    throw new Error('output paths must resolve to a file inside the current workspace')
  }
  return candidate
}

async function nearestExistingRealPath(candidate) {
  let current = candidate
  for (;;) {
    try {
      return await realpath(current)
    } catch (error) {
      if (error?.code !== 'ENOENT' && error?.code !== 'ENOTDIR') throw error
      const parent = dirname(current)
      if (parent === current) throw error
      current = parent
    }
  }
}

/** Reject existing symlinks that would make an output escape the workspace. */
export async function assertWorkspacePathContained(workspace, candidate) {
  const canonicalWorkspace = await realpath(workspace)
  const canonicalAncestor = await nearestExistingRealPath(candidate)
  if (canonicalAncestor !== canonicalWorkspace
    && isOutsideWorkspace(canonicalWorkspace, canonicalAncestor)) {
    throw new Error('output paths must not escape the current workspace through a symlink')
  }
  return candidate
}

function safeCommandId(commandId) {
  const sanitized = String(commandId).replace(/[^A-Za-z0-9_-]/gu, '_').slice(0, 64)
  return sanitized.length > 0 ? sanitized : 'command'
}

function defaultReportPath(workspace, commandId, now) {
  const timestamp = now.toISOString().replace(/[-:.]/gu, '')
  return resolve(
    workspace,
    '.api-relay-audit',
    'reports',
    `api-relay-audit-${timestamp}-${safeCommandId(commandId)}.md`,
  )
}

async function resolvePython(ctx, signal, platform = process.platform) {
  const candidates = [
    { command: 'python3', prefix: [] },
    { command: 'python', prefix: [] },
    ...(platform === 'win32' ? [{ command: 'py', prefix: ['-3'] }] : []),
  ]
  for (const candidate of candidates) {
    try {
      const executable = await ctx.subprocess.resolveExecutable(
        candidate.command,
        undefined,
        signal,
      )
      return { executable, prefix: candidate.prefix }
    } catch (error) {
      if (signal.aborted) throw error
    }
  }
  throw new Error('Python 3 was not found (tried python3, python, and Windows py -3)')
}

function collectedText(handle, stream) {
  const reader = handle.collected[stream]
  return reader === undefined ? '' : reader.readFrom(0).text
}

export function redactSecret(text, secret) {
  if (secret.length === 0) return text
  return text.split(secret).join('[REDACTED]')
}

function diagnosticTail(handle, secret) {
  const combined = [collectedText(handle, 'stdout'), collectedText(handle, 'stderr')]
    .filter(Boolean)
    .join('\n')
  return redactSecret(combined, secret).slice(-4_096).trim()
}

async function fileExists(path) {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

/** Execute one human-command invocation against the existing audit.py CLI. */
export async function executeAuditCommand(invocation, ctx, options = {}) {
  let secret = ''
  try {
    const parsed = parseCommandInput(invocation.rawInput)
    if (parsed.help) return { kind: 'success', text: USAGE }

    const workspace = invocation.agent.session?.header?.cwd
    if (typeof workspace !== 'string' || workspace.length === 0 || !isAbsolute(workspace)) {
      throw new Error('the receiving DSH session has no absolute workspace')
    }

    const target = await resolveTarget(ctx, invocation.agent, parsed, invocation.signal)
    const now = options.now ?? new Date()
    const fallbackReport = defaultReportPath(workspace, invocation.commandId, now)
    const reportPath = resolveWorkspacePath(workspace, parsed.output, fallbackReport)
    const transparentLogPath = parsed.transparentLog === undefined
      ? undefined
      : resolveWorkspacePath(workspace, parsed.transparentLog, parsed.transparentLog)
    await assertWorkspacePathContained(workspace, reportPath)
    if (transparentLogPath !== undefined) {
      await assertWorkspacePathContained(workspace, transparentLogPath)
    }

    const credential = await ctx.credentials.resolve(target.credentialRef)
    if (credential === undefined || typeof credential.value !== 'string' || credential.value.length === 0) {
      throw new Error(`DSH Credential ${target.credentialRef} is missing or empty`)
    }
    secret = credential.value

    const python = await resolvePython(
      ctx,
      invocation.signal,
      options.platform ?? process.platform,
    )

    const argv = [
      python.executable,
      ...python.prefix,
      options.auditScript ?? AUDIT_SCRIPT,
      '--key-env',
      CHILD_KEY_ENV,
      '--url',
      target.url,
      '--model',
      target.model,
      '--output',
      reportPath,
      ...parsed.transparentLog === undefined
        ? []
        : ['--transparent-log', transparentLogPath],
      ...parsed.passthrough,
    ]

    const handle = ctx.subprocess.spawn({
      argv,
      cwd: workspace,
      stdio: {
        stdin: 'ignore',
        stdout: { maxBytes: OUTPUT_LIMIT_BYTES },
        stderr: { maxBytes: OUTPUT_LIMIT_BYTES },
      },
      graceMs: PROCESS_GRACE_MS,
      signal: invocation.signal,
      env: { [CHILD_KEY_ENV]: secret },
    })
    const outcome = await handle.done
    const reportExists = await fileExists(reportPath)

    if (invocation.signal.aborted) {
      return {
        kind: 'error',
        text: reportExists
          ? `Audit canceled. Partial report: ${reportPath}`
          : 'Audit canceled; no report was generated.',
      }
    }
    if (outcome.exitCode !== 0) {
      const diagnostic = diagnosticTail(handle, secret)
      const report = reportExists ? `\nReport: ${reportPath}` : ''
      const detail = diagnostic.length > 0 ? `\n${diagnostic}` : ''
      return {
        kind: 'error',
        text: `Audit process exited with code ${String(outcome.exitCode)}.${report}${detail}`,
      }
    }
    if (!reportExists) {
      throw new Error('audit.py exited successfully but did not create its report')
    }
    return { kind: 'success', text: `Report: ${reportPath}` }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return { kind: 'error', text: redactSecret(message, secret) }
  }
}

/** Register the command globally for every DSH command-compatible surface. */
export function apply(ctx) {
  ctx.commands.register({
    name: 'relay-audit',
    description: 'run the local API relay security audit',
    input: { hint: '[audit.py options]' },
    recordInput: false,
    handler: invocation => executeAuditCommand(invocation, ctx),
  })
}
