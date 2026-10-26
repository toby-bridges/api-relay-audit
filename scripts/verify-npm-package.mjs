#!/usr/bin/env node
/** Build and inspect the exact prebuilt npm candidate, without publishing it. */
import { createHash } from 'node:crypto'
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, delimiter, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { gunzipSync } from 'node:zlib'

export const PACKAGE_FILES = Object.freeze([
  'LICENSE', 'NOTICE', 'README.md', 'VERSION', 'audit.py',
  'dsh/cordis.patch.yml', 'dsh/index.js', 'package.json',
])
const SOURCE_FILES = PACKAGE_FILES.filter(name => name !== 'package.json').sort()
const HOOKS = ['prepare', 'build', 'prepack', 'postpack', 'preinstall', 'install', 'postinstall', 'prepublish', 'prepublishOnly', 'publish', 'postpublish']
const SOURCE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const MAX_ARCHIVE_BYTES = 16 * 1024 * 1024

export class PackageVerificationError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`)
    this.name = 'PackageVerificationError'
    this.code = code
  }
}

function requireCheck(condition, code, message) {
  if (!condition) throw new PackageVerificationError(code, message)
}

function digest(algorithm, bytes, encoding = 'hex') {
  return createHash(algorithm).update(bytes).digest(encoding)
}

function isWithin(parent, child) {
  const path = relative(parent, child)
  return path === '' || (!isAbsolute(path) && path !== '..' && !path.startsWith(`..${sep}`))
}

/** Read only regular, whitelisted package files; never extract archive paths. */
export function readPackageArchive(bytes) {
  let archive
  try {
    archive = gunzipSync(bytes, { maxOutputLength: MAX_ARCHIVE_BYTES })
  } catch {
    throw new PackageVerificationError('ARCHIVE_INVALID', 'candidate is not a bounded, valid gzip archive')
  }
  const files = new Map()
  let offset = 0
  let terminated = false
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512)
    if (header.every(byte => byte === 0)) {
      requireCheck(archive.length >= offset + 1024 && archive.subarray(offset).every(byte => byte === 0), 'ARCHIVE_INVALID', 'tar archive has an invalid end marker')
      terminated = true
      break
    }
    const field = (start, length) => header.subarray(start, start + length).toString('utf8').replace(/\0.*$/su, '')
    const number = (start, length) => {
      const value = field(start, length).trim()
      requireCheck(/^[0-7]+$/u.test(value), 'ARCHIVE_INVALID', 'tar numeric field must be octal')
      return Number.parseInt(value, 8)
    }
    const checksum = [...header].reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0)
    requireCheck(checksum === number(148, 8), 'ARCHIVE_INVALID', 'tar header checksum does not match')
    const name = field(0, 100)
    const prefix = field(345, 155)
    const archivePath = prefix ? `${prefix}/${name}` : name
    requireCheck(archivePath.startsWith('package/'), 'FILE_SET_MISMATCH', 'archive entry is outside package/')
    const path = archivePath.slice('package/'.length)
    requireCheck(PACKAGE_FILES.includes(path), 'FILE_SET_MISMATCH', `unexpected archive entry: ${JSON.stringify(path)}`)
    requireCheck(header[156] === 0 || header[156] === 48, 'ARCHIVE_INVALID', `only regular files are allowed: ${path}`)
    requireCheck(field(157, 100) === '', 'ARCHIVE_INVALID', `link target is not allowed: ${path}`)
    requireCheck(!files.has(path), 'ARCHIVE_INVALID', `duplicate archive entry: ${path}`)
    const size = number(124, 12)
    const start = offset + 512
    requireCheck(size <= MAX_ARCHIVE_BYTES && start + size <= archive.length, 'ARCHIVE_INVALID', 'tar file size exceeds archive bounds')
    files.set(path, archive.subarray(start, start + size))
    offset = start + Math.ceil(size / 512) * 512
  }
  requireCheck(terminated, 'ARCHIVE_INVALID', 'tar end marker is missing')
  requireCheck(PACKAGE_FILES.every(path => files.has(path)) && files.size === PACKAGE_FILES.length, 'FILE_SET_MISMATCH', 'candidate must contain exactly the eight approved runtime and notice files')
  return files
}

function validateMetadata(manifest, version) {
  const expectedFields = ['name', 'version', 'description', 'type', 'main', 'exports', 'files', 'scripts', 'publishConfig', 'engines', 'peerDependencies', 'repository', 'homepage', 'license', 'dsh']
  requireCheck(manifest !== null && typeof manifest === 'object' && !Array.isArray(manifest), 'METADATA_INVALID', 'package metadata must be a JSON object')
  requireCheck(Object.keys(manifest).length === expectedFields.length && Object.keys(manifest).every(key => expectedFields.includes(key)), 'METADATA_INVALID', 'package metadata contains missing or unexpected fields')
  requireCheck(manifest.name === 'dsh-api-relay-audit' && manifest.version === version && /^\d+\.\d+\.\d+$/u.test(version), 'METADATA_INVALID', 'package name/version must match VERSION')
  requireCheck(manifest.type === 'module' && manifest.main === './dsh/index.js', 'METADATA_INVALID', 'ESM adapter entry point is incorrect')
  requireCheck(JSON.stringify(manifest.exports) === JSON.stringify({ '.': './dsh/index.js', './audit.py': './audit.py', './cordis.patch.yml': './dsh/cordis.patch.yml' }), 'METADATA_INVALID', 'package exports must point to the shipped runtime files')
  requireCheck(manifest.publishConfig?.access === 'public' && manifest.publishConfig?.registry === 'https://registry.npmjs.org/' && Object.keys(manifest.publishConfig).length === 2, 'METADATA_INVALID', 'publishConfig must select the public npm registry explicitly')
  requireCheck(Array.isArray(manifest.files) && JSON.stringify([...manifest.files].sort()) === JSON.stringify(SOURCE_FILES), 'METADATA_INVALID', 'files must be the exact prebuilt file whitelist')
  requireCheck(manifest.scripts && HOOKS.every(hook => manifest.scripts[hook] === undefined), 'METADATA_INVALID', 'prebuilt package cannot declare build/install/publish lifecycle hooks')
  requireCheck(JSON.stringify(manifest.dsh) === JSON.stringify({ bundle: { patch: './dsh/cordis.patch.yml' } }), 'METADATA_INVALID', 'DSH bundle patch entry point is incorrect')
  requireCheck(manifest.license === 'AGPL-3.0-only' && manifest.repository?.url === 'git+https://github.com/toby-bridges/api-relay-audit.git', 'METADATA_INVALID', 'license/repository metadata does not identify this project')
  requireCheck(manifest.engines?.node === '^22.19.0 || >=24.0.0', 'METADATA_INVALID', 'supported Node runtime range is missing')
  requireCheck(manifest.homepage === 'https://apirelayaudit.com/', 'METADATA_INVALID', 'homepage must point to the project website')
  const expectedPeers = ['@deepseek-ai/cordis', ...['commands', 'credentials', 'llm', 'settings', 'subprocess'].map(name => `@deepseek-ai/dsh-${name}`)].sort()
  requireCheck(manifest.peerDependencies && JSON.stringify(Object.keys(manifest.peerDependencies).sort()) === JSON.stringify(expectedPeers), 'METADATA_INVALID', 'DSH host peer dependencies are incomplete')
  for (const [name, range] of Object.entries(manifest.peerDependencies)) {
    requireCheck(range === (name === '@deepseek-ai/cordis' ? '^4.0.1' : '0.1.0-rc.6 || 0.1.7-rc.2 || 0.2.0-rc.2'), 'METADATA_INVALID', `unexpected host compatibility range: ${name}`)
  }
}

/** Verify bytes against the checkout before writing a temporary runtime copy. */
export function verifyPackageTarball(tarball, sourceRoot = SOURCE_ROOT) {
  const bytes = readFileSync(tarball)
  requireCheck(bytes.length <= MAX_ARCHIVE_BYTES, 'ARCHIVE_INVALID', 'compressed candidate exceeds the size limit')
  const files = readPackageArchive(bytes)
  let metadata
  try { metadata = JSON.parse(files.get('package.json').toString('utf8')) } catch {
    throw new PackageVerificationError('METADATA_INVALID', 'package.json is not valid JSON')
  }
  validateMetadata(metadata, files.get('VERSION').toString('utf8').trim())
  for (const [path, content] of files) {
    const source = join(sourceRoot, path)
    requireCheck(lstatSync(source).isFile(), 'SOURCE_MISMATCH', `source must be a regular file: ${path}`)
    requireCheck(content.equals(readFileSync(source)), 'SOURCE_MISMATCH', `packed bytes differ from source: ${path}`)
  }
  return { bytes, files, metadata }
}

/** npm is a JS program: do not spawn npm.cmd or pass package paths to a shell. */
export function resolveNpmCli(env = process.env) {
  const candidates = [env.npm_execpath, join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'), join(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js')]
  for (const directory of (env.PATH ?? env.Path ?? '').split(delimiter)) {
    candidates.push(join(directory, 'node_modules/npm/bin/npm-cli.js'))
    if (process.platform !== 'win32') candidates.push(join(directory, 'npm'))
  }
  for (const candidate of candidates.filter(Boolean)) {
    try {
      const path = realpathSync(candidate)
      if (basename(path) === 'npm-cli.js' && lstatSync(path).isFile()) return path
    } catch { /* Try the next explicitly resolved JS CLI. */ }
  }
  throw new PackageVerificationError('NPM_UNAVAILABLE', 'npm-cli.js could not be located; run through npm run verify:package')
}

async function verifyRuntime(files, scratch) {
  const runtime = join(scratch, 'runtime with spaces')
  for (const [path, bytes] of files) {
    const target = join(runtime, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, bytes)
  }
  let adapter
  try { adapter = await import(pathToFileURL(join(runtime, 'dsh/index.js')).href) } catch {
    throw new PackageVerificationError('ADAPTER_INVALID', 'packed adapter failed to import independently of the checkout')
  }
  let command
  try {
    adapter.apply({ commands: { register: value => { command = value } } })
    requireCheck(command?.name === 'relay-audit' && command.recordInput === false, 'ADAPTER_INVALID', 'packed adapter did not register relay-audit')
    const help = await command.handler({ rawInput: '--help', signal: new AbortController().signal })
    requireCheck(help?.kind === 'success' && /Usage: \/relay-audit/u.test(help.text), 'ADAPTER_INVALID', 'packed command --help failed')
  } catch (error) {
    if (error instanceof PackageVerificationError) throw error
    throw new PackageVerificationError('ADAPTER_INVALID', 'packed command registration or help failed')
  }
  const candidates = [['python3', []], ['python', []], ...(process.platform === 'win32' ? [['py', ['-3']]] : [])]
  for (const [executable, prefix] of candidates) {
    const result = spawnSync(executable, [...prefix, '-S', join(runtime, 'audit.py'), '--help'], { cwd: runtime, encoding: 'utf8', timeout: 20_000, maxBuffer: 1024 * 1024, windowsHide: true })
    if (!result.error && result.status === 0 && /usage:/iu.test(result.stdout)) {
      return { adapterImport: true, commandRegistration: true, commandHelp: true, auditHelp: true, python: executable, pythonSitePackages: false, networkProbes: false, curlRequiredForNetworkProbes: true }
    }
  }
  throw new PackageVerificationError('PYTHON_HELP_FAILED', 'Python 3 could not execute packed audit.py -S --help (curl/network probes were not attempted)')
}

export async function packAndVerify({ sourceRoot = SOURCE_ROOT, outputDir } = {}) {
  const root = realpathSync(sourceRoot)
  const output = resolve(outputDir ?? mkdtempSync(join(tmpdir(), 'api-relay-audit-npm-candidate-')))
  let ancestor = output
  while (!existsSync(ancestor)) ancestor = dirname(ancestor)
  const resolvedOutput = resolve(realpathSync(ancestor), relative(ancestor, output))
  requireCheck(!isWithin(root, resolvedOutput), 'OUTPUT_INVALID', '--output-dir must be outside the source checkout')
  mkdirSync(output, { recursive: true })
  requireCheck(!isWithin(root, realpathSync(output)), 'OUTPUT_INVALID', '--output-dir must be outside the source checkout')
  const source = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
  validateMetadata(source, readFileSync(join(root, 'VERSION'), 'utf8').trim())
  const filename = `${source.name}-${source.version}.tgz`
  const manifestPath = join(output, 'npm-package-manifest.json')
  requireCheck(!existsSync(join(output, filename)) && !existsSync(manifestPath), 'OUTPUT_EXISTS', 'candidate output already exists; use a new output directory')
  const commit = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', windowsHide: true })
  const dirty = spawnSync('git', ['status', '--porcelain', '--untracked-files=normal'], { cwd: root, encoding: 'utf8', windowsHide: true })
  requireCheck(commit.status === 0 && /^[0-9a-f]{40}$/u.test(commit.stdout.trim()) && dirty.status === 0, 'SOURCE_IDENTITY_FAILED', 'git could not establish the checkout commit and dirty state')
  const scratch = mkdtempSync(join(tmpdir(), 'api-relay-audit-npm-verification-'))
  const tarball = join(output, filename)
  try {
    const npmrc = join(scratch, 'empty.npmrc')
    const globalNpmrc = join(scratch, 'global.npmrc')
    writeFileSync(npmrc, '')
    writeFileSync(globalNpmrc, '')
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^npm_config_/iu.test(key)))
    const packed = spawnSync(process.execPath, [resolveNpmCli(), 'pack', '--offline', '--ignore-scripts', '--json', '--audit=false', '--fund=false', '--pack-destination', output, '--cache', join(scratch, 'cache'), '--userconfig', npmrc, '--globalconfig', globalNpmrc], { cwd: root, env, encoding: 'utf8', timeout: 120_000, maxBuffer: 1024 * 1024, windowsHide: true })
    requireCheck(!packed.error && packed.status === 0, 'PACK_FAILED', `offline npm pack failed (exit ${packed.status ?? packed.error?.code ?? 'unknown'})`)
    let result
    try { result = JSON.parse(packed.stdout) } catch { throw new PackageVerificationError('PACK_FAILED', 'npm pack did not return a JSON result') }
    requireCheck(Array.isArray(result) && result.length === 1 && result[0].filename === filename, 'PACK_FAILED', 'npm pack returned an unexpected candidate name')
    const verified = verifyPackageTarball(tarball, root)
    const runtime = await verifyRuntime(verified.files, scratch)
    const integrity = `sha512-${digest('sha512', verified.bytes, 'base64')}`
    requireCheck(result[0].integrity === integrity, 'INTEGRITY_MISMATCH', 'npm integrity does not match the actual candidate bytes')
    const manifest = {
      schema: 'api-relay-audit-npm-package/v1',
      package: { name: source.name, version: source.version },
      source: { commit: commit.stdout.trim(), dirty: dirty.stdout.trim().length > 0 },
      tarball: { path: tarball, filename, bytes: verified.bytes.length, sha256: digest('sha256', verified.bytes), sha512: digest('sha512', verified.bytes), integrity },
      files: [...verified.files].sort(([left], [right]) => left.localeCompare(right, 'en')).map(([path, content]) => ({ path, bytes: content.length, sha256: digest('sha256', content) })),
      checks: { offlinePack: true, lifecycleScriptsDisabled: true, exactFileWhitelist: true, sourceBytes: true, metadata: true, ...runtime },
      published: false,
    }
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' })
    return { ...manifest, manifestPath }
  } catch (error) {
    // A failed candidate must not be confused with an accepted release input.
    rmSync(tarball, { force: true })
    throw error
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
}

async function main(argv) {
  let outputDir
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--output-dir' && argv[index + 1]) outputDir = argv[++index]
    else if (argv[index] === '--help') {
      console.log('Usage: npm run verify:package -- [--output-dir <new directory outside checkout>]\nBuilds an offline npm candidate and verifies its exact runtime bytes. Does not publish.')
      return
    } else throw new PackageVerificationError('ARGUMENT_INVALID', 'only --output-dir <directory> and --help are accepted')
  }
  console.log(JSON.stringify(await packAndVerify({ outputDir }), null, 2))
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    console.error(error instanceof PackageVerificationError ? error.message : 'VERIFICATION_FAILED: unexpected local verification failure')
    process.exitCode = 1
  })
}
