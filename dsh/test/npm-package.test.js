import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import test, { after, before } from 'node:test'
import { gzipSync } from 'node:zlib'

import { packAndVerify, readPackageArchive, verifyPackageTarball } from '../../scripts/verify-npm-package.mjs'

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const scratch = mkdtempSync(join(tmpdir(), 'dsh-npm-package-test-'))
let candidate
let files

before(async () => {
  candidate = await packAndVerify({ outputDir: join(scratch, 'candidate with spaces') })
  files = readPackageArchive(readFileSync(candidate.tarball.path))
})
after(() => rmSync(scratch, { recursive: true, force: true }))

// Small standards-based tar fixture writer; no tar executable is needed on Windows.
function archive(entries) {
  const blocks = []
  for (const { path, bytes, type = '0' } of entries) {
    const header = Buffer.alloc(512)
    header.write(`package/${path}`, 0, 100, 'utf8')
    for (const [offset, length, value] of [[100, 8, 0o644], [108, 8, 0], [116, 8, 0], [124, 12, bytes.length], [136, 12, 0]]) {
      header.write(`${value.toString(8).padStart(length - 1, '0')}\0`, offset, length, 'ascii')
    }
    header.fill(32, 148, 156)
    header.write(type, 156, 1, 'ascii')
    header.write('ustar\0', 257, 6, 'ascii')
    const checksum = [...header].reduce((sum, byte) => sum + byte, 0)
    header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii')
    blocks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512))
  }
  blocks.push(Buffer.alloc(1024))
  return gzipSync(Buffer.concat(blocks))
}

function entries() {
  return [...files].map(([path, bytes]) => ({ path, bytes }))
}

function changedCandidate(changes) {
  const path = join(scratch, 'changed.tgz')
  writeFileSync(path, archive(changes))
  return path
}

test('actual offline npm candidate has only runtime files and verified checksums', () => {
  assert.equal(candidate.published, false)
  assert.equal(candidate.package.name, 'dsh-api-relay-audit')
  assert.equal(candidate.package.version, readFileSync(join(sourceRoot, 'VERSION'), 'utf8').trim())
  assert.match(candidate.source.commit, /^[0-9a-f]{40}$/u)
  assert.equal(typeof candidate.source.dirty, 'boolean')
  assert.deepEqual([...files.keys()].sort(), ['LICENSE', 'NOTICE', 'README.md', 'VERSION', 'audit.py', 'dsh/cordis.patch.yml', 'dsh/index.js', 'package.json'].sort())
  assert.deepEqual(readdirSync(dirname(candidate.tarball.path)).sort(), [candidate.tarball.filename, 'npm-package-manifest.json'].sort())
  const bytes = readFileSync(candidate.tarball.path)
  assert.equal(candidate.tarball.sha256, createHash('sha256').update(bytes).digest('hex'))
  assert.equal(candidate.tarball.sha512, createHash('sha512').update(bytes).digest('hex'))
  assert.equal(candidate.tarball.integrity, `sha512-${createHash('sha512').update(bytes).digest('base64')}`)
  assert.equal(files.get('audit.py').equals(readFileSync(join(sourceRoot, 'audit.py'))), true)
  for (const check of ['offlinePack', 'lifecycleScriptsDisabled', 'exactFileWhitelist', 'sourceBytes', 'metadata', 'adapterImport', 'commandRegistration', 'commandHelp', 'auditHelp']) {
    assert.equal(candidate.checks[check], true, check)
  }
  assert.equal(candidate.checks.pythonSitePackages, false)
  assert.equal(candidate.checks.networkProbes, false)
  assert.equal(candidate.checks.curlRequiredForNetworkProbes, true)
})

test('rejects changed audit bytes even when the archive is structurally valid', () => {
  const changed = entries().map(entry => entry.path === 'audit.py' ? { ...entry, bytes: Buffer.concat([entry.bytes, Buffer.from('\n# changed\n')]) } : entry)
  assert.throws(() => verifyPackageTarball(changedCandidate(changed), sourceRoot), { code: 'SOURCE_MISMATCH' })
})

test('rejects an added install lifecycle hook before running package code', () => {
  const manifest = JSON.parse(files.get('package.json'))
  manifest.scripts.install = 'node unsafe.js'
  const changed = entries().map(entry => entry.path === 'package.json' ? { ...entry, bytes: Buffer.from(JSON.stringify(manifest)) } : entry)
  assert.throws(() => verifyPackageTarball(changedCandidate(changed), sourceRoot), { code: 'METADATA_INVALID' })
})

test('rejects sensitive files and paths escaping the package', () => {
  for (const path of ['.npmrc', '../outside', 'dsh/../../outside']) {
    assert.throws(() => verifyPackageTarball(changedCandidate([...entries(), { path, bytes: Buffer.from('fixture') }]), sourceRoot), { code: 'FILE_SET_MISMATCH' })
  }
})

test('rejects links, duplicated files, and missing runtime files', () => {
  const linked = entries().map(entry => entry.path === 'audit.py' ? { ...entry, type: '2' } : entry)
  assert.throws(() => verifyPackageTarball(changedCandidate(linked), sourceRoot), { code: 'ARCHIVE_INVALID' })
  assert.throws(() => verifyPackageTarball(changedCandidate([...entries(), entries()[0]]), sourceRoot), { code: 'ARCHIVE_INVALID' })
  assert.throws(() => verifyPackageTarball(changedCandidate(entries().filter(entry => entry.path !== 'audit.py')), sourceRoot), { code: 'FILE_SET_MISMATCH' })
})

test('rejects corrupted archives', () => {
  const path = join(scratch, 'corrupt.tgz')
  writeFileSync(path, Buffer.from('not a gzip archive'))
  assert.throws(() => verifyPackageTarball(path, sourceRoot), { code: 'ARCHIVE_INVALID' })
})

test('refuses checkout output paths without creating them and preserves existing candidates', async () => {
  const forbidden = join(sourceRoot, 'npm-output-must-not-be-created')
  assert.equal(existsSync(forbidden), false)
  await assert.rejects(packAndVerify({ outputDir: forbidden }), { code: 'OUTPUT_INVALID' })
  assert.equal(existsSync(forbidden), false)
  const before = readFileSync(candidate.tarball.path)
  await assert.rejects(packAndVerify({ outputDir: dirname(candidate.tarball.path) }), { code: 'OUTPUT_EXISTS' })
  assert.equal(readFileSync(candidate.tarball.path).equals(before), true)
})

test('command rejects unsupported publishing arguments with an explicit failure code', () => {
  const result = spawnSync(process.execPath, [join(sourceRoot, 'scripts/verify-npm-package.mjs'), '--publish'], { cwd: sourceRoot, encoding: 'utf8', windowsHide: true })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /^ARGUMENT_INVALID:/u)
})
