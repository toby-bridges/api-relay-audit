import assert from 'node:assert/strict'
import test from 'node:test'
import { gzipSync } from 'node:zlib'
import { manifestFromTarball, startFixture } from './fixture.mjs'
import { runProcess } from './process.mjs'
import { sanitizeEvidence } from './sanitize.mjs'

const manifest = { name: 'dsh-api-relay-audit', version: '2.5.0', type: 'module' }

test('tarball manifest is read from the candidate, without checkout metadata', () => {
  const body = Buffer.from(JSON.stringify(manifest))
  const tar = Buffer.alloc(2048)
  tar.write('package/package.json')
  tar.write(body.length.toString(8).padStart(11, '0'), 124)
  body.copy(tar, 512)
  assert.deepEqual(manifestFromTarball(gzipSync(tar)), manifest)
  assert.throws(() => manifestFromTarball(gzipSync(Buffer.alloc(512))), /does not contain/u)
})

test('registry serves only the fixed candidate, including SRI and tarball bytes', async () => {
  const bytes = Buffer.from('one unpublished candidate')
  const fixture = await startFixture({ manifest, tarball: bytes })
  try {
    assert.equal(new URL(fixture.baseUrl).hostname, '127.0.0.1')
    const metadata = await (await fetch(`${fixture.baseUrl}/${manifest.name}`)).json()
    assert.equal(metadata.versions['2.5.0'].dist.integrity, fixture.integrity)
    const downloaded = Buffer.from(await (await fetch(metadata.versions['2.5.0'].dist.tarball)).arrayBuffer())
    assert.deepEqual(downloaded, bytes)
    assert.equal((await fetch(`${fixture.baseUrl}/unexpected-package`)).status, 404)
  } finally { await fixture.close() }
})

test('API fixture rejects real credentials and unexpected prompts', async () => {
  const fixture = await startFixture({ manifest, tarball: Buffer.from('candidate') })
  try {
    const request = key => fetch(`${fixture.baseUrl}/v1/messages`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': key },
      body: JSON.stringify({ model: 'claude-acceptance-loopback', max_tokens: 8, messages: [{ role: 'user', content: 'Reply with the single word: ok' }] }),
    })
    assert.equal((await request('not-the-fixture-key')).status, 400)
    assert.equal((await fetch(`${fixture.baseUrl}/v1/messages`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': fixture.syntheticKey },
      body: JSON.stringify({ model: 'claude-acceptance-loopback', max_tokens: 8, messages: [{ role: 'user', content: 'unexpected prompt' }] }),
    })).status, 400)
    assert.equal((await request(fixture.syntheticKey)).status, 200)
    assert.deepEqual(fixture.paths, ['/v1/messages'])
  } finally { await fixture.close() }
})

test('process verifier records exit and pipe close separately', async () => {
  const events = []
  const result = await runProcess(process.execPath, ['-e', 'process.stdout.write("Done"); process.exitCode = 7'], { allowFailure: true, onEvent: event => events.push(event) })
  assert.equal(result.exitCode, 7)
  assert.equal(result.timedOut, false)
  assert.equal(result.stdout, 'Done')
  assert.deepEqual(events.filter(event => ['exit', 'close'].includes(event.type)).map(event => event.type), ['exit', 'close'])
  assert.ok(events[0].pid > 0)
})

test('Done output does not convert a hung process into success', async () => {
  const events = []
  const result = await runProcess(process.execPath, ['-e', 'process.stdout.write("Done"); setInterval(() => {}, 1000)'], { allowFailure: true, timeoutMs: 1000, onEvent: event => events.push(event) })
  assert.equal(result.timedOut, true)
  assert.equal(result.stdout, 'Done')
  assert.ok(events.some(event => event.type === 'deadline'))
  assert.ok(events.some(event => event.type === 'close'))
})

test('evidence removes Windows raw, JSON, slash, file URL and encoded-space paths', () => {
  const root = 'C:\\Users\\Fixture User\\AppData\\Local\\Temp\\DSH acceptance abc'
  const variants = [
    root, JSON.stringify(root), root.replaceAll('\\', '/'),
    'file:///C:/Users/Fixture%20User/AppData/Local/Temp/DSH%20acceptance%20abc/log.js',
  ]
  for (const value of variants) {
    const result = sanitizeEvidence(`${value} fixture-secret`, { roots: [[root, '<acceptance-root>']], secrets: ['fixture-secret'] })
    assert.ok(!result.includes('Fixture'))
    assert.ok(!result.includes('acceptance%20abc'))
    assert.ok(!result.includes('fixture-secret'))
    assert.ok(result.includes('<acceptance-root>'))
    assert.ok(result.includes('<synthetic-credential>'))
  }
})

test('metadata cancellation fixture pauses the actual registry response', async () => {
  const fixture = await startFixture({ manifest, tarball: Buffer.from('candidate') })
  const pause = fixture.pauseNextMetadata()
  let completed = false
  const response = fetch(`${fixture.baseUrl}/${manifest.name}`).then(value => { completed = true; return value })
  try {
    await pause.reached
    assert.equal(completed, false)
    pause.release()
    assert.equal((await response).status, 200)
  } finally { pause.release(); await fixture.close() }
})
