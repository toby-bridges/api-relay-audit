import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { gunzipSync } from 'node:zlib'

export const SYNTHETIC_KEY = 'sk-acceptance-loopback-only-not-a-real-credential'

// The candidate is served from loopback. Metadata for the already bootstrapped
// public dependency closure may be read from npmjs; arbitrary packages, URLs,
// caller headers and credentials are never forwarded.
export function manifestFromTarball(bytes) {
  const files = filesFromTarball(bytes)
  assert.ok(files.has('package/package.json'), 'candidate tarball does not contain package/package.json')
  return JSON.parse(files.get('package/package.json').toString())
}

export function filesFromTarball(bytes) {
  const tar = gunzipSync(bytes, { maxOutputLength: 16 * 1024 * 1024 })
  const files = new Map()
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512)
    const name = header.subarray(0, 100).toString().replace(/\0.*$/su, '')
    const size = Number.parseInt(header.subarray(124, 136).toString().replace(/\0.*$/su, '').trim() || '0', 8)
    assert.ok(Number.isSafeInteger(size) && size >= 0, 'invalid tar member size')
    if (!name) break
    assert.ok(offset + 512 + size <= tar.length, 'truncated tar member')
    files.set(name, tar.subarray(offset + 512, offset + 512 + size))
    offset += 512 + Math.ceil(size / 512) * 512
  }
  return files
}

export async function startFixture({ manifest, tarball, metadataPackages = new Set(), onEvent = () => {} }) {
  assert.match(manifest.name, /^dsh-api-relay-audit$/u)
  assert.match(manifest.version, /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/u)
  const syntheticKey = SYNTHETIC_KEY
  const integrity = `sha512-${createHash('sha512').update(tarball).digest('base64')}`
  const paths = []
  let baseUrl
  let nextMetadataPause
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, baseUrl)
    if (request.method === 'GET' && url.pathname === `/${manifest.name}`) {
      if (nextMetadataPause) {
        const pause = nextMetadataPause
        nextMetadataPause = undefined
        onEvent({ type: 'candidate-metadata-paused' })
        pause.reached()
        await pause.released
      }
      response.setHeader('content-type', 'application/json')
      response.end(JSON.stringify({
        name: manifest.name,
        'dist-tags': { latest: manifest.version },
        versions: {
          [manifest.version]: {
            ...manifest,
            dist: { integrity, tarball: `${baseUrl}/candidate.tgz` },
          },
        },
      }))
      onEvent({ type: 'registry-metadata', name: manifest.name, version: manifest.version })
      return
    }
    if (request.method === 'GET' && url.pathname === '/candidate.tgz') {
      response.setHeader('content-type', 'application/octet-stream')
      response.end(tarball)
      onEvent({ type: 'registry-tarball', integrity })
      return
    }
    const packageName = decodeURIComponent(url.pathname.slice(1))
    if (request.method === 'GET' && metadataPackages.has(packageName)) {
      try {
        const metadata = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`, { signal: AbortSignal.timeout(20_000) })
        assert.equal(metadata.status, 200)
        response.setHeader('content-type', 'application/json')
        response.end(await metadata.text())
        onEvent({ type: 'public-dependency-metadata', name: packageName, source: 'registry.npmjs.org' })
      } catch {
        response.writeHead(502).end('public dependency metadata unavailable')
      }
      return
    }
    if (request.method !== 'POST' || !['/v1/messages', '/v1/chat/completions'].includes(url.pathname)) {
      response.writeHead(404).end()
      onEvent({ type: 'rejected-fixture-request', method: request.method, path: url.pathname })
      return
    }
    let body = ''
    for await (const chunk of request) {
      body += chunk
      if (body.length > 8192) {
        response.writeHead(413).end()
        return
      }
    }
    try {
      assert.equal(request.headers.host, new URL(baseUrl).host)
      assert.ok(request.headers['x-api-key'] === syntheticKey || request.headers.authorization === `Bearer ${syntheticKey}`)
      const data = JSON.parse(body)
      assert.equal(data.model, 'claude-acceptance-loopback')
      assert.deepEqual(data.messages, [{ role: 'user', content: 'Reply with the single word: ok' }])
      assert.equal(data.max_tokens, 8)
      paths.push(url.pathname)
      onEvent({ type: 'synthetic-api-request', path: url.pathname, authenticated: true })
      response.setHeader('content-type', 'application/json')
      response.end(JSON.stringify(url.pathname === '/v1/messages'
        ? { content: [{ type: 'text', text: 'ok' }], usage: { input_tokens: 1, output_tokens: 1 } }
        : { choices: [{ message: { role: 'assistant', content: 'ok' } }], usage: { prompt_tokens: 1, completion_tokens: 1 } }))
    } catch {
      response.writeHead(400).end('fixture rejected unexpected input')
    }
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  baseUrl = `http://127.0.0.1:${server.address().port}`
  return {
    baseUrl, syntheticKey, integrity, paths,
    pauseNextMetadata() {
      assert.equal(nextMetadataPause, undefined, 'only one metadata pause may be pending')
      let reached
      let release
      const reachedPromise = new Promise(resolve => { reached = resolve })
      const released = new Promise(resolve => { release = resolve })
      nextMetadataPause = { reached, released }
      return { reached: reachedPromise, release }
    },
    close: () => new Promise((resolve, reject) => {
      server.closeAllConnections()
      server.close(error => error ? reject(error) : resolve())
    }),
  }
}
