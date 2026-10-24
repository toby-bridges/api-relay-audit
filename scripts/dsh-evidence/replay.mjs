#!/usr/bin/env node
// Replays the pinned upstream classifiers; no replacement classifier is implemented here.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const evidence = join(root, 'docs/distribution/dsh-root-cause')
const args = process.argv.slice(2)
let sourceDir
let requireCorrect = false
for (let index = 0; index < args.length; index++) {
  if (args[index] === '--source-dir' && args[index + 1]) sourceDir = resolve(args[++index])
  else if (args[index] === '--require-correct-classification') requireCorrect = true
  else throw new Error('Usage: node scripts/dsh-evidence/replay.mjs [--source-dir DIR] [--require-correct-classification]')
}

const manifest = JSON.parse(await readFile(join(evidence, 'manifest.json'), 'utf8'))
let temporary
try {
  if (!sourceDir) {
    temporary = await mkdtemp(join(tmpdir(), 'dsh-evidence-'))
    sourceDir = temporary
    await Promise.all(manifest.sources.map(async source => {
      const response = await fetch(source.rawUrl, { signal: AbortSignal.timeout(15000), redirect: 'error' })
      if (!response.ok) throw new Error(`Download failed for ${source.id}: HTTP ${response.status}`)
      const bytes = Buffer.from(await response.arrayBuffer())
      assert.equal(createHash('sha256').update(bytes).digest('hex'), source.sha256, `Source hash mismatch: ${source.id}`)
      await writeFile(join(sourceDir, source.localFile), bytes)
    }))
  }
  for (const source of manifest.sources) {
    const bytes = await readFile(join(sourceDir, source.localFile))
    assert.equal(createHash('sha256').update(bytes).digest('hex'), source.sha256, `Source hash mismatch: ${source.id}`)
  }
  const results = []
  for (const source of manifest.sources.filter(source => source.role === 'classifier')) {
    const { classifyFailure } = await import(pathToFileURL(join(sourceDir, source.localFile)).href)
    for (const fixture of manifest.classificationCases) {
      const message = await readFile(join(evidence, 'fixtures', fixture.file), 'utf8')
      assert.equal(createHash('sha256').update(message).digest('hex'), fixture.sha256, `Fixture hash mismatch: issue ${fixture.issue}`)
      const actual = classifyFailure(message)
      const observed = fixture.observed[source.id]
      assert.equal(actual, requireCorrect ? fixture.expected : observed, `${source.id} issue ${fixture.issue}`)
      results.push({ source: source.id, issue: fixture.issue, actual, expected: fixture.expected, correct: actual === fixture.expected })
    }
  }
  console.log(JSON.stringify({
    mode: requireCorrect ? 'correct-classification-gate' : 'pinned-baseline-observation',
    sourceHashesVerified: manifest.sources.length,
    baselineAssertionsPassed: results.length,
    desiredClassificationsMatched: results.filter(result => result.correct).length,
    desiredClassificationsTotal: results.length,
    results,
  }, null, 2))
} finally {
  if (temporary) await rm(temporary, { recursive: true, force: true })
}
