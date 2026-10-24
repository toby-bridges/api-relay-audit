import assert from 'node:assert/strict'
import { readFile, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

// No adapter functions are called directly. This mounts the installed package
// through the official DSH Loader, then calls the real commands service. It is
// a headless host integration check; browser rendering is outside its claim.
const [hostDir, profileDir, workspace, fixtureUrl, expectInstalled] = process.argv.slice(2)
const requireHost = createRequire(join(hostDir, 'package.json'))
const cliRoot = join(hostDir, 'node_modules', '@deepseek-ai', 'dsh')
const { boot, loadProfile, createRuntimeResolution, PluginPackages } = await import(pathToFileURL(requireHost.resolve('@deepseek-ai/dsh-app-boot')))
const anchor = join(cliRoot, 'package.json')
const profile = loadProfile('dsh', 'acceptance', anchor)
assert.equal(profile.dir, profileDir)
const rootConfig = join(profileDir, 'acceptance-root.yml')
await writeFile(rootConfig, '[]\n')
const core = [
  ['commands', '@deepseek-ai/dsh-commands'],
  ['credentials', '@deepseek-ai/dsh-credentials-local', { watch: false }],
  ['subprocess', '@deepseek-ai/dsh-subprocess-local'],
  ['llm', '@deepseek-ai/dsh-llm'],
  ['config-editor', '@deepseek-ai/dsh-config-editor'],
  ['settings', '@deepseek-ai/dsh-settings'],
  ['sessions', '@deepseek-ai/dsh-session'],
].map(([id, name, config]) => ({ id, name, ...(config ? { config } : {}) }))
const patches = [{ insert: core }, ...profile.layers.flatMap(layer => layer.patches), ...profile.patches]
assert.deepEqual(profile.skippedBundles, [], 'host skipped a selected profile bundle')
console.log(JSON.stringify({ stage: 'loader-start', pid: process.pid, bundles: profile.layers.map(layer => layer.packageName) }))
const resolution = await createRuntimeResolution({ installAnchor: anchor, profile })
const ctx = await boot('dsh-acceptance', rootConfig, patches, async hostCtx => {
  hostCtx.provide('profileContext', {
    name: 'acceptance', dir: profileDir, patchPath: profile.patchPath,
    installAnchor: anchor, cwd: workspace, home: process.env.DSH_HOME,
    startedBundles: profile.layers.map(layer => layer.packageName), overlays: [],
    telemetryDisabledEnv: '1',
  })
  await hostCtx.plugin(PluginPackages, { resolution })
})
try {
  const session = ctx.sessions.create(undefined, { meta: { cwd: workspace } })
  const agent = { session, options: { model: 'claude-acceptance-loopback' } }
  const commands = ctx.commands.list(agent)
  const found = commands.find(command => command.name === 'relay-audit')
  if (expectInstalled !== 'yes') {
    assert.equal(found, undefined, 'uninstall left a registered relay-audit command')
    console.log(JSON.stringify({ stage: 'uninstalled-loader', commandAbsent: true }))
  } else {
    assert.ok(found, 'real command discovery did not find relay-audit')
    const signal = AbortSignal.timeout(45_000)
    const help = await ctx.commands.execute(agent, '/relay-audit --help', [], signal)
    assert.equal(help.result.kind, 'success')
    assert.match(help.result.text, /Usage: \/relay-audit/u)
    console.log(JSON.stringify({ stage: 'command-help', kind: help.result.kind }))
    const result = await ctx.commands.execute(agent,
      `/relay-audit --connectivity --url ${fixtureUrl} --model claude-acceptance-loopback --credential-ref DSH_ACCEPTANCE_FIXTURE_KEY --output "connectivity report.md" --timeout 5`, [], signal)
    assert.equal(result.result.kind, 'success', result.result.text)
    const report = await readFile(join(workspace, 'connectivity report.md'), 'utf8')
    assert.match(report, /Connectivity Verdict\*\*: \*\*OK\*\*/u)
    assert.ok(!report.includes(process.env.DSH_ACCEPTANCE_FIXTURE_KEY), 'credential appeared in the report')
    console.log(JSON.stringify({ stage: 'command-connectivity', kind: result.result.kind, report: 'connectivity report.md', bothFormats: true }))
  }
} finally {
  await ctx.fiber.dispose()
  console.log(JSON.stringify({ stage: 'loader-disposed', pid: process.pid }))
}
