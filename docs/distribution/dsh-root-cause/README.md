# DSH install failure evidence: issues 99, 101 and 103

Prepared on 2026-10-24 for review in the API Relay Audit repository. This package contains minimized public log fixtures, pinned source references, executable classifier observations and a proposed repair contract. It does not claim that an upstream repair has shipped or that the original Windows failure has been reproduced.

| Report | Observable failure | Proven boundary | Still unknown |
| --- | --- | --- | --- |
| [99](https://github.com/toby-bridges/api-relay-audit/issues/99) | Git reports `CONNECT tunnel failed, response 502` before fetching the repository. | The log does not show a plugin build failure. Hub's pinned classifiers return `pluginPrepare`. | Which proxy/intermediary returned 502. |
| [101](https://github.com/toby-bridges/api-relay-audit/issues/101) | pnpm prints `Done`, then Hub records `[timed out]`. | Printing `Done` is not evidence that DSH exited, committed profile state or loaded the command. | Which process, reconciliation step or inherited output pipe kept the original installation pending. |
| [103](https://github.com/toby-bridges/api-relay-audit/issues/103) | pnpm reports that the `git` executable was not found. | Fetching the Git dependency cannot start. The appended `allowBuilds` hint is not evidence of a build-policy rejection. | Exact executable lookup environment of the reported run. |

The reporter's later source-tree command for issue 101 was described as returning exit code 0 in [the follow-up](https://github.com/toby-bridges/api-relay-audit/issues/101#issuecomment-5711149504). Matching the Hub entry point, DSH build, `DSH_HOME`, profile, package manager and loaded command was still outstanding. The screenshot and raw environment are deliberately not redistributed here.

## Source and version boundaries

[manifest.json](manifest.json) pins full Git commits, Git blob IDs and SHA-256 hashes. The two classifier snapshots are Hub 1.4.2 (`641b716...`) and the reviewed Hub 2.2.0 source (`f17814f...`). Report 99 names Hub 1.4.2; reports 101 and 103 name Hub 1.4.3 and 1.4.7 respectively. The 1.4.2 replay is a historical baseline, not an exact-version replay of those latter reports. The current snapshot does not establish which binary a reporter used.

The DSH snapshots are the historical `dd6322d...` CLI implementation and reviewed `22ddee3...` source. They establish source behavior at those commits, not an installed-host test result. The [Hub npm target gate](https://github.com/dshplugin/dsh-plugin-hub/blob/f17814f949604a727c708accf10f2b68cdfa63bd/src/server/http/install.ts#L119-L124) now requires an explicit npm package name on that route. A publishable npm artifact removes the plugin's Git fetch/build dependency; it cannot repair a broken proxy or prove that the host installation lifecycle is correct.

## Reproduce the observations

Use Node 22.19 or newer with native TypeScript stripping (Node 24+ is also supported). From the repository root:

```sh
node scripts/dsh-evidence/replay.mjs
node --test scripts/dsh-evidence/lifecycle.test.mjs
```

The replay downloads eight public files at fixed commits into a temporary directory, checks SHA-256 before importing either unmodified upstream classifier, then removes that directory. It installs no packages and reads no account configuration. Network access to `raw.githubusercontent.com` is required. It never downloads from mutable branch names.

For an offline replay, obtain the exact public source bytes listed in the manifest, name them using each entry's `localFile`, and pass that directory:

```sh
node scripts/dsh-evidence/replay.mjs --source-dir /path/to/pinned-sources
```

The default mode asserts the **observed** outputs, so the baseline is green: 6 assertions pass while only 1 of the 6 outputs has the desired classification. [baseline-observation.json](baseline-observation.json) records that result. This is deliberate preservation of a defect, not a claim that five defects are repaired.

To demonstrate the classification acceptance failure explicitly:

```sh
node scripts/dsh-evidence/replay.mjs --source-dir /path/to/pinned-sources --require-correct-classification
```

That gate exits nonzero on these pinned sources. It is not a passing CI test. Upstream maintainers can reuse the sanitized fixtures and expected values as regression tests against their repair.

The lifecycle test is **synthetic**: a short-lived Node child exits 0 while its Node descendant still owns the inherited output pipe. It distinguishes `exit` from `close`, has a bounded watchdog and cleans up failed runs. It runs neither pnpm nor DSH and is not a reproduction or diagnosis of issue 101. Platform-specific host reproduction is a separate gate in [the acceptance matrix](acceptance-matrix.md).

[verification.json](verification.json) records the local commands and outcomes. The original evidence-package checks ran on macOS with Node 25.9.0; the revised lifecycle fixture was also checked on macOS with Node 22.19.0. These local results are not Windows acceptance.

The [first Windows CI run](https://github.com/toby-bridges/api-relay-audit/actions/runs/40107990920) failed the original synthetic fixture before the real DSH consumer step. Its parent exited and the pipe closed before the holder's release was observed. The original holder used `unref()` without `detached`; on Windows, [Node v22.19.0's libuv creates a kill-on-close Job](https://github.com/nodejs/node/blob/v22.19.0/deps/uv/src/win/process.c#L69-L96) and [assigns non-detached child processes to it](https://github.com/nodejs/node/blob/v22.19.0/deps/uv/src/win/process.c#L1082-L1102). That design is consistent with the early holder termination. The CI run did not instrument the Job itself, so its exact outer Job configuration is not claimed.

The corrected fixture explicitly detaches the holder, waits for its IPC readiness acknowledgement, disconnects that IPC channel, and releases the inherited pipe through an isolated temporary marker only after the observer sees the direct parent's `exit`. The holder has a 1.5-second self-cleanup deadline; the controller's original 2.5-second watchdog remains unchanged. This replaces a timing assumption with a startup/release protocol. It does not skip Windows, extend the install timeout or reproduce issue 101. Windows confirmation belongs to the next PR CI run; detachment does not imply escaping an outer CI Job.

## Review and delivery

- [findings.md](findings.md) separates observed evidence from inferences and unknowns.
- [repair-contract.md](repair-contract.md) proposes lifecycle results, ownership and the failure taxonomy.
- [acceptance-matrix.md](acceptance-matrix.md) defines closure requirements, including original Windows reproduction.
- [licenses](licenses/) preserve the upstream MIT notices. No upstream endorsement or author identity is implied.

Fixtures are manually minimized excerpts of public issue logs. Usernames, local absolute paths, stack locations, screenshots, headers, signed attachment links and unrelated diagnostics have been removed; `<PROFILE>` is an explicit replacement. They preserve the failure strings needed by the classifier. SHA-256 identifies the sanitized fixture, not the reporter's full log. The package contains no raw private report or full upstream source copy.

The public npm registry's availability must be checked again before publishing. A prior empty/null search result is not proof that a package name is available or absent. Publication, registry ownership changes, issue replies and upstream PRs require separate owner approval.
