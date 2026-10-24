# Findings and evidence limits

## 1. Error attribution is based on broad log wrappers

The full pinned classifiers are executed without modification by `scripts/dsh-evidence/replay.mjs`. Both snapshots miss the `CONNECT tunnel failed, response 502` form and later match the generic `Command failed` wrapper. That returns `pluginPrepare` even though the actual command was Git repository lookup.

The current classifier's Git-missing branch recognizes several shell/ENOENT forms but omits pnpm's `` `git` executable not found `` form. The appended DSH hint then reaches its `pnpmIgnoredBuild` branch. These are concrete missing signatures and overly broad fallback predicates:

- Hub [historical classifier](https://github.com/dshplugin/dsh-plugin-hub/blob/641b71666fd20cf9b0226106c879e60c33e0df26/src/client/logic/failures.ts#L224), [network/build fallback](https://github.com/dshplugin/dsh-plugin-hub/blob/641b71666fd20cf9b0226106c879e60c33e0df26/src/client/logic/failures.ts#L267-L274).
- Hub [current Git branch](https://github.com/dshplugin/dsh-plugin-hub/blob/f17814f949604a727c708accf10f2b68cdfa63bd/src/client/logic/failures.ts#L232), [network/build fallback](https://github.com/dshplugin/dsh-plugin-hub/blob/f17814f949604a727c708accf10f2b68cdfa63bd/src/client/logic/failures.ts#L273-L289), [timeout/hint fallback](https://github.com/dshplugin/dsh-plugin-hub/blob/f17814f949604a727c708accf10f2b68cdfa63bd/src/client/logic/failures.ts#L299-L305).

The desired outputs for these fixtures are `network`, `timeout` and `gitMissing`. The 1.4.2 baseline produces `pluginPrepare`, `repo`, `repo`; the reviewed current snapshot produces `pluginPrepare`, `timeout`, `pnpmIgnoredBuild`. This isolates classification defects; it does not fix the underlying network failure or missing executable.

## 2. DSH emits a build authorization suggestion without evidence of that cause

The [historical DSH branch](https://github.com/deepseek-ai/deepseek-harness/blob/dd6322d604e00eec1ba5e0c8541159906a21094a/apps/cli/src/plugin.ts#L147-L160) emits the hint for any nonzero package-manager exit when an argument looks like a Git source. The [reviewed current branch](https://github.com/deepseek-ai/deepseek-harness/blob/22ddee3792402c3e70ec5f86a63c3e3e895a2f60/apps/cli/src/plugin.ts#L103-L106) still has that predicate. Neither condition checks whether pnpm actually rejected a build. The hint therefore pollutes both human troubleshooting and downstream classification.

The repair should carry a structured cause from the package operation and emit `allowBuilds` advice only for a confirmed build-policy rejection. A Git URL alone is not evidence that any build was attempted. The plugin's prebuilt npm artifact should not introduce an installation-time build script simply to satisfy that hint.

## 3. Hub can overwrite timeout evidence with filesystem presence

The [current task queue](https://github.com/dshplugin/dsh-plugin-hub/blob/f17814f949604a727c708accf10f2b68cdfa63bd/src/server/services/install/task-queue.ts#L645-L649) changes a timed-out first installation to `exitCode: 0`, `timedOut: false` when dependency and entry checks appear satisfied. It then takes the normal success path. Files may have been written before profile reconciliation, before loading, or before rollback completes.

The entry checker additionally [returns `{ name, missing: null }` when installed metadata cannot be read or parsed](https://github.com/dshplugin/dsh-plugin-hub/blob/f17814f949604a727c708accf10f2b68cdfa63bd/src/server/services/install/task-queue.ts#L730-L742). Its `missing: null` value therefore conflates “checked and complete” with “unable to check.” Unreadable patch text is also silently excluded. This is a source-level proof of an insufficient success predicate, not a reproduced instance from a reporter's machine.

A repair must retain timeout/exit/cleanup evidence and represent filesystem verification as `complete`, `incomplete` or `unknown`. Dependency presence cannot upgrade a cancelled or timed-out operation to success. Any separate reconciliation/recovery operation must record its own result.

## 4. Issue 101 remains unassigned to a concrete lifecycle cause

Hub's [spawn path](https://github.com/dshplugin/dsh-plugin-hub/blob/f17814f949604a727c708accf10f2b68cdfa63bd/src/server/services/install/task-queue.ts#L555-L607) has a total timeout and a grace period after `exit` while waiting for `close`. The historical [DSH implementation](https://github.com/deepseek-ai/deepseek-harness/blob/dd6322d604e00eec1ba5e0c8541159906a21094a/apps/cli/src/plugin.ts#L131-L149) synchronously invokes pnpm, then reconciles profile bundles on exit 0. Those boundaries give at least three distinguishable hypotheses:

| Hypothesis | Required observation to distinguish it | Repair owner if confirmed |
| --- | --- | --- |
| pnpm printed `Done` but its process/worker did not exit | pnpm process status and owned handles after that line; DSH still waiting on pnpm | pnpm/runtime owner, then DSH's supported version selection |
| pnpm exited but DSH reconciliation/lock/commit did not finish | pnpm exit recorded, DSH commit stage not completed | DSH plugin manager |
| DSH exited but an owned descendant kept stdout/stderr open | direct-child exit recorded before pipe close, identified pipe owner | launcher and originating descendant owner |

The included bounded Node fixture demonstrates only the third mechanism's feasibility. It must not be cited as the root cause of issue 101. The reported pnpm version is newer than the historical DSH source snapshot and must be reproduced as reported, rather than replaced with whichever version is currently installed. Later success from another invocation does not establish environment equivalence.
