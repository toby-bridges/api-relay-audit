# Proposed Hub / DSH repair contract

Status: design proposal prepared for owner review; no upstream implementation or communication is included.

## Responsibilities and sequence

1. API Relay Audit supplies one exact-version npm artifact with all runtime files, an allowlist, integrity evidence, no install-time build and no mandatory Git dependency. The same packed bytes must be used in acceptance and publication.
2. DSH records the package-manager invocation, real exit, profile reconciliation/commit result, and whether its operation is final. It preserves the original failure category and does not generate a build-policy hint from the source URL alone.
3. Hub launches and cancels the owned process tree, records `exit` separately from pipe `close`, consumes the DSH result, then records plugin activation independently. It does not replace failure evidence because files exist.
4. Reproduce issue 101 on the reported Windows combination. Repair the component demonstrated to own the hang. Adopt an upstream worker-lifecycle fix if pnpm is responsible; a larger timeout does not satisfy this gate.

## Machine-readable operation result

A versioned JSON result on a dedicated result file/IPC channel avoids mixing human logs with control data. Logs remain logs. The channel must be created inside the private operation directory and written atomically, with no secrets or raw environment dump. This is a proposed minimum schema, not a current DSH API:

```json
{
  "schema": "dsh-plugin-operation-v1",
  "operationId": "opaque-per-operation-id",
  "action": "add",
  "package": "dsh-api-relay-audit@EXACT_VERSION",
  "packageManager": { "exitCode": 0, "signal": null, "completed": true },
  "profile": { "reconciled": true, "committed": true },
  "result": "installed",
  "cause": null
}
```

The launcher separately records `childExitCode`, `childSignal`, `exited`, `pipesClosed`, `timedOut`, `cancelled`, `cleanupComplete`, and `artifactVerification`. The Hub loader records `activation: loaded | restart-required | failed | unknown`. This keeps the DSH process exit independent from the npm process exit and makes a missing final result observable.

An operation is successfully **installed** only after the package manager exits 0, the profile is committed, required metadata/entries verify as complete and DSH returns a matching final result. A plugin is **ready** only after activation succeeds; `restart-required` remains visible until loading is verified. A nonzero exit, cancellation, deadline, missing final result or unresolved writer cannot be reclassified as success. A completed install followed by launcher cleanup failure remains a distinct degraded outcome with both facts preserved.

Older DSH versions without the result channel use a conservative compatibility path: record actual process and pipe events, check metadata as tri-state, and keep ambiguous completion `unknown`. Log parsing may select explanatory text; it cannot certify a missing commit or final result.

## Error taxonomy and regression rules

| Observable evidence | Cause / advice | Do not infer |
| --- | --- | --- |
| Git `CONNECT tunnel failed, response 502` | Network/proxy failure; report the failing fetch stage and status | Build script failed; package is incomplete |
| `` `git` executable not found ``, `spawn git ENOENT`, or a Git-specific shell lookup failure | Git unavailable for a Git source; npm source removes that source dependency | DSH itself missing; allow builds |
| `ERR_PNPM_GIT_DEP_PREPARE_NOT_ALLOWED` / `ERR_PNPM_IGNORED_BUILDS` | Build policy rejection; identify exact blocked package key | Every Git failure is policy denial |
| A lifecycle script actually starts and fails with an exit code | Build/lifecycle failure, preserving script and stage | Every `Command failed` wrapper is a build |
| Total deadline expires after `Done`, absent final result | Timeout; preserve stage and process/pipe facts | Installed or ready because package files exist |
| Package or patch metadata unreadable | Artifact verification unknown, with bounded safe detail | No required files; verified complete |

Specific, causally relevant error evidence takes precedence over generic wrappers. Explicit build-policy rejection still remains specific evidence when a log also contains unrelated retry warnings. `ERR_PNPM_GIT_RESOLVE_FAILED` alone is not enough to distinguish missing Git, network failure or invalid repository.

## Process ownership, cancellation and atomicity

Use an operation-specific lock and record which process/tree owns the write. Cancellation or deadline starts bounded tree termination and a cleanup check. Preserve the real exit/signal; do not substitute 0. A queue must not start another writer on that profile while cleanup is incomplete. On Windows, exercise the real launch entry and supported process-tree control rather than assuming POSIX process-group behavior.

An update stages and validates the new dependency/profile before commit; interruption leaves the previous usable profile or an explicit recovery state. Recovery is an observable, separately identified operation. File presence is a diagnostic observation, not the commit protocol. Increasing timeout, killing the direct child alone, unconditional `allowBuilds`, and declaring success from `Done` or files do not meet this contract.
