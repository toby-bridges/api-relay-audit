# DSH npm consumer acceptance

This suite consumes an unpublished npm tarball through the real DSH
`0.1.7-rc.2` CLI and its Loader/commands service. It does not publish npm
packages, open a browser, contact a real model API, or read the user's DSH
home, npm credentials, or environment credentials.

```sh
npm run verify:package -- --output-dir /tmp/npm-candidate
node --test scripts/dsh-acceptance/*.test.mjs
node scripts/dsh-acceptance/run.mjs \
  --package-dir /tmp/npm-candidate \
  --artifacts /tmp/dsh-acceptance-evidence
```

Use Node `22.19.0` (the CI pin) or another version admitted by `package.json`.
The runner normally finds npm beside Node. `--npm-cli /absolute/npm-cli.js`
supports an independently unpacked Node binary during local investigation.
`--tarball /absolute/candidate.tgz` can replace `--package-dir` for a tarball
without the packaging manifest. CI always uses the manifest and checks its SRI.

The workflow builds one candidate on Ubuntu and downloads that exact candidate
on Ubuntu and Windows. Candidate bytes, package name/version and SHA-512 SRI
come from the tarball and packaging manifest. The installed `audit.py`,
adapter and bundle patch must match the candidate bytes. Neither job rebuilds
the candidate during consumption.

The runner creates a new home, profile, npm configuration/cache, pnpm store,
and working directory with spaces. Bootstrap installs the pinned pnpm
`11.7.0`, DSH CLI, and real DSH service packages while Git is available. It
then restricts PATH to explicit Node/pnpm/Python/curl tools (plus required
Windows system tools) and requires `git` to fail with `ENOENT` before any
candidate lifecycle operation. This proves the plugin's registry distribution
does not require Git; it does not claim the host's own bootstrap never needs
Git.

The candidate registry and chat endpoint listen on `127.0.0.1` only. The
registry serves one exact candidate; it permits metadata reads from the fixed
public npm registry only for package names already present in the isolated
bootstrap dependency closure. It never forwards request headers or credentials.
Unknown package names remain 404. The API fixture accepts only its fixed
synthetic credential, fixed Claude fixture model, eight-token connectivity
requests, and the exact connectivity prompt. No provider is configured for
an external model endpoint.

Acceptance requires real CLI exit and closed output pipes, committed profile
bundle metadata, discovery through the real commands service, `/relay-audit
--help`, and both connectivity formats through the installed standalone
Python program. A nonexistent-version install must fail and preserve the
installed candidate; retrying the exact candidate must work. The suite also
holds a real registry metadata response, cancels the actual CLI process tree,
checks the previously observed PIDs have all exited, checks the original
manifest/lockfile bytes and command remain usable, and retries. It then
performs an idempotent fixed-version update, repeats command invocation, removes
the package, and verifies the real Loader no longer registers its command.
This update does not stand in for compatibility with an unbuilt future release.

Lifecycle hooks are admitted by exact package/version only: Koffi `3.1.1`
and `3.3.3` local-prebuild loaders, node-pty `1.2.0-beta.15` prebuild/fallback
and post-install steps, protobufjs `7.6.6` post-install, `@google/genai`
`1.52.0`'s no-op preinstall, and DSH subprocess-local `0.1.7-rc.2`'s packaged
spawn-helper permission repair. A new lifecycle hook fails installation and
requires source review before changing this list. Scripts are not globally
disabled and missing builds are not treated as successful installations.

`events.jsonl` records each phase, direct child PID, real exit, pipe close,
deadline and cleanup attempt. `summary.json` records assertions and failures;
sanitized stdout/stderr and isolated dependency lockfiles remain available on
failure. Deadlines and package errors remain failures even if files exist or
pnpm printed `Done`. A Windows taskkill attempt after a parent exited cannot
prove orphan cleanup and is explicitly recorded as unconfirmed. A failed run
retains its temporary root for investigation; it never deletes a directory
that might still have a writer. Successful runs remove their temporary root
after every phase closes, unless `--keep-temp yes` is explicitly requested.

This is headless host integration evidence. It does not cover browser command
rendering, the Windows environments reported in issues #99/#101/#103, or the
root cause of the historical `Done`-then-timeout report. The separate
`scripts/dsh-evidence` suite preserves those evidence boundaries.
