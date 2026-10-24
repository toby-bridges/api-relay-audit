# DSH npm Distribution Preparation

This change prepares a registry distribution. It does not publish an npm
package, create a release, update a directory, or establish ownership of an npm
name. Keep the existing immutable Git installation instructions available until
the registry package has been published and independently checked.

## Candidate and source

`VERSION` remains the version source. This preparation does not choose the next
release version or replace the published GitHub release. The release-prep PR
must synchronize versions before an eventual publication.

Run from a clean checkout of the candidate commit:

```text
npm run test:dsh
npm run verify:package
```

The verifier packs the real npm tarball, inspects every member, compares runtime
files with the checkout, imports the extracted adapter, and runs the extracted
standalone Python help command. Preserve the tarball and its machine-readable
manifest together. Verification must fail if an unexpected file, missing
runtime file, lifecycle hook, version mismatch, or changed standalone artifact
is found.

By default the verifier creates a temporary candidate directory and prints its
manifest path. For retained CI artifacts, pass `--output-dir` followed by a new
directory outside the checkout. The verifier refuses to overwrite an existing
candidate or put generated output among the source files.

The consumer package remains prebuilt and has no install/build lifecycle
scripts. Its runtime requirements are Node.js, the compatible DSH services,
Python 3, and curl. Installing this plugin from a registry does not require Git;
installing the DSH host and its other plugins may have different requirements.

## Acceptance before publication

The `DSH npm package acceptance` workflow consumes the candidate tarball through a
loopback npm registry. It does not use a published copy or `plugin add .`.
The registry serves the exact package version and tarball integrity from the
candidate. One Ubuntu job builds it; Windows and Ubuntu consume the same
uploaded bytes and integrity. Other host dependencies come from the public npm
registry during the isolated host bootstrap.
If pnpm rechecks metadata during plugin installation, the fixture permits only
the already bootstrapped public dependency names and reads their metadata from
`registry.npmjs.org` without forwarding incoming headers. Unknown packages and
arbitrary upstream URLs are rejected.

The acceptance record must distinguish:

1. host/toolchain bootstrap;
2. plugin installation with Git unavailable;
3. package bytes and profile configuration;
4. a real DSH loader and command registry in a headless service harness;
5. help and connectivity against a loopback API with a synthetic credential;
6. update and removal, including absence of the plugin after removal;
7. child exit, output closure, timeout, and cleanup observations.

The candidate suite also rejects a nonexistent version and cancels a real
metadata request. Both cases must preserve the original manifest/lock bytes
and the old command before retry. Cancellation records the owned DSH/pnpm
process IDs and independently checks that those observed processes exited.
This covers the controlled metadata boundary; interruption during a profile
commit remains a separate upstream repair gate.

Windows acceptance requires a successful run on a real Windows runner. Linux
or macOS checks, adapter mocks, and the existence of files cannot substitute
for it. A required restart and an unsuccessful runtime load must remain visible
in the result. Timeout must never become a fabricated successful exit code.
The headless check proves the official loader, command service and installed
adapter path; browser rendering and a manual Web UI interaction remain outside
its claim.

Each run uses an independent DSH home, profile, npm cache and pnpm store, and a
path containing spaces. No existing user profile or production relay credential
is used. Uploaded evidence must exclude environment dumps, authorization
headers, request bodies, and private reports. Record versions, source commit,
candidate digest, stage results and sanitized diagnostics instead.

The [upstream evidence package](./dsh-root-cause/README.md) tracks issues #99,
#101 and #103 separately. A successful npm acceptance run does not prove that
the reporter's historical #101 environment has been reproduced or repaired.

The [2026-10-24 acceptance receipt](./dsh-npm-acceptance-2026-10-24.json)
records the exact tested PR head, integration commit, candidate integrity and
successful Windows/Ubuntu results. Its evidence is scoped to those identities;
future releases require acceptance of their own exact candidate.

## Publication approval checklist

Publication remains a separate manual action after PR review and merge:

- confirm package-name ownership and the exact approved version;
- complete release preparation under [the release policy](../release-policy.md);
- verify Windows and Linux results for the exact candidate being released;
- review all tarball members and source/digest metadata;
- obtain explicit approval for npm publication and any account authorization;
- publish the already verified tarball, then compare registry integrity and
  downloaded bytes with that candidate;
- verify a fresh fixed-version install from the public registry;
- obtain approval before directory changes, issue replies, or announcements.

Once publication is verified, the intended installation form is
`dsh plugin --profile web add dsh-api-relay-audit@<approved-version>`.
Do not advertise that command as available before the registry check passes.
Directory metadata must identify this exact package and repository, rather
than depend on a repository search or an implicit Git fallback. Discovery,
first installation, and upgrades of existing profiles are separate checks.

No workflow in this preparation publishes to npm. Trusted publishing may be
configured later after separate account authorization; no long-lived write
token is needed in this PR.
