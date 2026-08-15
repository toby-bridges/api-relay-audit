# Release Policy

API Relay Audit uses a manual release-prep PR plus a manual draft-release
workflow. PR labels declare release intent; they do not bump `VERSION`
automatically in Phase 1.

## Version Source

- `VERSION` is the only manual version source and must use
  `MAJOR.MINOR.PATCH` without a leading `v`.
- User-facing audit reports use a display version derived from `VERSION`:
  `2.3.0` displays as `v2.3`, while `2.3.1` displays as `v2.3.1`.
- Versioned skill downloads use the full release tag, for example `v2.3.0`.
- Run `python3 scripts/sync-version.py` after changing `VERSION`, then
  regenerate the standalone artifact with `python3 scripts/build-standalone.py`.

## PR Release Labels

Every pull request must carry exactly one of these labels:

| Label | Meaning |
| --- | --- |
| `release:patch` | Bug fix, false-positive/false-negative repair, documentation correction, or compatibility fix that does not change public audit semantics. |
| `release:minor` | New detector, new audit step, new profile capability, new public workflow, or meaningful release/distribution improvement. |
| `release:major` | Breaking CLI, report schema, risk-matrix, distribution, or compatibility change. |
| `release:none` | No user-facing release impact, such as CI-only maintenance or internal cleanup. |

Use the highest applicable label when a PR spans multiple categories.

## Release Prep

Before running the draft-release workflow:

1. Update `VERSION` in a release-prep PR.
2. Run `python3 scripts/sync-version.py`.
3. Run `python3 scripts/build-standalone.py`.
4. Run `python3 scripts/collect-metrics.py` and sync public test counts if they changed.
5. Confirm the expected release notes file exists:
   - `docs/releases/vX.Y.md` for `X.Y.0`
   - `docs/releases/vX.Y.Z.md` for patch releases

The release workflow validates and creates a draft GitHub Release. It must not
edit `master`; source changes belong in the release-prep PR.

Run the draft-release workflow only from `master` after the release-prep PR is
merged. If versioned skill or release docs now point at a new tag such as
`v2.3.0`, create the draft release immediately after merge so the immutable tag
exists before users follow those download commands.

## Standalone Artifact Provenance

Each release has one authoritative standalone artifact: `audit.py` at the
release tag. The GitHub Release asset `audit.py` must be byte-identical to that
tagged file, and `audit.py.sha256` must be the SHA-256 digest of the uploaded
asset.

The draft-release workflow enforces this after creating or resuming the draft
release:

```bash
python3 scripts/verify-release-artifact.py --tag vX.Y.Z --source-ref <release-commit>
```

The verifier checks all three links in the chain:

1. `git show <release-commit>:audit.py` while the release is draft, and
   `git show vX.Y.Z:audit.py` after publication
2. the generated standalone artifact for the checked-out source
3. the downloaded GitHub Release `audit.py` and `audit.py.sha256` assets

If any byte differs, the release is not reproducible and must not be published.
Do not manually replace release assets to paper over drift. Fix the source and
regenerate `audit.py`. A rerun may replace assets only when the existing release
is still a draft targeting the exact same commit. Published releases, draft
target mismatches, and orphaned tag-only states fail closed and require explicit
maintainer recovery.
