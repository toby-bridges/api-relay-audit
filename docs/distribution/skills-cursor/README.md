# skills.sh and Cursor Directory — approval packet

Status: **local candidate; not published or submitted**. Prepared 2026-10-22.

## Candidate

- Repository: [toby-bridges/api-relay-audit](https://github.com/toby-bridges/api-relay-audit).
- Frozen starting point: `390de58b83f8e3a7b6c54944c78eae286238dbf5`.
- Branch: `codex/skills-cursor-preparation`.
- Engine: released v2.5.0, unchanged; SHA-256
  `fd99409bf745090a26bb4616fd33fbe0d873de08cfe077df413b2b93845f151d`.
- Changed distribution surface: root and nested SKILL.md share a neutral,
  self-contained body while retaining their OpenClaw/Hermes metadata.
- Commands now pass the credential environment-variable name, verify the
  engine hash, preserve the report's existing risk rating, and keep raw reports
  local. This does not change detection rules, the CLI, DSH, or licensing.
- The original dirty checkout is outside this worktree and was not edited.

## Review files

- [skills.sh installation copy](skills-sh.md)
- [Cursor Directory field draft](cursor-directory.json)
- [Cursor submission procedure](cursor-directory.md)
- [Machine-readable local evidence](verification.json)
- [Reproducible integration check](verify-local.py)
- [Pinned upstream detector replay](verify-cursor-detector.mjs)

The Cursor JSON is proposed form content, not a request sent to the service.
It contains only public project copy and the reviewed Skill instructions.

## Verification

The real `skills@1.7.4` CLI was staged in a temporary directory with dependency
install scripts disabled. Checks use project-local installations, telemetry
and security-audit requests disabled, application-level Node networking
blocked, and a curl wrapper permitting only the local fixture endpoint.
This is scoped test instrumentation, not an OS-level network-isolation claim.

The integration verifier discovers one Skill, installs exactly one SKILL.md
into Cursor's documented `.agents/skills/api-relay-audit/` location, lists it,
and loads its complete instructions as a prompt without starting a model.
The installed recipe invokes the real released engine against a synthetic
loopback relay. Both protocol paths succeed, credentials stay out of curl
arguments and the JSON report, and connectivity remains unrated.
The hash-verification recipe also rejects an altered engine.

Cursor Directory's exact detector source is replayed against the candidate
tree. It detects the nested Skill, strips its frontmatter, and preserves the
whole neutral body. The shared-body assertion protects both discovery paths.

See `verification.json` for exact counts, tool versions, input hashes, and
command exit codes. Temporary test installations are removed at verifier exit.
No user-level Skill installation is created.

### Reproduce

Stage these public inputs into a temporary `TOOLS` directory:

1. Install `skills@1.7.4` there with
   `npm install --prefix "$TOOLS" --ignore-scripts --no-audit --no-fund skills@1.7.4`.
2. Save the two [fixed Cursor detector sources](cursor-directory.md#source-provenance)
   as `$TOOLS/cursor-source/parse.ts` and `slug.ts`.
3. Save the [released engine](https://raw.githubusercontent.com/toby-bridges/api-relay-audit/v2.5.0/audit.py)
   as `$TOOLS/audit-v2.5.0.py`.
4. From the candidate repository, run:

```bash
python3 docs/distribution/skills-cursor/verify-local.py \
  --tools "$TOOLS" --output /tmp/relay-skill-verification.json
python3 -m pytest tests/test_skill_distribution.py tests/test_example_report.py -q
python3 scripts/build-standalone.py --check
git diff --check
```

The verifier needs local loopback-listening permission, Node 22.20+ with
`node:module.stripTypeScriptTypes`, Python 3, curl, and the staged CLI. It does
not download dependencies or submit anything itself. The recorded execution
used Node 25.9.0 on macOS; other operating systems remain unverified.

## Remaining external gates

1. Human review of this candidate, its patch, and the proposed copy.
2. Separate approval before pushing/creating a PR; proposed release impact is
   `release:none`, since the v2.5.0 engine and package versions are unchanged.
3. Review and merge approval before changing the public default branch.
4. Reinstall from the resulting public commit with telemetry disabled, then
   verify bytes and instructions again. Local paths do not prove remote install.
5. Approve account authorization and Cursor Directory submission. Its scanner
   reads repository HEAD and ignores branch/SHA URL suffixes, so submit only
   after the approved files reach the public default branch.
6. Verify the actual hosted listing, scan outcome, and Copy output. For
   skills.sh, real consenting users' installs drive discovery; do not generate
   artificial install counts or promise immediate indexing.

Cursor model selection/automatic activation, paid providers, a full real-relay
audit, Windows/Linux runtime, hosted acceptance, and acquisition impact were
not tested. The tests prove filesystem installation, CLI prompt assembly,
fixed-source detection, and the local connectivity recipe.

## Proposed PR copy

Title: Prepare API Relay Audit for skills.sh and Cursor Directory

Body:

The repository's two Skill entry points currently provide different
host-specific instructions. Default skills CLI discovery selects the root,
while Cursor Directory reads the nested file. Share a neutral instruction
body, retain compatibility metadata, and recommend the explicit Skill
subdirectory to avoid copying the repository into an installation.

Use environment-name credentials and the verified v2.5.0 engine hash, preserve
the engine's risk rating and missing coverage, and retain private evidence
locally. Add local installation evidence and draft submission fields.
The audit engine, DSH integration, package versions, and AGPL-3.0-only license
are unchanged. No directory submission or public listing is included.

Validation: see the recorded integration checks, focused pytest results,
standalone check, and diff check in this packet.
