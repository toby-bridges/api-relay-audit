# Cursor Directory — submission draft

Status: **prepared locally; not submitted**.

Submission page: https://cursor.directory/plugins/new

## Proposed fields

Use [cursor-directory.json](cursor-directory.json) as the field reference.
Choose Auto and paste the repository URL after the approved files are on its
public default branch; review the detected component against the draft.

- Name: API Relay Audit
- Repository: https://github.com/toby-bridges/api-relay-audit
- Homepage: https://apirelayaudit.com/
- Logo: optional; no new logo or upload is required for this draft.
- Component: exactly one Skill, `api-relay-audit`; no MCP claim.

The description is factual project copy, not a safety certification or a
promise of hosted acceptance. The material contains no private report, API
key, personal contact information, or production target.

Current source checks: plugin name is at least two characters, description
at least ten, at least one component, nonempty component name, valid URL
fields, and a slug of at most 80 characters. The observed schema does not
declare a content maximum; hosted request limits remain unverified.

## Source provenance

Cursor Directory source commit:
`e81660652954a089f443d0032afd7de3bea73217`.

- [Parser](https://raw.githubusercontent.com/cursor/community-plugins/e81660652954a089f443d0032afd7de3bea73217/apps/cursor/src/lib/github-plugin/parse.ts)
  SHA-256: `a9c6d9d18c9813e56a8c39e3d67934d025a66e1914ec20d2cc7cc8dfc103d788`.
- [Slug helper](https://raw.githubusercontent.com/cursor/community-plugins/e81660652954a089f443d0032afd7de3bea73217/apps/cursor/src/lib/slug.ts)
  SHA-256: `fea2e12d8af3c8b5332662643288be14c116c6b8627200e4dc9ea3a38ccfa02a`.
- [Submission schema](https://github.com/cursor/community-plugins/blob/e81660652954a089f443d0032afd7de3bea73217/apps/cursor/src/actions/create-plugin.ts).
- [Form](https://github.com/cursor/community-plugins/blob/e81660652954a089f443d0032afd7de3bea73217/apps/cursor/src/components/forms/plugin-form.tsx).
- [Skill copy behavior](https://github.com/cursor/community-plugins/blob/e81660652954a089f443d0032afd7de3bea73217/apps/cursor/src/components/plugins/detail/generic-component-section.tsx).
- [Cursor Skill loading paths](https://cursor.com/docs/skills).

The verifier reads the exact pinned upstream files, verifies their hashes,
replaces only the app-local slug import, and supplies a mocked GitHub tree and
file responses. Upstream code is a temporary verification input, not vendored
project code or an assertion of upstream endorsement.

## Installation and copy boundaries

The detector scans `skills/<directory>/SKILL.md` and discards frontmatter
when creating the displayed Skill component. The page's Copy action returns
the body; it is not a full persistent Skill installation.
The body therefore includes its own prerequisites and execution boundaries.

The real skills CLI installation targets Cursor's documented
`.agents/skills/api-relay-audit/SKILL.md` path. The CLI can list it and print
the full instructions without starting a model. This does not verify a
Cursor model's automatic activation or a native GUI interaction.

Auto detection reads repository HEAD. Appending a branch or commit path to
the repository URL does not make the live scanner inspect that ref.

## After approval

1. Resolve the approved public candidate and independently recheck its bytes.
2. Confirm the signed-in account, approve authorization if required, and
   review the website's detected fields.
3. Submit once; retain the receipt/permalink and scan state.
4. Independently open the listing. Confirm exactly one Skill, its description,
   and the complete Copy output. A submission receipt alone is not acceptance.
5. Record acceptance and installability separately from traffic or stars.

No step above has been executed by this preparation task.
