# GitHub Actions Integration Example

This example shows how another repository can run API Relay Audit in its own
GitHub Actions runner. It is a downstream integration pattern, not evidence
that any third-party repository has adopted the tool.

Use this when you want a manual workflow that downloads the pinned standalone
`audit.py`, runs a local audit against a relay URL stored in repository
secrets, and records a checksum for the resulting Markdown report.

## Secrets

Create these repository secrets in the downstream repository:

| Secret | Purpose |
| --- | --- |
| `API_RELAY_AUDIT_KEY` | API key for the relay under test. |
| `API_RELAY_AUDIT_URL` | Base URL for the relay, such as `https://relay.example.invalid/v1`. |

Do not put API keys, private relay URLs, wallet material, or raw reports in
workflow logs, issue comments, branch names, or commit messages.

## Workflow

Copy [`examples/github-actions/relay-audit.yml`](../../examples/github-actions/relay-audit.yml)
into the downstream repository as `.github/workflows/relay-audit.yml`.

The workflow is manual (`workflow_dispatch`) and asks for:

- `model`: the model name sent to the relay.
- `profile`: `general`, `web3`, or `full`.
- `upload_private_report`: optional, default `false`. Enabling it uploads the
  raw `report.md` as a private workflow artifact for internal review.

The workflow pins `AUDIT_SCRIPT_REF` to `v2.3.0`. Update that value only after
reviewing the corresponding API Relay Audit release. The workflow downloads
the release asset `audit.py` plus `audit.py.sha256` and verifies the script
checksum before running.

## Report Handling

The workflow does not upload `report.md` by default. It uploads only
`report.md.sha256`, which lets an internal team later prove which private
report was reviewed without exposing report contents.

If `upload_private_report` is enabled, the uploaded `report.md` artifact may
contain private relay metadata depending on the target and findings. Treat it
as private by default.

Before sharing a report publicly:

- replace real relay domains with `example.invalid`;
- remove API keys, bearer tokens, key prefixes, raw headers, and private URLs;
- remove wallet material, signed transactions, and private traffic;
- keep tool version, profile, tested-at time, and step summaries when safe;
- hash the redacted artifact if submitting public audit evidence.

Public reports are evidence from one run under one tool version and profile.
They are not relay recommendations, rankings, certifications, or safety
guarantees.
