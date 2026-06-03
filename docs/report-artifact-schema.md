# Report Artifact Schema

This is the draft data contract for public, redacted API Relay Audit report
artifacts. It is intended to support documentation examples today and a future
user-submission page later.

It is not a required JSON output format for `audit.py` yet. The current CLI
continues to write Markdown reports.

`report-artifact-v0.1` is a draft documentation and fixture contract only. No
backward compatibility or CLI JSON output is promised until an explicit v1
schema and implementation ship.

## Design Goals

- Preserve the difference between `clean`, `anomaly`, `inconclusive`, and
  `informational`.
- Preserve the difference between a step that ran and a step that was skipped
  or profile-gated.
- Keep public examples safe to publish.
- Make future user submissions reviewable before they appear on any public
  surface.
- Avoid treating an audit report as a safety certificate.

## Artifact Shape

```yaml
schema_version: report-artifact-v0.1
tool_version: v2.3
profile: general | web3 | full
target_host_redacted: example.invalid
overall_rating: LOW | MEDIUM | HIGH
generated_at: 2026-06-02T00:00:00Z
fixture_source: deterministic fixture | local audit | user submission
steps:
  - step_number: 1
    step_name: Infrastructure recon
    step_status: run | skipped | profile_gated | not_applicable
    verdict: clean | anomaly | inconclusive | informational
    severity: none | low | medium | high
    summary: Short human-readable finding.
    evidence_redacted: Public-safe evidence excerpt.
redaction_notes:
  - no real API keys
  - no real relay domains
  - no private traffic
submission_compatibility:
  intended_for_future_submission_page: true
  public_safe_example: true
```

## Field Notes

| Field | Required | Notes |
| --- | --- | --- |
| `schema_version` | yes | Version this schema independently from the CLI. |
| `tool_version` | yes | Audit tool version, such as `v2.3`. |
| `profile` | yes | One of `general`, `web3`, or `full`. |
| `target_host_redacted` | yes | Use `example.invalid` for public fixtures. |
| `overall_rating` | yes | One of `LOW`, `MEDIUM`, or `HIGH`. |
| `generated_at` | yes | ISO-8601 UTC timestamp. |
| `fixture_source` | yes | Describes whether the artifact is a fixture, local audit, or submission. |
| `steps` | yes | Ordered audit findings. |
| `step_status` | yes | Records whether a step ran; skipped/profile-gated steps must not be rendered as clean. |
| `redaction_notes` | yes | Must explain why the artifact is public-safe. |
| `submission_compatibility` | yes | Marks whether the artifact can seed future submission UI tests. |

## Public Safety Rules

Public artifacts must not contain:

- Real API keys or key prefixes.
- Bearer tokens.
- Private relay domains or private URLs.
- Wallet seed phrases, private keys, signed transactions, or raw wallet traffic.
- Raw request or response captures containing user traffic.
- Relay rankings, recommendations, or safety certifications.

## Compatibility Boundary

The fixture in `docs/examples/sanitized-audit-report.fixture.json` follows this
schema and can seed future UI and submission-page tests.
Future schema revisions should preserve existing public-safety rules even when
new fields are added.
