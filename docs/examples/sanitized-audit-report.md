# Sanitized API Relay Audit Report

This is a sanitized fixture-style example, not a real relay result.

It is built from `docs/examples/sanitized-audit-report.fixture.json` and follows
the draft report artifact schema in `docs/report-artifact-schema.md`. It is
intended to show the shape of a local API Relay Audit report without exposing
real relay domains, API keys, wallet material, or private traffic.

## Report Artifact

| Field | Value |
| --- | --- |
| Schema version | `report-artifact-v0.1` |
| Tool version | `v2.3` |
| Profile | `full` |
| Target host | `example.invalid` |
| Overall rating | `MEDIUM` |
| Generated at | `2026-06-02T00:00:00Z` |
| Fixture source | Deterministic fixture, not a live relay result |

## Risk Summary

- Overall verdict: `MEDIUM`
- Prompt injection: synthetic hidden-token delta shown as an anomaly.
- Prompt extraction: one synthetic extraction result is shown as an anomaly.
- Context length: inconclusive, not clean.
- Tool-call rewriting: clean in this fixture.
- Error leakage: redacted internal path leak shown as an anomaly.
- SSE anomalies: clean in this fixture.
- Web3 wallet checks: clean in this fixture.
- Upstream channel classifier: inconclusive, not clean.

## Step Findings

| Step | Area | Verdict | Severity | Summary |
| --- | --- | --- | --- | --- |
| 1 | Infrastructure recon | `informational` | `none` | The target host is redacted to `example.invalid` for public documentation. |
| 2 | Model list enumeration | `informational` | `none` | The relay returned a small synthetic model list in the fixture. |
| 3 | Token injection detection | `anomaly` | `medium` | Expected 38 input tokens; observed 146 input tokens; delta +108 tokens. |
| 4 | Prompt extraction | `anomaly` | `medium` | 1 of 6 extraction probes produced fixture-only hidden instruction wording. |
| 5 | Instruction conflict and identity | `clean` | `none` | No non-claimed model identity markers are present in this fixture step. |
| 6 | Jailbreak extraction | `clean` | `none` | Jailbreak extraction responses are synthetic refusals. |
| 7 | Context length | `inconclusive` | `medium` | Canary recall was interrupted before the boundary could be established. |
| 8 | Tool-call rewriting | `clean` | `none` | Package-command echoes match expected fixture text. |
| 9 | Error response leakage | `anomaly` | `medium` | Synthetic error body includes `/redacted/internal/path` and no credentials. |
| 10 | SSE stream integrity | `clean` | `none` | Event whitelist, usage monotonicity, and signature-presence checks pass. |
| 11 | Web3 wallet prompt injection | `clean` | `none` | Transfer guidance, signed-transaction, and private-key probes produce fixture-safe refusals. |
| 12 | Infrastructure fingerprint | `informational` | `none` | Framework family is synthetic and informational only. |
| 13 | Latency variance | `informational` | `none` | Synthetic latency values are intentionally non-operational. |
| 14 | Upstream channel classifier | `inconclusive` | `medium` | Channel markers are omitted; this is recorded as inconclusive rather than clean. |

## What This Example Shows

This fixture demonstrates how API Relay Audit separates:

- `clean`: the probe did not find an anomaly in this fixture.
- `anomaly`: the fixture includes reviewable evidence for a suspicious result.
- `inconclusive`: the fixture could not prove clean or anomalous behavior.
- `informational`: the step records context without changing the safety verdict.

## What This Example Does Not Prove

- It does not certify any relay as safe.
- It does not rank or recommend relay providers.
- It does not represent a live audit of a real relay.
- It does not replace a local audit against the relay URL you choose.

## Redaction Notes

- No real API keys are included.
- No real relay domains are included.
- No private traffic is included.
- The target host is `example.invalid`.
- All findings are deterministic fixture data.

## Future Submission Page Compatibility

This example is intentionally schema-first. The fixture JSON can seed future
submission-page tests, while the Markdown report gives README and Pages readers
a public-safe 30-second view of the report shape.

