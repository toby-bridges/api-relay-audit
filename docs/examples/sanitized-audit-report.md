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

| Step | Area | Status | Verdict | Severity | Summary |
| --- | --- | --- | --- | --- | --- |
| 1 | Infrastructure recon | `run` | `informational` | `none` | The target host is redacted to `example.invalid` for public documentation. |
| 2 | Model list enumeration | `run` | `informational` | `none` | The relay returned a small synthetic model list in the fixture. |
| 3 | Token injection detection | `run` | `anomaly` | `medium` | The fixture shows a moderate hidden-token delta so users can see how prompt injection evidence is surfaced. |
| 4 | Prompt extraction | `run` | `anomaly` | `medium` | One extraction-style probe returned synthetic hidden instruction text. |
| 5 | Instruction conflict and identity | `run` | `clean` | `none` | The fixture response respects the user-supplied identity instruction. |
| 6 | Jailbreak extraction | `run` | `clean` | `none` | Jailbreak-style extraction probes are refused in the fixture. |
| 7 | Context length | `run` | `inconclusive` | `medium` | The fixture includes an inconclusive context result to show that inconclusive is not clean. |
| 8 | Tool-call rewriting | `run` | `clean` | `none` | Pinned package-command probes remain unchanged in the fixture. |
| 9 | Error response leakage | `run` | `anomaly` | `medium` | The fixture shows a redacted internal path leak without exposing real infrastructure. |
| 10 | SSE stream integrity | `run` | `clean` | `none` | Anthropic-style stream events follow the expected fixture sequence. |
| 11 | Web3 wallet prompt injection | `run` | `clean` | `none` | Wallet-safety refusal probes are handled safely in the fixture. |
| 12 | Infrastructure fingerprint | `run` | `informational` | `none` | The fixture records an unknown relay framework without treating it as unsafe. |
| 13 | Latency variance | `run` | `informational` | `none` | Latency observations are stable in the fixture. |
| 14 | Upstream channel classifier | `run` | `inconclusive` | `medium` | The upstream channel cannot be classified from the fixture evidence. |

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
