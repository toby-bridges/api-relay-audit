# Community Evidence And Feedback

API Relay Audit accepts public input through separate lanes. Keep the lane
boundary clear so users can share useful information without leaking private
relay traffic or turning reports into relay recommendations.

## Local Run Feedback

Use this when the tool was hard to install, confusing to run, or produced an
unclear local report.

- Issue template: [Local Run Feedback](https://github.com/toby-bridges/api-relay-audit/issues/new?template=local-run-feedback.yml)
- Good input: tool version, install method, profile, command shape with secrets
  removed, OS/shell/Python/curl versions, sanitized error text, and a concrete
  improvement suggestion.
- Avoid: relay domains, API keys, raw request or response bodies, wallet
  material, full unredacted reports, or claims that a relay is safe or unsafe.

This lane is not telemetry. It is a user-authored issue for local runtime and
documentation feedback.

## Detector Gap

Use this when a specific audit step appears to miss, overstate, or misclassify
behavior.

- Issue template: [Detector Gap](https://github.com/toby-bridges/api-relay-audit/issues/new?template=detector-gap.yml)
- Good input: affected step, profile, sanitized reproduction, expected result,
  actual result, and why the current classification seems wrong.
- Avoid: private domains, secrets, raw traffic captures, or unredacted reports.

Detector-gap issues can become tests or documentation clarifications, but they
do not publish relay evidence by themselves.

## Audit Evidence Submission

Use this only when you want to submit a redacted, reviewable audit artifact for
maintainer review.

- Issue template: [Submit Audit Evidence](https://github.com/toby-bridges/api-relay-audit/issues/new?template=audit-report.yml)
- Good input: redacted report artifact, report hash, profile, tool version,
  tool commit, tested-at timestamp, step summary, and key findings.
- Avoid: screenshots without artifacts, unhashable claims, secrets, raw headers,
  full response bodies, private relay traffic, or wallet material.

Submitted audit evidence is shape-checked by GitHub Actions. It still requires
maintainer review before any public evidence record is published. A report is
evidence from one run under one tool version and profile; it is not a relay
recommendation, ranking, certification, or safety guarantee.

## Operator Response

Relay operators can use the
[Operator Response](https://github.com/toby-bridges/api-relay-audit/issues/new?template=operator-response.yml)
template to respond to submitted evidence. Operator responses are linked to a
domain only after the requested domain-control proof is supplied.
