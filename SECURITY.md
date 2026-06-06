# Security Policy

API Relay Audit is a local security audit tool for third-party AI API relays
and LLM proxies. This policy covers vulnerabilities in this repository, not
findings about relay operators.

## Supported Version

Until the first tagged release, the supported line is the current `master`
branch. After tagged releases begin, the supported lines are the current
`master` branch and the latest published release. Older snapshots may be useful
for comparison, but security fixes land on `master` first.

## Reporting a Vulnerability

If you find a vulnerability in API Relay Audit itself, use GitHub private
vulnerability reporting when it is enabled for this repository.

If private vulnerability reporting is not available, open a minimal public
issue only with non-sensitive reproduction details. Do not include secrets,
private relay details, API keys, wallet material, or raw traffic captures in a
public issue.

Please include:

- The affected file, command, or workflow.
- A minimal reproduction that does not expose real API keys.
- Whether the issue affects the standalone `audit.py`, the modular package, or
  both.
- Any evidence that a report could leak credentials, send traffic to an
  unintended host, or misclassify an unsafe relay as clean.

Do not include live credentials, private relay URLs, wallet seed phrases,
private keys, or user traffic captures.

## Which Path To Use

Use the public evidence path for redacted relay audit evidence:

- Use the `Submit Audit Evidence` issue template.
- Include only sanitized screenshots, redacted report artifacts, hashes,
  provider/profile metadata, and reproducible non-sensitive summaries.
- Do not include API keys, raw headers, full response bodies, wallet material,
  private relay traffic, or user data.

Use the operator response path when you operate the relay being discussed:

- Use the `Operator Response` issue template.
- Prove domain control as requested by the template.
- Keep remediation notes public-safe and avoid posting secrets or private user
  traffic.

Use private vulnerability disclosure for sensitive issues:

- API key exposure caused by this repository or its workflows.
- A bug that can redirect audit traffic to an unintended host.
- A redaction failure involving raw response bodies, request headers, wallet
  material, or user data.
- A reproducible issue where this tool marks an unsafe or inconclusive state as
  clean.

## Scope

In scope:

- Credential leakage caused by this tool.
- Incorrect redaction or unsafe report handling.
- A bug that silently changes the target relay URL.
- A bug that marks an inconclusive or anomalous audit step as clean.
- Drift between the standalone and modular distributions that changes audit
  behavior.

Out of scope:

- A relay operator's behavior unless it demonstrates a bug in this tool.
- Requests for relay recommendations or rankings.
- Vulnerabilities in upstream AI providers.
- Results from modified forks that do not match this repository.

## Audit Findings Are Not Certifications

API Relay Audit reports evidence from local probes. A `LOW` result is not a
certificate that a relay is safe, and an `inconclusive` result is not clean.
Use the report as one input to a broader security review.
