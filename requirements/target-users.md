# Target Users

## Segment A: Relay users

### Job to be done

Before routing coding-agent, production, or sensitive traffic through a third-party relay, determine whether the relay exhibits behavior that warrants further investigation.

### Questions

- Can I trust this relay enough to test it further?
- Does it appear to inject hidden instructions?
- Does it truncate context or rewrite tool output?
- Are model-identity signals inconsistent with the claim?
- What does `clean`, `anomaly`, or `inconclusive` mean?

### Success condition

The user can install the tool, run an audit, understand the evidence boundary, and choose an appropriate next action.

## Segment B: Relay operators

### Job to be done

Use reproducible tests to find compatibility, integrity, and transparency problems and respond responsibly to user-submitted audit evidence.

### Questions

- Why do users distrust the relay?
- Which failures are compatibility issues versus security signals?
- How should an operator respond to a report?
- How can a fix be reproduced and verified?
- How can transparency improve without claiming certification?

### Success condition

The operator can reproduce a finding, understand what the report does and does not prove, and document a corrective response.

## Trust conflict

The project serves both users and operators, but testing rules, risk thresholds, evidence wording, and publication decisions must remain independent of operator commercial interests.

API Relay Audit does not sell or imply safety certification. Operators may contribute reproductions, compatibility fixes, documentation, and sanitized evidence, but they cannot purchase favorable findings.
