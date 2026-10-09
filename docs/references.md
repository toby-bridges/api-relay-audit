# References

API Relay Audit keeps its core references intentionally small. These papers are
the main research anchors for the current audit model.

## Core Papers

| Paper | Why it matters here |
| --- | --- |
| Liu et al., [*Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the LLM Supply Chain*](https://arxiv.org/abs/2604.08407), arXiv:2604.08407, 2026. | Defines the malicious intermediary / LLM API router threat model behind prompt injection, dependency-targeted injection, conditional delivery, and secret exfiltration checks. |
| Zhang et al., [*Real Money, Fake Models: Deceptive Model Claims in Shadow APIs*](https://arxiv.org/abs/2603.01919), arXiv:2603.01919, 2026. | Motivates model-identity and shadow-API audit questions for third-party API relays that claim to provide official frontier models. |

## Citation

Use [CITATION.cff](../CITATION.cff) to cite API Relay Audit itself. Cite the
papers above directly when relying on their methods, findings, or threat models.
