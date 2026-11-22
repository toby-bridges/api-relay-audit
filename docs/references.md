# References

API Relay Audit keeps its core references intentionally small. These papers are
the main research anchors for the current audit model.

## Core Papers

| Paper | Why it matters here |
| --- | --- |
| Liu et al., [*Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the LLM Supply Chain*](https://arxiv.org/abs/2604.08407), arXiv:2604.08407, 2026. | Defines the malicious intermediary / LLM API router threat model behind prompt injection, dependency-targeted injection, conditional delivery, and secret exfiltration checks. |
| Zhang et al., [*Real Money, Fake Models: Deceptive Model Claims in Shadow APIs*](https://arxiv.org/abs/2603.01919), arXiv:2603.01919, 2026. | Motivates model-identity and shadow-API audit questions for third-party API relays that claim to provide official frontier models. |

## Relay measurements

In *What the Middleman Delivers* (2026), Wu et al. cite API Relay Audit in §III-C, reference [35]. The authors compared 20 services against official endpoints. Their sample was selected by access, language and payment criteria, and requests originated in the United States. Use the findings below to design and interpret local measurements. [Paper and supplementary material](https://arxiv.org/html/2611.07650v1)

| Observation in the paper | Implication for the audit |
|---|---|
| Four services returned 30 calls under explicit suppression in round one. Another returned two search-call records with no declared tools. Neither pattern recurred in round two (§V-E). | Record the request’s permission, the returned structure and the attempt count. Execution, retrieval and the responsible component remain unknown. |
| Five services reported thousands of extra input tokens on matched requests. Six exposed balances and only R11 belonged to both groups (Table VI and Table S3). | Compare categories with a matched official request. Verify charges separately using a price schedule and balances bracketing collection. |
| Review confirmed zero injections in 3,332 responses to benign coding and setup requests. An early parser mistook shell continuations and requirements-file arguments for packages (§V-C, supplement §V). | Review candidates with their prompt, official response and parser version. Keep screening hits and confirmed additions in separate counts. |
| R19 sent SSE to a non-streaming request. R15 returned a refusal through a translated content-filter field (§V-E). | Record protocol mismatches and parse failures with their own denominators. Count a recognizable refusal explicitly and report sensitivity to its scoring. |
| After 11–18 days, seven of 35 retested pairs gained or lost a behavioral flag. A common multiple-testing correction reduced this count to six. The primary price-group comparison gave p = 0.07 (§V-B, §V-D). | Repeat identical requests against fresh references and report sampling and scoring choices. These comparisons leave backend identity and a population price effect unresolved. |

The authors released anonymized aggregates and selected analysis inputs. Full responses, annotations and the complete question bank remained private (§VII). Independent recomputation is possible for specific aggregate results. New field collections need their own provenance, selection rules, and scope. [Evidence and data availability](https://arxiv.org/html/2611.07650v1#:~:text=The%20accompanying%20data%20contain) · [Project measurement waves](../ROADMAP.md#measurement-pr-waves)

## Citation

Use [CITATION.cff](../CITATION.cff) to cite API Relay Audit itself. Cite the
papers above directly when relying on their methods, findings, or threat models.
