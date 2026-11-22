# Reproduce relay usage and delivery measurements

## Replay the published bill

Wu et al. report usage for 188 Astra and 185 Opus calls in their second collection at the anonymized service R11. The [CSV](wu-2026-r11.csv) transcribes the eight category totals and historical prices from supplementary Table S3. The authors report a collection-wide deduction of $1.2011. Data source: [*What the Middleman Delivers*, arXiv:2611.07650v1, supplementary §VI, Table S3](https://arxiv.org/html/2611.07650v1#:~:text=R11%20Usage%20and%20Charge%20Reconciliation). [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

From the repository root, run:

```sh
python3 scripts/experiments/replay_relay_measurements.py billing docs/measurements/wu-2026-r11.csv --deduction-usd 1.2011
```

Multiplying each category's tokens by its own USD rate per million yields $0.39640320 for Astra and $0.80467075 for Opus. Their sum, $1.20107395, differs from the reported deduction by $0.00002605. Both the usage and the deduction came from the endpoint. The calculation verifies the authors’ arithmetic. The actual input processed upstream remains unknown.

Table VI illustrates why the units matter. The authors counted 30 returned records at four services under explicit tool suppression in round one, including 24 at R11. They counted two search records at another service with no declared tools. The second round produced zero returned calls. The records include failed attempts, and the researchers did not execute them. This motivates recording attempts, response coverage and returned call counts independently. [Study §V-E, Table VI](https://arxiv.org/html/2611.07650v1#:~:text=Observed%20tool%20calls).

## Collect a matched field sample

This protocol is for a future project measurement. Record the audit commit, UTC windows, model snapshot or advertised alias, API format, request templates, generation settings, budget and planned trial count before collecting. Keep official credentials confined to the official account or a locally controlled forwarder configured for it. Use the relay's own credential on the authorized relay endpoint.

1. Freeze a manifest of cases and trials. Use one file per protocol, model and configuration. In each time window, send the same cases to two independent groups of official requests (`official_a`, `official_b`), a locally controlled transparent forwarder (`transparent`) and the measured service (`relay`). Interleave the arms. Include benign cases with a forced inert tool, a declared but disabled tool, and no declared tools. Record structured calls without executing them. Preserve the request settings and manifest for the next window.
2. Give each scheduled slot a single recorded outcome. Disable automatic retries for this design. Mark transport failures, unparseable replies and missing attempts separately. A valid refusal is a response. A tool-only completion counts as an answer for delivery coverage. When a response carries observable structured calls, retain their count even if it fails answer parsing. Zero means the tool fields were inspected and yielded zero records.
3. Export only these columns. Keep hostnames, raw content, headers, keys and full traffic out of the public file. Check the exported block keys against the frozen manifest to catch a block missing across all four arms.

| CSV column | Allowed values or meaning |
|---|---|
| `round,case,trial` | Nonempty stable IDs. A case identifies one fixed request template. |
| `permission` | `forced`, `disabled`, `undeclared` |
| `arm` | `official_a`, `official_b`, `transparent`, `relay` |
| `outcome` | `answer`, `refusal`, `error`, `unparseable`, `missing` |
| `tool_calls` | Number of structured call records. Leave blank for unobservable tool fields. |
| `input_total` | Endpoint-reported total input. Leave blank for unknown or invalid usage. For Messages, add ordinary input, cache creation and cache read. For Chat Completions, use prompt tokens, which already include the cached portion. |

```sh
python3 scripts/experiments/replay_relay_measurements.py measurements local-redacted-slots.csv
```

For each round, arm and permission, the output counts scheduled slots, observed outcomes, tool-field coverage, slots with unexpected calls and the number of call records. For disabled or undeclared tools, any returned call is unexpected under this contract. Use the forced condition as a positive control and the auditor's structured probe to inspect names and arguments. Interpret call counts alongside the observable denominator. Report refusal and error counts even when they remove a slot from a comparison.

Input differences use matched `case,trial,permission,round` slots in which both arms returned an answer or refusal and reported total input. Read the median difference and matched-pair count together. `official_b` compared with `official_a` estimates same-window official variation. A median from zero matched pairs is emitted as `null`. With repeated samples, report results for each time window and note when flags change. A small pilot establishes delivery behavior for the sampled configuration and dates.

For a fresh billing check, isolate the account from other usage and record the opening and closing balances, currency, route, price schedule and precision. Include every billed attempt in the interval, including failures if billed. Build disjoint ordinary-input, cache-read, cache-write and output buckets at their actual rates. For a single rate per category and model, use the billing command above with your CSV and the observed balance difference. If multiple cache rates or rate periods apply, give each schedule its own model-group label. Missing balances, ambiguous rates or missing billed usage leave reconciliation unresolved. Submit the redacted project evidence through [the existing evidence workflow](../community-evidence.md).
