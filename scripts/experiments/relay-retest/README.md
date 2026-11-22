# Recount the relay behavior flags in Wu et al. (2026)

Run this from the project root with Python 3.8 or later. It reads the bundled CSV offline.

```sh
python3 scripts/experiments/relay-retest/recount.py
```

`table-iii.csv` transcribes the price group and four label columns of Table III in *What the Middleman Delivers*, by Xiaodong Wu et al. (arXiv:2611.07650v1, CC BY 4.0). Blank fields represent unmeasured cells. Each letter gives the authors’ classification for one relay and model in one round. A single letter applies to all four scoring rules. Four letters give the rules in the order below. The recount treats C and S as flagged, N as unflagged, and compares only pairs measured in both rounds. The published labels are the inputs. Rescoring the underlying answers would require the private responses and scoring labels. [Table III and methods](https://arxiv.org/html/2611.07650v1#S5.SS2) · [Source license](https://creativecommons.org/licenses/by/4.0/)

| Question bank / handling of refusals | Paired relay–models | Flagged twice | Lost flag | Gained flag | Unflagged twice |
|---|---:|---:|---:|---:|---:|
| Primary / count as misses | 35 | 9 | 5 | 2 | 19 |
| Primary / exclude | 35 | 9 | 4 | 1 | 21 |
| Alternate / count as misses | 35 | 10 | 3 | 2 | 20 |
| Alternate / exclude | 35 | 10 | 3 | 1 | 21 |

The unit changes for the price test. A service counts once when either measured target has a primary flag in round one. The script independently computes the two-sided Fisher exact test for 7 of 10 low-price services versus 2 of 10 same- or higher-price services (`p = 0.0698`). The sample was recruited by availability and price group. It supports a description of these services during the collection window.

Scoring choices change the apparent stability. Counting refusals as misses yields seven transitions under the primary bank. Excluding refusals on the same bank yields five. A separate sensitivity analysis in the paper held the multiple-testing family constant across rounds and found six primary transitions. Table III retains the original correction, so reproducing that six requires the authors’ hit counts and correction procedure. [Authors’ counts and script](https://arxiv.org/src/2611.07650v1/anc)

## Decision for the capability pilot

Keep the [roadmap’s capability benchmark](../../../ROADMAP.md) informational pending a fresh official-to-official baseline. The authors’ accessible summaries establish that flags can change with the scoring rule. The rate of changes solely from official response variability remains unknown. For one example of limited sensitivity, Table S2 reports flags in only 4% of simulations when 25% of Astra answers were replaced by Luna answers in the selected question bank. A flag measures a difference in behavior under the chosen prompts. Determining the upstream model requires independent evidence. [Results, Sections V-A and V-D](https://arxiv.org/html/2611.07650v1#S5)

1. Before collection, pin one model version, protocol, question bank, answer key, refusal rule, budget and comparison family. Fix an acceptable accuracy difference for the intended workload and reserve questions for evaluating the rule after development.
2. Collect two independent official samples under those settings. Record correct answers, wrong answers, refusals and acquisition failures. Score refusals both ways and report failures against the scheduled-call denominator. Pair the arms by question and keep repetitions of the same question together when estimating uncertainty.
3. Run the same analysis on a relay with a fresh official reference. Report the effect and its interval alongside the official-to-official result. Expand the bank only if the pilot can distinguish the predeclared meaningful effect from baseline variation. If the baseline is too imprecise, collect more independent questions before changing the product rating.
