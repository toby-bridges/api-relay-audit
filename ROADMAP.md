# api-relay-audit Roadmap

Living document tracking completed work, near-term candidates, medium-term
ideas, explicitly deferred backlog, and the explicit "not-doing" list. Each
item has a short rationale so future contributors (including future
iterations of the author) can quickly reconstruct why a thing is or is not
on the list.

**Last updated**: 2026-04-20 (handoff-prep cleanup: Tier A archival shipped, v1.9 decouplings logged, 562/562 passing)

**Threat model anchor**: Liu et al., *Your Agent Is Mine: Measuring
Malicious Intermediary Attacks on the LLM Supply Chain*, arXiv:2604.08407.
Detection concepts cross-referenced with SlowMist OpenClaw Security
Practice Guide and hvoy.ai `zzsting88/relayAPI` `claude_detector.py`.

---

## ✅ Shipped

### v2.1 and earlier (pre-session baseline)
- Steps 1-7: infrastructure recon / model list / token injection via delta
  method / prompt extraction / instruction conflict / jailbreak / context
  length scan
- Step 8: AC-1.a tool-call package substitution (pip / npm / cargo / go
  echo probes with character-level diff)
- 3D risk matrix (D1 injection / D2 override / D3 substitution)
- Dual-distribution: `scripts/audit.py` + `api_relay_audit/*.py` modular,
  `audit.py` standalone curl-only single-file

### v2.2 + v2.3 + v1.7.3 (shipped 2026-04-11, 12 commits in one session)
- **Step 9 — Error Response Header Leakage (AC-2 adjacent)**: 7 deterministic
  broken requests + scan for credential echo / upstream URLs / env vars /
  FS paths / stack traces / LiteLLM internal fields / Bedrock guardrail PII
  echoes. Sourced from 8 verified LiteLLM GitHub issue bug reports.
- **Step 10 — Stream Integrity (AC-1 SSE-level)**: Anthropic streaming
  probe + 4 invariants (SSE event whitelist / `output_tokens` monotonicity /
  `input_tokens` consistency / thinking signature validity) + stream model
  identity check. Concept verified against hvoy.ai `claude_detector.py`,
  clean-room reimplementation with tri-state verdicts instead of their
  0-100 score.
- **Step 11 — Web3 Prompt Injection (profile=web3|full)**: 3 probes
  targeting SlowMist signature isolation (transfer guidance / sign refusal
  / private key refusal). Safe-priority classifier with hard-injection
  override for contradictory responses.
- **Non-Claude identity detection**: 22-keyword tuple (→ 26 in v1.7.7) with two-tier
  matching (strict keywords require identity anchor phrases; lax keywords
  use word-boundary + non-letter lookahead). Catches Chinese-market
  substitutes: GLM / DeepSeek / Qwen / MiniMax / Grok / GPT / ERNIE /
  Doubao / Moonshot / Kimi + Chinese brand names (通义/千问/智谱/豆包/
  文心/月之暗面). Eliminates residual "I am Claude, not GPT" false
  positive.
- **`--profile {general,web3,full}` flag**: runtime audience selector
  instead of git branch split. Web3 users opt in; general users see no
  change. Preserves dual-distribution, test suite, memory, and single-
  source-of-truth invariants that branches would break.
- **6D risk matrix** (D1/D2/D3/D3i/D4/D4m/D4i/D5/D5i/D6/D6i) with
  character-identical parity between modular and standalone audit.py.
- **10 Codex-review bugs fixed** across 6 independent review rounds
  (2 MEDIUM + 1 LOW + 1 NIT + 1 MEDIUM + 1 MEDIUM + 1 LOW + 1 MEDIUM +
  2 LOW). Every fix has a regression test.
- **319 pytest tests** (from 114 baseline, +205 new, zero regressions)
- **11 CLI flags** and 3 profile choices
- FOR_JOHN.md diary chapter, memory files updated, full push to
  `origin/master`

### v1.7.7 (shipped 2026-04-14, 6 commits)
- **`--transparent-log <path>` (arXiv §7.3)**: append-only JSONL forensic
  log. Every API request recorded with timestamp, URL, SHA-256 of
  request/response bytes, status code, transport metadata. Hash only,
  not body. Hooks into all 4 `APIClient` methods with incremental
  SHA-256 for streaming. `redact_error()` strips response body from
  error field to prevent credential leakage (Codex review HIGH fix).
  `os.makedirs` for parent directory (Codex review MEDIUM fix).
- **Identity anchor residual fixes**: CJK no-whitespace (`"我是GPT-5"`)
  via `_CJK_STRICT_PATTERNS` supplementary path; filler cap `{0,4}` →
  `{0,6}` for verbose self-IDs.
- **Context-strict tier for warp/windsurf**: new `_CONTEXT_STRICT_KEYWORDS`
  requiring post-keyword identity signal (punctuation or role word).
  Eliminates FP on "I am in warp speed" / "I am a windsurf instructor"
  (Codex review MEDIUM fix). CJK path also enforces suffix constraint
  with full-width punctuation support (Codex review LOW fix).
- **26 identity keywords** (from 22: added warp, windsurf, antigravity,
  deepmind). Three-tier matching: strict (anchor-required), context-strict
  (anchor + suffix), lax (word-boundary).
- **493 pytest tests** (from 319, +174 new, zero regressions)
- **12 CLI flags** (`--transparent-log` added) and 3 profile choices
- Version sync: scripts/audit.py v2.2 → v2.3, SKILL.md YAML fix,
  README/CLAUDE.md numbers updated

---

## ✅ Shipped v1.8 — Infrastructure Audit Layer (2026-04-18)

### Step 12: Infrastructure Fingerprint (informational)
**Commit**: `17387b0` on `feat/v1.8-infra-audit-layer`
**Module**: `api_relay_audit/infra_fingerprint.py` (~240 LOC, 24 tests)
**What**: 3 unauthenticated GET probes (`/`, `/v1/models`, `/nonexistent-*`)
+ hand-curated framework signature database (new-api, one-api, lobechat-relay,
fastgpt, cloudflare, nginx-raw, caddy-raw) + majority-vote confidence
(confirmed ≥2 hits / tentative 1 hit / unknown 0 hits).
**Why**: Zhang et al., *Real Money, Fake Models*, arXiv:2603.01919,
Section 3.2 Infrastructure reports 11 of 17 identified shadow APIs are
built on OneAPI and its derivative NewAPI.
Knowing the framework lets the operator cross-reference CVEs and assess
professionalism.
**Classification**: informational only — does NOT feed into the 6D risk matrix.

### Step 13: Latency Variance (informational)
**Commit**: `3339bc1` on `feat/v1.8-infra-audit-layer`
**Module**: `api_relay_audit/latency_variance.py` (~180 LOC, 20 tests)
**What**: N (default 10) identical `max_tokens=8` probes + descriptive stats
+ gap-ratio bimodality heuristic. Verdict = stable (CV<0.25) / variable
(0.25≤CV<0.5) / high-variance (CV≥0.5) / bimodal / inconclusive.
**Why**: silent A/B testing between the advertised model and a cheaper
substitute produces bimodal latency. Queue multiplexing produces multi-modal.
Stable low-variance latency is the honest baseline.
**Classification**: informational only; v1.8 could false-positive on jitter
and warm-up. Future v2+ may promote bimodality to a D7 dimension once we
have enough honest-relay baseline data.

### v1.8 Codex review cycle (same-day follow-up, 2026-04-18)
**Commits**: `4db33b7` (MEDIUM fix), `d0fb5d9` (LOW coverage + HIGH known-limitation docs)
**Verdict**: minor-fixes-needed → closed. 6th Codex review round shipped on this
repo, cumulative 18 real bugs/limitations found across the loop.
- **HIGH** (app-layer drowned by edge-layer on aggregate): **deferred to v1.8.1**
  per Pareto analysis. Current Step 12 is informational-only; per-probe result
  still preserves one-api / new-api identity; only the majority-vote aggregate
  loses it. Fix requires changing `aggregate_framework` signature + all call
  sites + report renderer, which warrants real Cloudflare-fronted relay data
  before committing to the layer split. Current behavior locked by
  `test_one_api_behind_cloudflare_aggregates_as_cloudflare` +
  `test_new_api_behind_cloudflare_aggregates_as_cloudflare`.
- **MEDIUM** (N=4 single-outlier bimodality false positive): **fixed**. Gap
  search restricted to interior splits where both sides have ≥2 samples.
  `[1.00, 1.01, 1.02, 1.80]` now returns `(False, ~0.01)` — the single outlier
  is correctly treated as high-variance, not bimodal. Genuine 2+2 distributions
  `[1.00, 1.01, 1.80, 1.82]` still fire. Dual-distribution parity preserved.
- **LOW** (missing test coverage): **fixed**. 5 new tests — N=4 outlier +
  N=4 true bimodal + N=5/N=6 extreme-outlier cluster-size rule + 3-success /
  7-error partial-success CV verdict + Step 12/13 constants dual-distribution
  parity (FRAMEWORK_SIGNATURES, INFORMATIVE_HEADERS, _BODY_SCAN_LIMIT,
  BIMODAL_GAP_THRESHOLD, CV cutoffs, DEFAULT_PROBE_COUNT).
- **Final test count**: 546/546 passing (v1.7.7 baseline 493 → v1.8 ship 537
  → v1.8 Codex follow-up 546, +53 net for v1.8).

### v1.8.1 Codex review cycle #2 (handoff-prep, 2026-04-20)
Second Codex pass before front-end handoff. 5 findings (1 HIGH already in
v1.8.1 backlog + 2 MEDIUM + 2 LOW); 4 fixed in this cycle.
- **HIGH** (majority-vote mixes app-layer and edge-layer): **unchanged** —
  already tracked as v1.8.1 item #0 below; deferral rationale still stands.
- **MEDIUM** #2 (Step 13 first sample polluted by format detection): **fixed**.
  New `APIClient.ensure_format()` warm-up; `run_latency_variance` calls it
  before the timing loop so no sample includes a failed Anthropic probe plus
  a successful OpenAI request. 2 new tests (call ordering + graceful
  degradation for clients lacking the method).
- **MEDIUM** #3 (`time.time` is wall clock, not monotonic): **fixed**.
  Migrated to `time.perf_counter()` in both distributions. Removes NTP / VM
  clock-skew artifacts from CV / bimodality inputs.
- **LOW** #4 (LobeChat's `x-powered-by: next.js` misfires on every Vercel
  site): **fixed**. Signal removed; body branding (`lobechat` / `lobe-chat`)
  is still the identifier. Negative test locks behavior.
- **LOW** #5 (`--latency-probe-count` took 0 / negatives / huge values):
  **fixed**. `validate_probe_count` rejects values outside `[3, 50]` with a
  readable `argparse.ArgumentTypeError`. 11 new tests around the bounds.
- **Final test count**: 560/560 passing (546 → 560, +14 this cycle).

### v1.8.1 Codex review cycle #2 round 2 (post-commit verification, 2026-04-20)
Re-ran Codex on commit `122f23d` right after v1.8.1 shipped. Codex
confirmed all 4 code fixes were correct but flagged 3 **test-coverage
gaps** — cases where the existing tests could be false-greens (pass
identically if the underlying fix were reverted). Triaged under
strict-2-hour handoff window; prioritized the one true false-green
and deferred the other two to v1.9.
- **#3 test gap — false-green clock-source check**: **fixed in this
  round**. Added two new regression tests —
  `tests/test_latency_variance.py::test_uses_perf_counter_not_wall_clock`
  and `tests/test_dual_distribution_parity.py::test_standalone_uses_
  perf_counter_not_wall_clock`. Both monkeypatch the `time` module,
  instrument `perf_counter` with a deterministic counter + `time.time`
  with a constant, then assert that `perf_counter` was invoked ≥2×
  per probe, `time.time` was never called, and measured latencies
  equal the fake clock deltas exactly. Under a reverted `time.time`
  implementation these fail loudly because the mocked client returns
  instantaneously (elapsed ≈ 0), whereas the fake `perf_counter`
  yields `elapsed = 1.0`. Both distributions pinned.
- **#2 test gap — `ensure_format` only exercised via mock**: deferred
  to v1.9 (see item 2.5 below). Current `test_ensure_format_called_
  before_timing` proves the ordering contract but does not exercise
  the real `APIClient.ensure_format()` body.
- **#5 test gap — validator not tested at `parse_args()` level**:
  deferred to v1.9. Unit tests on `validate_probe_count` + parity
  test on the constants are both green; what is missing is an
  end-to-end `parse_args(["--latency-probe-count", "0"])` test that
  fails with `SystemExit(2)` proving the wiring inside `scripts/
  audit.py` AND the standalone argparse actually uses the validator.
- **Final test count**: 562/562 passing (560 → 562, +2 this round).

---

## 🔜 Near-term candidates (next 1-2 sessions)

Pick one of these to start the next session. Each is scoped to fit in a
single session, has a clear spec, and does not require new infrastructure.

### 0. v1.8.1 — app-layer vs edge-layer framework separation
**Status**: deferred from v1.8 Codex review HIGH finding (2026-04-18)
**Precondition**: at least one real Cloudflare-fronted one-api or new-api
endpoint audit result on file. Without real data, any layer-split heuristic
is a guess.
**Scope**: ~60 LOC refactor — partition `FRAMEWORK_SIGNATURES` into
`APP_LAYER_FRAMEWORKS = {"one-api", "new-api", "lobechat-relay", "fastgpt"}`
and `EDGE_LAYER_FRAMEWORKS = {"cloudflare", "nginx-raw", "caddy-raw"}`.
`aggregate_framework` returns `{"app": (framework, confidence), "edge":
(framework, confidence)}` tuple instead of a single `(framework, confidence)`.
Report renderer displays both layers with distinct labels.
**Dual-distribution impact**: large. `aggregate_framework` signature change
affects `scripts/audit.py` wiring + standalone `audit.py` inlined copy +
report renderer + all 4 existing aggregate tests (must update assertions).
**Parity regression test**: add a new test confirming that a Cloudflare-
fronted one-api landing page returns `{"app": ("one-api", "tentative"),
"edge": ("cloudflare", "confirmed")}` — this is the HIGH-finding scenario
we want to NOT lose.
**Cost of deferring further**: zero if operators don't hit this case in
real audits. Every month without a Cloudflare-fronted complaint is evidence
we can leave it. Revisit when #1 (local Docker validation) runs.

### 1. Local one-api Docker real-world validation
**Status**: not a coding task — ops / validation exercise
**Scope**: 30-60 minutes Docker setup + audit run + write-up
**Why**: generate the first real "before/after" detection rate data by
running the tool against a clean local one-api deployment. Confirms that
the 13-step pipeline does not false-positive on a legitimate relay, and
gives Step 12 its first real confirmed-framework hit for ground truth.
**Dependencies**: Docker + a valid upstream API key. `one-api` source
is publicly available at `github.com/songquanpeng/one-api`.
**Output**: a `reports/one-api-clean-baseline.md` file plus a diary entry
in `FOR_JOHN.md` documenting what Step 9/12/13 actually caught.

### 2. Crypto Address Substitution (profile=web3|full)
**Status**: spec'd, deferred from original v3 PR 2 — DEMOTED from v1.8
lead because Step 12/13 had clearer Pareto justification
**Scope**: ~180 LOC new module + ~30 tests
**Why**: arXiv §5.2 reports a real case of a relay draining an ETH
private key. Probe set: ETH USDT contract / BTC Satoshi genesis /
SOL Token Program / ERC-20 transfer calldata / BTC bech32 address.
**Strict byte-level classifier** — NO case folding (EIP-55 mixed case).
**Dependencies**: none. Byte-level string comparison, no crypto libs.
**Cost of deferring further**: low — no new adversarial case reported
since the original paper.

### 2.4 v1.9 — test-coverage follow-ups from Codex review cycle #2 round 2
**Status**: 2 deferred test-coverage gaps from 2026-04-20 Codex
verification; code-side fixes already shipped in v1.8.1.
**Scope**: ~40 LOC new tests, no product changes.

1. **`ensure_format` real-body integration test** — current
   `test_ensure_format_called_before_timing` proves the call-ordering
   contract via a mock but never runs the real
   `api_relay_audit.client.APIClient.ensure_format()` body. A reviewer
   could silently replace the real method with a no-op and all tests
   would still pass. Add an integration-style test that constructs a
   real `APIClient` (mocked HTTP transport), calls `ensure_format()`,
   and asserts `_format` is set to a sentinel value afterwards. Mirror
   into the standalone via the `_load_standalone_audit()` helper in
   `test_dual_distribution_parity.py`.
2. **`--latency-probe-count` parser-level wiring test** — current
   `TestValidateProbeCount` class exercises the validator directly but
   does not prove `scripts/audit.py`'s argparse AND the standalone
   argparse both actually wire the validator. Add a test that invokes
   each distribution's `parse_args` (or entry point with
   `monkeypatch.setattr(sys, "argv", ...)`) with values `0`, `-1`,
   `51` and asserts `SystemExit(2)`. Without this, someone could
   accidentally drop `type=validate_probe_count` from the
   `add_argument` call and all existing tests would still pass.

**Cost of deferring further**: low. Both are "defence-in-depth"
rather than real bugs — the v1.8.1 fixes themselves are correct,
these tests just harden the regression guard. Revisit when the next
feature cycle starts (same session that picks up 2.5 over-engineering
prune is a natural fit).

### 2.45 v1.9 — controlled-blast decouplings (handoff-prep triage, 2026-04-20)

**Status**: audit done 2026-04-20 before front-end handoff.
**Shipped in this audit**: Tier A archival — `scripts/verify_signature_
schema.py` moved to `scripts/experiments/` (zero blast on imports, no
module references the archived script). Codex review on the move
caught one latent path-drift bug: `OUT_DIR = Path(__file__).parent.
parent / "reports"` would have written to `scripts/reports/` rather
than `<repo_root>/reports/` after the rename. Fixed in the same
branch by bumping the anchor to `.parent.parent.parent`. Regression
lesson: whenever a script moves deeper into the tree, `__file__`-
relative paths inside it must be re-verified.
**Deferred to v1.9**: four real decoupling candidates ranked by
blast-radius vs. leverage.

1. **Extract `REFUSAL_MARKERS` + `_looks_like_refusal`**
   from `scripts/audit.py` (lines 81, 156-158) into a new module
   `api_relay_audit/refusal.py`.
   **Scope** (verified via grep, 2026-04-20 Codex review):
   - 3 call sites of `_looks_like_refusal` in `scripts/audit.py`
     (lines 178, 403, 559) — NOT 6 as initially stated
   - `tests/test_refusal_detector.py` already imports
     `modular._looks_like_refusal` directly; a re-export on
     `scripts/audit.py` keeps the test untouched, a hard rename
     does not
   - `tests/test_clean_summary_flags.py` does not import the
     helpers but does exercise Step 4/6 with a `CLEAN_REFUSAL`
     fixture, so any behavior change in the helper surfaces here
   - Standalone `audit.py` keeps its inline copy unchanged — the
     existing `TestRefusalMarkerParity` parity test covers drift
   **Blast radius**: LOW. Parity test is the regression guard; if
   it stays green and the test suite passes, the extraction is
   safe. Recommended approach: re-export on `scripts.audit` so
   `tests/test_refusal_detector.py` needs zero changes.
   **Why now-safe**: unlike a client.py / audit.py split, this
   does NOT require a standalone refactor because the parity
   strategy already treats refusal markers as "inline on
   standalone, imported on modular" in principle — we just need
   to complete that on the modular side.
   **Prereq**: none.
   **Time estimate**: 25-30 min.
   **Why deferred past this handoff**: medium-value, not zero-
   blast. A typo in an import path or a missed call site would
   produce a silent refusal-detection regression; worth a
   proper code review rather than a 30-min squeeze before
   handoff.

2. **Split `api_relay_audit/client.py` (924 LOC)**
   into `client/transport.py` + `client/format_detection.py` +
   `client/stream.py` + `client/__init__.py` (re-exports).

   **Codex review follow-up (2026-04-20)**: my original "HIGH
   blast / blocked on dual-distribution policy" framing was over-
   pessimistic. A cheaper incremental path exists:

     *Phase 2a — transport extraction only, facade-preserved.*
     Move just the httpx-vs-curl transport code into an internal
     `api_relay_audit/_transport.py` helper module and have
     `api_relay_audit/client.py` import from it. `APIClient`
     class stays in `client.py`; all public imports stay valid.
     No test changes. Standalone `audit.py` stays flat because
     modular's public API is unchanged — the parity constraint
     does not care what's behind the facade. Blast radius: LOW.
     Time estimate: 60-90 min.

   After 2a lands and stabilizes, Phase 2b (stream extraction)
   and 2c (format-detection extraction) can follow the same
   pattern. Only Phase 2d ("promote the internal modules to
   public re-exports under `api_relay_audit.client.*`") needs
   the dual-distribution policy decision, because that is when
   the standalone flat copy starts diverging.

   **Scope (Phase 2a only)**: ~300 LOC moved into internal
   helper + ~30 LOC of import rewiring inside `client.py`. No
   change to public import paths. No change to standalone.
   **Blast radius (Phase 2a)**: LOW.
   **Prereq (Phase 2a)**: none.
   **Time estimate (Phase 2a)**: 60-90 min.

   **Original full-split Phase 2d** (for reference): HIGH blast,
   blocked on dual-distribution policy (keep / deprecate /
   auto-generate standalone from modular). 2-3 hours plus design.

3. **Split `scripts/audit.py` (1536 LOC)**
   into `scripts/steps/` subdirectory, one file per numbered step.
   **Scope**: ~1200 LOC moved + `scripts/audit.py` becomes a thin
   orchestrator that imports from `scripts.steps.step_NN_*`.
   **Blast radius**: MEDIUM-HIGH. The `test_risk_matrix_character_
   identical` parity test slices text between `# Overall rating`
   and `# Output` comments; if the split moves those comments into
   a step module the parity test breaks unless we relocate the slice
   markers.
   **Prereq**: same dual-distribution decision as #2; also needs the
   parity test's slice markers redesigned.
   **Time estimate**: 3-4 hours.

4. **Extract `web/` dashboard to a separate repo**
   `api-relay-audit-dashboard`.

   **Codex review follow-up (2026-04-20)**: my "1h mechanical"
   estimate was wrong — `web/` has live wiring into the rest of
   the repo that must be re-established after extraction:

   - `.github/workflows/pages.yml` deploys `web/**` to GitHub
     Pages; triggered by `paths: [web/**]`. Either (a) remove
     this workflow when extracting and rewire inside the new
     repo, or (b) keep a thin `web/` symlink/submodule in this
     repo that still satisfies the paths filter.
   - `scripts/extract-data.py` has `--output` as a **required
     flag with no default** (`scripts/extract-data.py:197`);
     the CLAUDE.md + docstring example just happens to pass
     `--output ./web/data.json`. After extraction, either the
     script gains a default pointing at the new repo path or
     every caller/doc/CI invocation is updated to the new
     location.
   - `web/index.html` is 75 KB with inline JS/CSS; splitting
     into HTML + CSS + JS is a separate frontend task that
     probably wants to happen IN the new repo rather than this
     one.

   **Blast radius**: LOW on the Python backend (nothing under
   `api_relay_audit/*` or `scripts/audit.py` imports the
   dashboard), but MEDIUM on CI/deployment because the
   GitHub Pages workflow currently depends on `web/` living
   in-tree.
   **Why not now**: defer to the front-end colleague's first-
   day discussion. They may prefer to keep it in-tree for one
   more iteration OR prefer a clean extract where they own
   the new repo from day one. Either answer is reasonable.
   **Time estimate**: 2-3 hours (extraction + CI rewire +
   README cross-links), NOT 1 hour.

**Cost of deferring further**: moderate. #1 and the Phase-2a slice of
#2 are the highest-leverage of the four because they ship real module
cohesion without touching standalone. Full-split Phase-2d of #2 and
the whole of #3 are blocked on the dual-distribution decision, which
is itself ROADMAP 2.5 item #1 (biggest-debt candidate). #4 is a front-
end colleague conversation, not a backend task.

### 2.5 v1.9 — over-engineering prune (backlog, handoff-prep triage)
**Status**: audit done 2026-04-20 before front-end handoff; no deletions
yet — items tabled because deletion before handoff is high-risk.
**Scope**: each item below is a separate consideration; don't do them all
at once.

Top-5 candidates ranked by maintenance-cost-per-value (worst first):

1. **Dual-distribution invariant** (`audit.py` standalone, ~2500 LOC
   char-parity with `scripts/audit.py`): biggest recurring tax. Every
   feature ships twice; 3 dual-distribution parity tests guard risk
   matrix / Web3 markers / refusal vocab. **Prerequisite for deletion**:
   data on actual standalone usage. If user telemetry shows <5% of runs
   use `audit.py`, deprecate it; otherwise keep.
2. **`error_leakage` GitHub-issue cross-reference**: every leak marker
   maps to a real LiteLLM issue number (#5762, #8075, ...). Elegant when
   shipped but issue state rots (renames, merges, closures). Simplify
   to the regex + literal substring paths; keep issue refs only in
   `FOR_JOHN.md` provenance notes.
3. **`transparent_log.py`**: JSONL forensic logger (`--transparent-log`
   gated). Academic anchor (arXiv §7.3) but real-world usage
   unconfirmed. Convert to an optional extra once packaging is
   introduced (same packaging work needed for v2.5 LLMmap Pro).
4. **Web3 profile** (Step 11, 3 probes + profile gating + hard-injected
   override): low invocation rate expected vs. surface area. Could
   collapse to a single probe while keeping the `--profile web3` CLI
   surface.
5. **`latency_variance` bimodality branch**: Step 13 is already
   informational-only; bimodality adds inference complexity without
   affecting risk matrix. Could report only CV + count and still
   deliver the same operator value.

**Cost of deferring further**: zero. Pruning helps only if we keep
shipping new features on top; if development pauses, these stay as
inert reference code. Revisit when next feature cycle starts.

### 3. MistTrack AML integration (profile=web3|full, optional)
**Status**: sketched in SlowMist OpenClaw Practice Guide, not started
**Scope**: ~100 LOC adapter + external API dependency
**Why**: SlowMist's "Cross-Skill Pre-flight Check" pattern — when an
agent is about to make a high-value crypto action, call MistTrack for an
AML risk score. Score ≥ 90 → hard abort. Integrates well with our
`--profile web3` flag.
**Dependencies**: MistTrack API key or public endpoint. Breaks the
zero-dep invariant for standalone `audit.py`. Should probably be
modular-only, with `--profile full` gate.
**Cost of deferring**: low — requires external infrastructure setup.

---

## 🛠 Medium-term ideas (1-3 month horizon)

### 6. Full AC-1 tool_call support (as opposed to AC-1.a text echo)
**Status**: backlog item from Step 8
**Scope**: ~150 LOC — `APIClient.tool_call()` method + structured
tool_call payload inspection + matching probe set
**Why**: Step 8 currently catches AC-1.a (typosquat on plain text echoes)
via text-level comparison. A more specific attack — rewriting the
`tool_calls` JSON payload but leaving plain text alone — is not caught.
Paper §4.2.1 notes: "the compromised dependency is cached locally and
re-imported across future sessions, giving the attacker a durable
supply-chain foothold."
**Cost vs benefit**: marginal coverage uplift over AC-1.a (all observed
wild samples were AC-1.a). Defer until the first wild AC-1 case is
reported.

### 7. Schema deviation anomaly detection (paper §7.2)
**Status**: paper lists it as a detection dimension; we don't implement
**Scope**: unknown — would need design work. Paper §7.2 Table 10 reports
~10% contribution to AC-1.a detection at 6.7% FPR budget, 0% at 1% FPR
budget.
**Why not**: low marginal value — our byte-level diff in Step 8 is
strictly better on AC-1.a, and the architectural complexity of adding a
schema-deviation feature to both distributions is high. Paper authors
themselves flagged this as the weakest of their three defenses.
**Decision**: defer indefinitely unless a new attack class needs it.

### 8. JA3 fingerprint clustering
**Status**: mentioned in paper §7.3 (6 JA3 fingerprints observed on 147
IPs, 40k unauthorized access attempts)
**Scope**: client-side JA3 fingerprinting + server-side collection +
corpus-level clustering
**Why not yet**: single-session value is low. JA3 clustering becomes
valuable after the audit corpus reaches ≥100 distinct relay endpoints.
We currently have 0 in our corpus (users run the tool ad-hoc). Revisit
after ~6 months of field use and corpus growth.

### 9. Structured audit corpus from hvoy.ai leaderboard
**Status**: hvoy.ai `/APIreview.html` lists 40+ real Chinese relay
endpoints with CNY pricing and推荐/中性/不推荐 ratings
**Scope**: ops + data pipeline: scrape or manually collect the list,
request consent from relay operators, run api-relay-audit against each,
compile a `reports/corpus-2026-Qx.md` document
**Why**: independent validation — our tool's findings should be compared
against hvoy.ai's recommendations and any divergence explained. Also
gives us JA3 data (see item 8) if we collect client-side TLS fingerprints
during the audit runs.
**Legal consideration**: some of the listed relays may have ToS that
prohibit audit probing. Need consent per-relay.
**Cost**: high — multi-session ops work.

### 10. v2.0 — Capability benchmark delta (direct model-substitution detection)
**Status**: promoted from "future idea" (v1.8 Codex cycle note). The most
direct signal we do not yet ship: run a small skill-gated prompt set and
measure accuracy delta vs. a known-honest baseline. If the advertised model
is Opus 4.6 but the delta is Haiku-shaped, that is substitution evidence
stronger than any fingerprint.
**Scope**: 2-3 week project — GPQA / MMLU subset (20-30 questions, rotating
pool to avoid memoization), grader (can be Claude itself with a strict
rubric), cost model, baseline corpus build. Not one-session work.
**Why not now**: ROADMAP #1 (local Docker validation) must run first — we
need an honest-relay reference before we can claim a "delta" exists.
Running v2.0 without a baseline produces noise.
**Dependencies**: curated probe set, grader prompt, baseline data from at
least one honest relay (local one-api + legitimate upstream key).
**Risk**: score noise, question leakage into future training corpora,
grader variance. Need many probes + CI bounds before reporting a verdict.

### 11. English-first README + blog-post announcement
**Status**: current README has English intro + 中文说明 section
**Scope**: polish pass + a 500-word X/Twitter announcement thread
**Why**: broader visibility after the Codex review loop gave us a
credible quality story ("10 bugs found and fixed across 6 reviews, all
with regression tests"). The 319-test count is a marketable data point.
**When**: after item 1 or 4 — the tool should have one more
differentiating feature before the announcement.

---

## 🤔 Long-term / uncertain

### 11a. v2.5 — LLMmap Pro active fingerprinting (breaks zero-dep invariant)
**Status**: sketched but shelved during v1.8 Pareto selection — PyTorch +
transformers pull ~4.5 GB of dependencies, which directly breaks the
zero-dependency invariant of the standalone `audit.py`.
**Scope**: port LLMmap-style active probing (crafted adversarial questions
whose response distribution distinguishes Claude vs GPT vs LLaMA vs Qwen
vs DeepSeek) + optional embedding-distance scoring.
**Blocker**: the zero-dep invariant. Options:
- Option A: split into a separate repo `api-relay-audit-deep` with
  heavy deps, linked from README.
- Option B: keep modular-only, gated behind `pip install
  api-relay-audit[deep]` extra. Standalone `audit.py` excludes it.
- Option C: re-implement the classifier as pure numpy+stdlib with
  pre-trained weights shipped as a blob. Brittle.
**Decision**: defer until someone demands it. The fingerprinting we ship in
Step 12 (infra) + future v2.0 (capability delta) together cover the same
detection question — active prompt-distribution fingerprinting is the
third orthogonal signal but has the worst cost/benefit of the three.

### 11. AC-2 active webhook canary
**Status**: paper describes this as the highest-confidence AC-2 signal
**Blocker**: requires a publicly reachable HTTPS endpoint to receive
beacon requests. Breaks the zero-dep invariant. Needs domain name,
HTTPS cert, webhook receiver service.
**When**: if/when api-relay-audit gets a hosted component.

### 12. Full AC-1.b conditional-delivery detection
**Status**: paper §4.2.2 lists 5 theoretical trigger families (content
keyword, user fingerprint, time windows, request count, tool name)
**Blocker**: paper itself concludes "finite black-box auditing is
fundamentally inadequate for conditional delivery." We can probe some
families (Step 8 + `--warmup` partially covers request-count gating),
but complete coverage requires many-round or long-running audits.
**Decision**: accept this as an out-of-scope attack class. Document in
README limitations.

### 13. Hosted web dashboard (hvoy.ai-style)
**Status**: hvoy.ai has a React/Vite dashboard that makes the tool
approachable to non-developers
**Blocker**: requires separate web app maintenance, API backend, auth.
Changes the product from "one-curl-download" to "hosted service".
**Decision**: out of scope for the CLI project. If demand emerges, spin
off a separate repo.

### 14. Claude Code CLI header impersonation
**Status**: observed in hvoy.ai's `get_headers` function (impersonates
`claude-cli/2.0.76` + all x-stainless-* headers)
**Why not port**: would make our requests indistinguishable from their
tool — no differentiation benefit. Also, impersonating a specific CLI
version is brittle (breaks when Claude Code bumps its version).
**Decision**: permanently out of scope.

---

## 🚫 Explicitly NOT doing (and why)

These were evaluated and deliberately dropped. They are listed here so
future contributors don't re-consider them without new information.

| Item | Why not |
|---|---|
| Token accounting audit (exact token counting) | Paper out of scope; no clean offline tokenizer; character-ratio heuristic too noisy; breaks zero-dep invariant if `tiktoken` added. |
| Knowledge cutoff probe (hvoy.ai dimension 1) | Author of hvoy.ai acknowledges it is trivially defeated by a relay hard-coding "May 2025" in system prompts. 50% of their score is wasted. |
| hvoy.ai 0-100 numeric scoring | We use 6D boolean risk matrix for clearer downstream decisions. Numeric thresholds need recalibration every model generation. |
| Copy hvoy.ai's `"null"` text block body fingerprint | Unclear purpose in upstream source; would make our requests indistinguishable from theirs (no benefit). |
| 4-tier risk scale (adding CRITICAL) | Requires Reporter class refactor; dashboard has downstream consumers; current LOW/MEDIUM/HIGH covers the action space. |
| Git branch split (main + web3) | `--profile` runtime flag is strictly better: one codebase, one test suite, one distribution, single-source-of-truth memory. Branches would double maintenance cost and break `test_dual_distribution_parity`. |
| Auto-detection of OpenAI streaming | Step 10 is Anthropic-only by design; OpenAI SSE schema differs. A Chinese relay that only speaks OpenAI format is correctly reported as "inconclusive" on Step 10, not "clean". |

---

## 📐 Architectural invariants (must-preserve)

When adding any new feature, verify these hold before committing:

1. **Dual-distribution parity** — `test_risk_matrix_character_identical`
   must stay green. Any risk matrix change must be mirrored byte-for-byte
   into `audit.py` standalone. Add parity tests for any new shared
   constants (see `TestWeb3MarkerParity` as an example).
2. **Zero-dependency standalone** — `audit.py` must run on vanilla
   Python 3.7+ with only `curl` available. No new pip dependencies in
   the standalone distribution. New third-party libs go in
   `api_relay_audit/*` modular only.
3. **Profile gating** — any new detection step that only serves a subset
   of users (e.g. Web3-specific) must be gated by `--profile web3|full`
   and default to **off** under `--profile general`.
4. **Risk matrix monotonic** — a new dimension can only add to the risk
   matrix, never weaken an existing determination. New dimensions go
   into HIGH or MEDIUM branches, never LOW.
5. **Memory-grounded decisions** — before adding a feature, check
   `~/.claude/projects/C--Users-john-Downloads-api-relay-audit/memory/`
   for prior decisions on the same topic. Especially `project_competitive_
   landscape.md` (so we don't re-invent hvoy.ai features) and
   `reference_litellm_secret_regex.md` (so Step 9 patterns stay in sync
   with LiteLLM's issue tracker).
6. **Codex review loop** — any feature PR ≥200 LOC or adding a new
   detection step should get at least 2 rounds of independent Codex
   review. The review loop found 10 real bugs in this session that would
   otherwise have shipped; the cost (~2-5 min per round) is trivial
   compared to the false-negative risk.
7. **Attribution for ported concepts** — when porting from hvoy.ai,
   SlowMist, LiteLLM, or one-api, add clear docstring attribution
   ("concept inspired by X, clean-room reimplementation"). License
   matters: LiteLLM is Apache-2.0 (can port code verbatim); hvoy.ai has
   no LICENSE (must be clean-room); SlowMist docs are narrative (ideas,
   not code).

---

## 🧭 How to use this roadmap

**Starting a new session**:
1. Read the top "Shipped" section to know current state
2. Read "Near-term candidates" — pick one based on available time
3. If the session is short (< 1 hour), pick items 1, 3, or 4. If longer,
   pick item 2 or 5.

**Completing a feature**:
1. Move it from "Near-term" to "Shipped" with the commit hash
2. Add any sub-items that got deferred to the appropriate section
3. If the decision changed what was previously "explicitly not doing",
   update the reason or remove it

**Proposing a new feature**:
1. First check the "Explicitly NOT doing" table — if it's listed, do not
   re-propose without new information
2. Check "Architectural invariants" — does the feature break any?
3. Draft the item in the appropriate time horizon section with a
   rationale and dependencies
4. Run it through Codex review methodology during implementation
