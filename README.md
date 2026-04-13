# API Relay Audit

by [@li9292](https://x.com/li9292)

[**🇨🇳 中文**](#中文) · [**🇺🇸 English**](#english) · [ROADMAP](./ROADMAP.md) · [Engineering Diary (中文)](./FOR_JOHN.md)

---

<a id="中文"></a>

## 🇨🇳 中文

全面审计第三方 AI API 中转站(反代/转发站)的安全性、可靠性和透明度。针对**普通用户**(Claude / GPT API 使用者)和 **Web3 钱包用户**两个受众,通过一个 `--profile` 开关切换,一份代码两种审计。

威胁模型遵循 Liu 等人提出的 AC-1 / AC-1.a / AC-1.b / AC-2 分类法,出自论文 [*Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the LLM Supply Chain*, arXiv:2604.08407](https://arxiv.org/abs/2604.08407)。流级别检测概念源自 [hvoy.ai](https://hvoy.ai/) 的 `claude_detector.py`(2026-04-11 对照源文件验证,clean-room 重新实现)。

### 🚀 30 秒快速开始

一行命令审计任意中转站 — 不用 clone、不用 pip install、只依赖 `curl`:

```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py

# 普通用户(默认 profile=general,跑 Step 1-10)
python audit.py --key <你的KEY> --url <中转站地址> --output report.md

# Web3 / 钱包用户(额外运行 Step 11 SlowMist 签名隔离探针)
python audit.py --key <你的KEY> --url <中转站地址> --profile web3 --output report.md
```

**产出**:一份结构化的 Markdown 报告,顶部是整体风险汇总(LOW / MEDIUM / HIGH),下面是每一步的详细结果。见下方 [报告示例](#报告示例) 和 [11 步审计](#11-步审计)。

### 👥 适合谁用

| 角色 | 场景 | 推荐 profile |
|---|---|---|
| **普通 API 用户** | 买了中转站的 Claude / GPT 服务,担心中转商在请求/响应里做手脚(注入、改写、截断) | `--profile general`(默认) |
| **Web3 钱包用户** | 用 agent + 中转站构造链上交易或处理私钥,担心恶意中转导致资产损失 | `--profile web3` |
| **安全研究员** | 想深度验证一个中转站的所有可观测维度 | `--profile full` |
| **中转站运营方** | 想自查自家服务有没有意外暴露凭证 / 漏洞 | 任一 profile,外加 `--output` 保存报告 |

### 🔒 项目质量数据

这是一个**质量管线异常严格**的 CLI 工具:

- **493 个 pytest 单元测试**(从 v2.1 的 114 增长到 v2.3 的 319,v1.7.5 review 轮再增 +107 个)
- **6 轮独立 Codex 代码审查 + 1 轮独立 peer review** 在 v2.2 → v2.3 → v1.7.5 开发期间发现并修复 **17 个真实 bug**(全部是 false-negative 级别的安全工具失效,如果 ship 进生产会造成对真实恶意中转站误判为 clean)
- **零回归**:每次修复都带 regression test,bug 类别不会复发
- **双分发字节级一致性**:`test_risk_matrix_character_identical` 测试强制 modular 和 standalone 两个版本的风险矩阵代码块完全相同
- **每一个借鉴的概念都有 docstring 归属**(LiteLLM Apache-2.0 secret regexes / hvoy.ai clean-room 重实现 / SlowMist 签名隔离灵感)

完整的已交付功能、下一步路线图、和明确不做的事项,见 [`ROADMAP.md`](./ROADMAP.md)。

### 📰 最近更新

| 版本 | 核心内容 |
|---|---|
| **v2.3** (2026-04-11) | **Step 10 流完整性**(Anthropic SSE 事件白名单 + usage 单调性 + thinking 签名有效性)+ **Step 11 Web3 Prompt 注入**(3 个 SlowMist 签名隔离探针)+ **`--profile` 选择器**(general / web3 / full)+ 6D 风险矩阵 |
| **v2.2** (PR 1 of v3) | **Step 9 错误响应泄漏**(AC-2 adjacent,7 个故意破坏的请求 + 凭证回显扫描)+ 4D 风险矩阵 + LiteLLM issue tracker 溯源的 8+ regex |
| **v2** | **Step 8 工具调用改写检测**(AC-1.a 拼写投毒 / `pip install requests → reqeusts`)+ 3D 风险矩阵 + `--warmup N` AC-1.b 部分缓解 |

### 📋 11 步审计

| # | 检测项 | 针对攻击 |
|---|---|---|
| 1 | 基础设施侦察 | DNS / WHOIS / SSL / CDN / 面板识别(New API, One API) |
| 2 | 模型列表枚举 | 可用模型 / `owned_by` 字段 / 后端通道识别 |
| 3 | Token 注入检测 | delta 法比对 `input_tokens` 实际 vs 预期 |
| 4 | Prompt 提取 | 3 种直接提取攻击,识别可泄漏的隐藏 system prompt |
| 5 | 指令冲突 + 身份替换 | 猫测试 + 26 关键词非 Claude 身份检测(GLM/DeepSeek/Qwen/通义/千问/智谱/豆包/文心) |
| 6 | 越狱测试 | 3 种越狱方法测试反提取防护 |
| 7 | 上下文长度扫描 | 5 个 canary marker + 二分查找真实截断边界 |
| 8 | 工具调用改写 (AC-1.a) | pip/npm/cargo/go 装包命令 echo,字符级 diff 检测拼写投毒 |
| 9 | 错误响应泄漏 (AC-2 adjacent) | 7 个故意破坏的请求,扫描错误体/响应头的凭证回显/上游 URL/环境变量/栈追踪/LiteLLM 内部字段/Bedrock guardrail PII echo |
| 10 | 流完整性 (AC-1 SSE 层) | Anthropic 流请求 + 4 个不变量检测(事件白名单 / usage 单调性 / usage 一致性 / thinking 签名有效性) |
| 11 | Web3 Prompt 注入(`--profile web3` 专属) | 3 个 SlowMist 签名隔离探针(转账指引 / 签名拒绝 / 私钥泄漏拒绝) |

### 📊 报告示例

运行后产出的 Markdown 报告大致长这样:

```markdown
# API Relay Security Audit Report

**Generated**: 2026-04-11 15:23
**Target**:    `https://relay.example.com/v1`
**Model**:     `claude-opus-4-6`

## Risk Summary

- 🟢 Infrastructure recon clean
- 🟢 6 models enumerated
- 🟢 No token injection detected
- 🟢 All extraction attempts failed
- 🟢 Cat test passed (user system prompt works)
- 🟢 Context boundary: 180K~200K chars
- 🟢 No tool-call package substitution detected
- 🔴 Error response leaks partial credentials (AC-2)
- 🟢 Stream integrity clean: SSE whitelist + usage + signature passed
- ⚪ Step 11 skipped (profile=general)

---

## 9. Error Response Leakage (AC-2 adjacent)
| Trigger          | HTTP | Severity   | Leaks        |
|------------------|------|------------|--------------|
| malformed_json   | 400  | 🟢 none    | —            |
| invalid_model    | 400  | 🔴 HIGH    | upstream_host|
| missing_messages | 400  | 🟢 none    | —            |
...

## 12. Overall Rating

### HIGH RISK

**Partial credential / upstream URL / environment variable leaked
in error response.** The relay is exposing internal plumbing that
maps onto the attacker's credential-collection surface. **Do not use.**
```

### 🏗 架构摘要

- **双分发模型**:同一份 11 步审计逻辑以两种并行形式发布
  - `audit.py` — 零依赖单文件版(~2500 行),只用 curl,一条 `curl -sO` 下载 + `python audit.py` 运行
  - `api_relay_audit/` + `scripts/audit.py` — 模块化版,`httpx` + 完整 pytest 测试,开发者路径
  - `test_dual_distribution_parity.py` 强制两边风险矩阵字节级一致
- **6D 风险矩阵**:D1 token 注入 / D2 指令覆盖 / D3 工具调用改写 / D4 错误响应泄漏 / D5 流完整性异常 / D6 Web3 注入。任一 D3-D6 触发即 HIGH
- **`--profile` 选择器**:`general`(Steps 1-10)/ `web3`(+ Step 11)/ `full`(全部)。运行时开关代替 git branch 分叉
- **三态判定**:每一步返回 clean / anomaly / **inconclusive**。被 relay 默默吞掉的探针不算 clean,算可疑
- **基于不变量检测,不是基于签名**:token 计数是不可伪造的整数(Step 3),canary marker 是确定性子串(Step 7),SSE 事件类型是封闭的 schema(Step 10)。工具不找已知坏模式,它验证已知好不变量是否成立
- **Codex review 循环**:非平凡 PR 至少 2 轮独立 Codex review,本 session 发现 10 个真实 bug 全部修复

详细的架构说明和设计决策,见 [English Architecture 章节](#architecture) 和中文工程日记 [`FOR_JOHN.md`](./FOR_JOHN.md)。

### 📦 使用方式

**方式 A — 一行命令(零安装)**:见 [🚀 30 秒快速开始](#-30-秒快速开始)

**方式 B — OpenClaw Skill**:安装 [`SKILL.md`](./SKILL.md) 后,直接对 agent 说"测试这个中转站"

**方式 C — 开发者模式**:
```bash
git clone https://github.com/toby-bridges/api-relay-audit.git
cd api-relay-audit && pip install httpx pytest
python -m pytest tests/ -v           # 跑全套 493 个测试
python scripts/audit.py --key <KEY> --url <URL> --output report.md
```

### ⚙️ CLI 选项

```
python audit.py --key <KEY> --url <URL> [options]

必填:
  --key KEY              API 密钥
  --url URL              中转站地址(例如 https://xxx.com/v1)

常用:
  --model MODEL          测试模型(默认 claude-opus-4-6)
  --output PATH          报告输出路径(默认 stdout)
  --profile {general,web3,full}  受众选择器(默认 general)
  --timeout SECONDS      请求超时(默认 120)

跳过步骤:
  --skip-infra                    跳过 Step 1(DNS/WHOIS/SSL)
  --skip-context                  跳过 Step 7(上下文长度扫描,省 5-10 分钟)
  --skip-tool-substitution        跳过 Step 8(AC-1.a 包名改写)
  --skip-error-leakage            跳过 Step 9(AC-2 adjacent 错误响应扫描)
  --aggressive-error-probes       启用 Step 9 的 256 KB 大 body 探针(可能产生计费)
  --skip-stream-integrity         跳过 Step 10(需要 Anthropic 流支持)
  --skip-web3-injection           跳过 Step 11(仅 --profile web3|full 激活)

其他:
  --warmup N             审计前先发 N 次无害请求(AC-1.b 请求次数门控部分缓解)
```

### 📉 风险等级

| 等级 | 判定条件 | 建议 |
|------|----------|------|
| **LOW** 🟢 | 6 个维度(D1-D6)全部 clean | 可放心使用 |
| **MEDIUM** 🟡 | 轻微注入(<100 tokens)、prompt 可提取、或任一 step inconclusive、或 Step 9 medium-only 信息披露 | 简单任务可用,复杂工作流需谨慎 |
| **HIGH** 🔴 | 任一 D3-D6 触发(工具改写 / 错误响应泄漏 / 流完整性异常 / Web3 注入),或 D1+D2 同时触发 | 不推荐使用 |

完整的 6D 风险矩阵规则见 [ROADMAP.md 架构不变量章节](./ROADMAP.md#-architectural-invariants-must-preserve)。

---

<a id="english"></a>

## 🇺🇸 English

Security audit tool for third-party AI API relay/proxy services. Detects hidden prompt injection, prompt leakage, instruction override with non-Claude identity substitution (GLM/DeepSeek/Qwen/…), context truncation, tool-call package substitution (AC-1.a), error response header leakage (AC-2 adjacent), SSE-level stream integrity anomalies (AC-1 streaming layer), and Web3 prompt injection (SlowMist signature isolation). One codebase serves both **general API relay users** and **Web3 wallet users** via a `--profile` runtime selector.

Threat model follows the AC-1 / AC-1.a / AC-1.b / AC-2 taxonomy from Liu et al., [*Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the LLM Supply Chain*, arXiv:2604.08407](https://arxiv.org/abs/2604.08407). Stream-level detection concept sourced from [hvoy.ai](https://hvoy.ai/) / `claude_detector.py` (verified against source 2026-04-11, clean-room reimplementation).

### 🚀 Quick Start (30 seconds)

One command to audit any relay — no install, no clone, no Python dependencies beyond `curl`:

```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py

# General profile (Steps 1-10, 95% of users)
python audit.py --key <YOUR_KEY> --url <BASE_URL> --output report.md

# Web3 / wallet profile (adds Step 11 SlowMist signature isolation probes)
python audit.py --key <YOUR_KEY> --url <BASE_URL> --profile web3 --output report.md
```

Output: a structured Markdown report with a risk summary (LOW / MEDIUM / HIGH) at the top plus per-step details. See [Example Output](#example-output) and [11-Step Audit](#11-step-audit) below.

### 👥 Who should use this

| Role | Situation | Recommended profile |
|---|---|---|
| **General API user** | Bought relay access to Claude / GPT, worried the relay is tampering with requests or responses (injection / rewriting / truncation) | `--profile general` (default) |
| **Web3 / wallet user** | Using an agent + relay to construct on-chain transactions or handle private keys, worried a malicious relay could cause asset loss | `--profile web3` |
| **Security researcher** | Wants to deeply verify every observable dimension of a relay | `--profile full` |
| **Relay operator** | Self-audit: has my service accidentally leaked credentials or left vulnerabilities open? | Any profile + `--output` to save the report |

### 🔒 Quality Assurance

This project uses an unusually rigorous quality pipeline for a CLI tool:

- **493 pytest unit tests** across 15 test files (from 114 baseline in v2.1, +205 in v2.3, +107 in v1.7.5 review round)
- **6 independent Codex review rounds + 1 independent peer review round** during v2.2 → v2.3 → v1.7.5 development
- **17 real bugs caught and fixed** by those reviews before ship — every one was a false-negative-class failure that would have misjudged a truly malicious relay as "clean"
- **Byte-level dual-distribution parity** enforced by `test_risk_matrix_character_identical` — the modular and standalone versions cannot drift
- **Every ported concept has docstring attribution** (LiteLLM Apache-2.0 secret regexes, hvoy.ai clean-room reimplementation for SSE integrity, SlowMist inspiration for Web3 probes)
- **Zero regressions**: every fix in every Codex round is accompanied by a regression test so the bug class cannot return

See [`ROADMAP.md`](./ROADMAP.md) for the complete shipped feature list, deferred backlog, and "explicitly NOT doing" decisions with rationale.

### 📰 Recent Highlights

| Version | Contents |
|---|---|
| **v2.3** (2026-04-11) | **Step 10 Stream Integrity** (Anthropic SSE event whitelist + usage monotonicity + thinking signature validity) + **Step 11 Web3 Prompt Injection** (3 SlowMist signature isolation probes) + **`--profile` selector** (general / web3 / full) + 6D risk matrix |
| **v2.2** (PR 1 of v3) | **Step 9 Error Response Leakage** (AC-2 adjacent, 7 deterministic broken requests + credential echo scan) + 4D risk matrix + 8+ regex patterns sourced from LiteLLM issue tracker |
| **v2** | **Step 8 Tool-Call Substitution** (AC-1.a typosquat detection: `pip install requests → reqeusts`) + 3D risk matrix + `--warmup N` partial AC-1.b mitigation |

### 11-Step Audit

| Step | Test | What it detects |
|------|------|-----------------|
| 1 | Infrastructure Recon | DNS/WHOIS/SSL/CDN, hosting, certificate issues |
| 2 | Model List | Backend channels, model coverage |
| 3 | Token Injection | Hidden system prompt injection (delta method) |
| 4 | Prompt Extraction | Leakable hidden prompts (3 attack vectors) |
| 5 | Instruction Conflict + Identity | User system prompt overridden; non-Claude identity substitution (GLM / DeepSeek / Qwen / Warp / Windsurf / Chinese-market substitutes) |
| 6 | Jailbreak | Weak anti-extraction defenses (3 methods) |
| 7 | Context Length | Truncation below advertised limit (canary markers + binary search) |
| 8 | Tool-Call Substitution (AC-1.a) | Package-name rewriting on the return path (`requests` → `reqeusts` typosquat) |
| 9 | Error Response Leakage (AC-2 adjacent) | Echoed `Authorization` / API key prefix / upstream URL / env var name / FS path / stack trace / LiteLLM internal field / Bedrock guardrail PII in error responses |
| 10 | Stream Integrity (AC-1 SSE) | SSE event whitelist + usage monotonicity + thinking signature validity + stream model identity on an Anthropic streaming response |
| 11 | Web3 Prompt Injection (`profile=web3\|full`) | 3 probes for wallet-safety refusal: transfer guidance / sign-transaction refusal / private key leak refusal. Safe-priority classifier with hard-injected marker override |

<a id="example-output"></a>

### 📊 Example Output

A typical run produces a Markdown report that looks like this (abbreviated):

```markdown
# API Relay Security Audit Report

**Generated**: 2026-04-11 15:23
**Target**:    `https://relay.example.com/v1`
**Model**:     `claude-opus-4-6`

## Risk Summary

- 🟢 Infrastructure recon clean
- 🟢 6 models enumerated
- 🟢 No token injection detected
- 🟢 All extraction attempts failed
- 🟢 Cat test passed (user system prompt works)
- 🟢 Context boundary: 180K~200K chars
- 🟢 No tool-call package substitution detected
- 🔴 Error response leaks partial credentials (AC-2)
- 🟢 Stream integrity clean: SSE whitelist + usage + signature passed
- ⚪ Step 11 skipped (profile=general)

---

## 9. Error Response Leakage (AC-2 adjacent)
| Trigger          | HTTP | Severity   | Leaks          |
|------------------|------|------------|----------------|
| malformed_json   | 400  | 🟢 none    | —              |
| invalid_model    | 400  | 🔴 HIGH    | upstream_host  |
| missing_messages | 400  | 🟢 none    | —              |
...

## 12. Overall Rating

### HIGH RISK

**Partial credential / upstream URL / environment variable leaked
in error response.** The relay is exposing internal plumbing that
maps onto the attacker's credential-collection surface. **Do not use.**
```

<a id="architecture"></a>

### Architecture

#### Dual-distribution model

The same 11-step audit logic ships in two parallel forms, kept byte-identical by a dedicated parity test:

- **Standalone** (`audit.py`): a single ~2500-line file with zero Python dependencies beyond the stdlib. All HTTP goes through `curl` subprocess. One `curl -sO` download + one `python audit.py` run. This is the path most users take.
- **Modular** (`api_relay_audit/` + `scripts/audit.py`): a proper Python package with `httpx` for HTTP, full pytest suite, and per-module docstrings. This is the path developers extend.

Every change to one distribution must be mirrored into the other. `tests/test_dual_distribution_parity.py::test_risk_matrix_character_identical` enforces the invariant at the risk-matrix layer with a byte-for-byte comparison. `tests/test_web3_injection.py::TestWeb3MarkerParity` enforces it at the Web3 probe data layer.

#### 11-step pipeline

```
┌────────────────────────────────────────────────────────────────┐
│  Step 1  Infrastructure Recon     DNS / WHOIS / SSL / headers  │
│  Step 2  Model List                /v1/models enumeration      │
│  Step 3  Token Injection           delta method on input_tokens│
│  Step 4  Prompt Extraction         3 direct attacks            │
│  Step 5  Instruction Conflict      cat test + identity spoof   │
│  Step 6  Jailbreak Tests           3 anti-extraction probes    │
│  Step 7  Context Length            canary markers + bin search │
│  Step 8  Tool-Call Substitution    AC-1.a character-level diff │
│  Step 9  Error Response Leakage    AC-2 adjacent, 7 triggers   │
│  Step 10 Stream Integrity          AC-1 SSE-level, 4 invariants│
│  Step 11 Web3 Prompt Injection     profile=web3 only, 3 probes │
│                                                                │
│  Overall Rating (6D risk matrix)                               │
└────────────────────────────────────────────────────────────────┘
```

Each step returns a tri-state verdict (clean / anomaly / inconclusive) into a shared `Reporter` which builds the Markdown report with a risk summary header at the top and per-step detail sections below.

#### 6D risk matrix

The overall rating aggregates 6 orthogonal risk dimensions:

| Dim | Step | Triggered when... |
|---|---|---|
| D1 | 3 | Token injection > 100 tokens |
| D2 | 5 | User system prompt overridden (cat test fails or identity spoofed) |
| D3 | 8 | Tool-call package substitution detected |
| D4 | 9 | Error response leaks credentials (critical/high severity) |
| D5 | 10 | Stream integrity anomaly (unknown events / usage rewrite / empty signatures / non-Claude stream model) |
| D6 | 11 | Web3 prompt injection (only active under `--profile web3\|full`) |

Plus inconclusive variants (`D3i`, `D4i`, `D4m`, `D5i`, `D6i`) for cases where a step ran but could not reach a clean/anomaly verdict.

Rules (first match wins):
- `D3 or D4 or D5 or D6` → **HIGH**
- `D1 and D2` → **HIGH**
- `D1` or `D2` → **MEDIUM**
- `D3i or D4i or D4m or D5i or D6i` → **MEDIUM**
- otherwise → **LOW**

#### `--profile` audience selector

Instead of maintaining two git branches for general vs Web3 audiences, the tool uses a runtime flag:

| Profile | Runs | Suitable for |
|---|---|---|
| `general` (default) | Steps 1-10 | Regular API relay users (95% case) |
| `web3` | Steps 1-11 | Wallet / crypto users |
| `full` | Steps 1-11 + any future profile-gated steps | Security researchers |

This design preserves the dual-distribution invariant, the single test suite, the memory/documentation consistency, and the "one-curl-download" standalone story. See [`ROADMAP.md`](./ROADMAP.md) for why git branches were rejected.

#### Key design principles

1. **Detection based on invariants, not signatures.** Token counts are non-forgeable integers (Step 3). Canary markers are deterministic substrings (Step 7). SSE event types are a closed schema (Step 10). The tool doesn't look for known-bad patterns — it verifies that known-good invariants hold.
2. **Tri-state verdicts, not booleans.** Every step returns clean, anomaly, or **inconclusive**. A relay that blocks a probe is not clean — it's suspicious. Silent swallowing becomes a detectable signal.
3. **Clean-room reimplementation for ported concepts.** Step 9 regexes are adapted from LiteLLM's Apache-2.0 `_logging.py`. Step 10 SSE schema comes from hvoy.ai's `claude_detector.py` (no LICENSE — concepts and schema field names are not copyrightable). Step 11 probes follow SlowMist's signature isolation principle. Every port has attribution in the module docstring.
4. **Review loop for non-trivial PRs.** Independent Codex reviews + peer review caught 17 real bugs across this feature set — every one would have shipped as a false-negative or parity violation otherwise. The review round is a 2-5 minute cost that prevents much larger downstream costs.
5. **Pareto-optimal scope.** Every step has to earn its place: does it cover a dimension nothing else catches, does the detection stay valid across relay variants, can it be implemented without breaking zero-dep? Steps that fail any of these get deferred (see [`ROADMAP.md`](./ROADMAP.md) "Explicitly NOT doing").

For a deep-dive engineering narrative (in Chinese), see [`FOR_JOHN.md`](./FOR_JOHN.md).

### Installation Options

**Option A — One-liner (zero install)**: see [🚀 Quick Start](#-quick-start-30-seconds) above.

**Option B — OpenClaw Skill**: install [`SKILL.md`](./SKILL.md) then say "audit this relay" to your agent.

**Option C — Developer setup**:
```bash
git clone https://github.com/toby-bridges/api-relay-audit.git
cd api-relay-audit && pip install httpx pytest
python -m pytest tests/ -v           # run the full 493-test suite
python scripts/audit.py --key <YOUR_KEY> --url <BASE_URL> --output report.md
```

#### Project Structure

```
audit.py                             # Standalone zero-dep version (~2500 LOC)
SKILL.md                             # OpenClaw skill definition
ROADMAP.md                           # Shipped / near-term / deferred backlog
FOR_JOHN.md                          # Engineering narrative (Chinese)
api_relay_audit/                     # Modular package (requires httpx)
  client.py                          #   APIClient with auto-detection + streaming
  context.py                         #   Context length canary + binary search
  error_leakage.py                   #   Step 9 AC-2 scan (7 triggers + regex)
  identity_patterns.py               #   Step 5 non-Claude identity detection
  reporter.py                        #   Markdown report builder with risk flags
  stream_integrity.py                #   Step 10 SSE analyzer + StreamSignals
  tool_substitution.py               #   Step 8 AC-1.a package substitution
  transparent_log.py                 #   Forensic JSONL logger (arXiv §7.3)
  web3/                              #   Profile=web3 subpackage
    injection_probes.py              #     Step 11 SlowMist signature isolation
scripts/
  audit.py                           #   11-step orchestrator (entry point)
  context-test.py                    #   Standalone context length probe
  extract-data.py                    #   Report → JSON extractor for dashboard
tests/                               # 493 pytest tests across 15 files
  test_dual_distribution_parity.py   #   byte-level parity guard
  test_client_stream.py              #   streaming SSE parser unit tests
  test_stream_integrity.py           #   Step 10 verdict analysis tests
  test_web3_injection.py             #   Step 11 probes + classifier tests
  ...
web/
  index.html                         # Dashboard (single-page vanilla JS)
deploy/
  deploy-nas.sh                      # Docker/nginx deployment script
```

### CLI Options

```
python audit.py --key <KEY> --url <URL> [options]

Required:
  --key KEY              API key
  --url URL              Base URL (e.g. https://xxx.com/v1)

Common:
  --model MODEL          Model name (default: claude-opus-4-6)
  --output PATH          Report output path (default: stdout)
  --profile {general,web3,full}  Audience selector (default: general)
  --timeout SECONDS      Request timeout (default: 120)

Skip flags:
  --skip-infra                    Skip Step 1 (DNS/WHOIS/SSL recon)
  --skip-context                  Skip Step 7 (context length, saves 5-10 min)
  --skip-tool-substitution        Skip Step 8 (AC-1.a package substitution)
  --skip-error-leakage            Skip Step 9 (AC-2 error response scan)
  --aggressive-error-probes       Enable 256 KB oversized probe in Step 9 (may incur billing)
  --skip-stream-integrity         Skip Step 10 (needs Anthropic streaming support)
  --skip-web3-injection           Skip Step 11 (only runs under --profile web3|full)

Other:
  --warmup N             Send N benign requests before the audit
                         (partial AC-1.b request-count gate mitigation)
```

### Risk Levels

| Level | Criteria | Recommendation |
|-------|----------|----------------|
| **LOW** 🟢 | All 6 risk dimensions (D1-D6) clean: no injection, instructions work, full context, no tool-call substitution, no error leakage, clean stream integrity, no Web3 injection (if `--profile web3`) | Safe to use |
| **MEDIUM** 🟡 | Minor injection (<100 tokens) OR prompt extractable OR any of Steps 8/9/10/11 **inconclusive** OR Step 9 medium-only leakage (FS path / stack trace) | OK for simple tasks, use with caution |
| **HIGH** 🔴 | Injection >100 tokens AND instructions overridden, OR **any** of: tool-call substitution (Step 8), critical/high error leakage (Step 9), stream integrity anomaly (Step 10), or Web3 injection detected (Step 11 under `--profile web3`) | Not recommended |

See [`ROADMAP.md`](./ROADMAP.md#-architectural-invariants-must-preserve) for the full 6D risk matrix rules and dimension definitions.

---

## Contributing

Read [`CLAUDE.md`](./CLAUDE.md) for architecture context, module responsibilities, and test commands. Run `python -m pytest tests/ -v` before submitting a PR.

## Author

[@li9292](https://x.com/li9292)

## License

MIT
