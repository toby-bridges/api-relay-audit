<p align="center">
  <img alt="API Relay Audit - local AI API relay security audit with separate query families for relay audit, prompt injection audit, model substitution signals, and Web3 relay audit." src="./assets/readme-banner.png">
</p>

# API Relay Audit

<p align="center">
  Local security audit for AI API relays and LLM proxies.
</p>

<p align="center">
  <a href="https://toby-bridges.github.io/api-relay-audit/"><img alt="GitHub Pages" src="https://img.shields.io/badge/GitHub%20Pages-Live%20Site-0a7f5a?style=for-the-badge"></a>
  <a href="#chinese-readme"><img alt="README 中文" src="https://img.shields.io/badge/README-%E4%B8%AD%E6%96%87-111111?style=for-the-badge"></a>
  <a href="https://x.com/li9292"><img alt="X @li9292" src="https://img.shields.io/badge/X-%40li9292-111111?style=for-the-badge"></a>
  <a href="https://github.com/toby-bridges"><img alt="GitHub toby-bridges" src="https://img.shields.io/badge/GitHub-toby--bridges-24292f?style=for-the-badge"></a>
</p>

<p align="center">
  <a href="./SKILL.md"><strong>OpenClaw Skill</strong></a>
  ·
  <a href="./skills/api-relay-audit/SKILL.md"><strong>Hermes Skill</strong></a>
</p>

## What Is API Relay Audit?

API Relay Audit is a local security audit tool for AI API relays and LLM proxies. It keeps API relay audit, prompt injection audit, model substitution signals, and Web3 relay audit as separate query families so each result keeps a clean evidence boundary. Your API key is sent only to the relay URL you choose.

Use it when you rely on a third-party AI API relay, OpenAI-compatible proxy, Claude-compatible proxy, or Web3 agent workflow and want a repeatable Markdown report before trusting that relay with production or wallet-related traffic.

## AI API Relay Security Audit

- **Detect relay tampering:** prompt injection, prompt extraction, identity consistency signals, context truncation, tool-call rewriting, error-response leakage, and SSE stream anomalies.
- **Run locally:** the standalone `audit.py` uses only Python stdlib plus `curl`; your API key is sent only to the relay URL you choose.
- **Produce reviewable evidence:** each run generates a structured Markdown report with per-step findings and a final `LOW / MEDIUM / HIGH` verdict.

## Query Family Boundaries

| Query family | User intent | Profile / steps | Evidence boundary |
|---|---|---|---|
| API relay audit | Audit a third-party relay, mirror, gateway, LLM proxy, or resale API before trusting traffic. | `general` by default; `full` for every probe | Produces a local report, not a safety certificate. |
| Prompt injection audit | Detect hidden prompt injection, prompt leakage, instruction override, and extraction behavior. | `general`; Steps 3-6 | Records prompt evidence without publishing private prompts or secrets. |
| Model substitution signals | Collect model identity, stream, latency, and upstream channel signals. | `general`; Steps 5, 10, 13, 14 | Self-ID, latency, and channel fingerprints are signals, not standalone proof of provider substitution. |
| Web3 relay audit | Check wallet-sensitive relay behavior before agent workflows touch signing or transactions. | `web3` or `full`; Step 11 | Profile-gated; general relay audits do not imply wallet safety. |

The canonical contract lives in [docs/query-families.md](./docs/query-families.md). README headings, Pages cards, issue templates, and skill descriptions should preserve these boundaries instead of flattening them into one slogan.

## Quick Start

```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py

python audit.py --key <YOUR_KEY> --url <BASE_URL> --output report.md

# Web3 / wallet users
python audit.py --key <YOUR_KEY> --url <BASE_URL> --profile web3 --output report.md
```

See a public-safe fixture report: [sanitized audit report](./docs/examples/sanitized-audit-report.md).

## Coverage

API Relay Audit checks whether a relay modifies the request or response path between you and the model:

- Prompt safety: token injection, prompt extraction, instruction override, jailbreak resistance
- Relay integrity: context truncation, tool-call substitution, error leakage, stream integrity
- Model identity: non-Claude identity leaks, model substitution signals, Claude/OpenAI-compatible relay behavior
- Web3 wallet safety: transfer guidance, signed-transaction refusal, private-key refusal

## Audit LLM Proxies Locally

The project has two distribution modes:

- `audit.py`: zero-dependency standalone script for quick local audits
- `api_relay_audit/` plus `scripts/`: modular development version with tests

Runtime profiles:

- `general`: default AI API relay and LLM proxy checks
- `web3`: wallet-safety probes for Web3 agent flows
- `full`: general plus Web3 checks

## Agent Skills: OpenClaw and Hermes

API Relay Audit can also run as an agent skill when an agent workflow needs to
audit a relay before trusting it with coding, tool, or wallet-related traffic.

- **OpenClaw Skill:** run a local AI API relay audit before an OpenClaw agent
  depends on a third-party relay, proxy API, or resale key.
- **Hermes Skill:** install API Relay Audit as a Hermes Agent skill and run the
  same local 14-step LLM proxy security audit from an agent workflow.

These skills do not certify that a relay is safe. They help agents generate a
local, reviewable Markdown report before trusting a relay path.

## When to Use It

- You use a third-party AI API relay, mirror, gateway, or LLM proxy.
- You want to check whether a Claude-compatible or OpenAI-compatible proxy injects prompts, swaps models, truncates context, or rewrites tool output.
- You are testing relay behavior before production traffic, coding-agent automation, package-install suggestions, or wallet-related actions.
- You need a local, repeatable audit report instead of a web tool that asks for your API key.

## What It Does Not Claim

- It does not certify that a relay is safe.
- It does not replace manual security review or operational monitoring.
- It does not treat `inconclusive` as `clean`; blocked probes and ambiguous responses stay visible in the report.

## Evidence Boundaries

Natural-language self-identification is treated as a consistency signal, not upstream proof. A response saying it is Qwen, DeepSeek, GPT, or Claude can indicate a mismatch, but it does not by itself prove that a provider substituted the upstream model.

Stronger claims require corroborating evidence such as raw response JSON, request IDs, provider/model metadata, stream signatures, transparent-log hashes, and reproducible runs. Public submissions should use redacted report artifacts and never include API keys, raw headers, full response bodies, wallet material, private relay traffic, or user data.

## Web3 Wallet Safety Checks

With `--profile web3` or `--profile full`, API Relay Audit adds wallet-oriented prompt injection probes inspired by signature-isolation risks:

- ETH transfer guidance checks
- Signed-transaction refusal checks
- Private-key leak refusal checks

These probes are model-agnostic, but they are intentionally profile-gated so general relay audits stay focused.

## Working Model

```text
your machine
  -> audit.py / scripts/audit.py
  -> chosen relay endpoint
  -> Markdown report + optional hash-only transparent log
  -> optional: redacted evidence issue for maintainer review
```

Community evidence is shape-checked by GitHub Actions, but publication still requires maintainer review. Operators keep a separate response path, and sensitive vulnerabilities belong in the disclosure path described in [SECURITY.md](./SECURITY.md).

## Project Status

| Metric | Current value |
|---|---:|
| Version | `v2.3` |
| Audit steps | 14 |
| Risk matrix | 6D |
| pytest collected tests | 764 |
| CLI flags | 21 |
| Runtime profiles | `general`, `web3`, `full` |

## Example Report And Live Page

- GitHub Pages: [toby-bridges.github.io/api-relay-audit](https://toby-bridges.github.io/api-relay-audit/)
- Chinese landing page: [toby-bridges.github.io/api-relay-audit/zh/](https://toby-bridges.github.io/api-relay-audit/zh/)
- Example report: [sanitized fixture report](./docs/examples/sanitized-audit-report.md)
- Guides:
  [AI API relay / LLM proxy](https://toby-bridges.github.io/api-relay-audit/guides/what-is-ai-api-relay-proxy.html),
  [Claude relay audit](https://toby-bridges.github.io/api-relay-audit/guides/audit-claude-api-relay-safely.html),
  [tool comparison](https://toby-bridges.github.io/api-relay-audit/guides/compare-api-relay-audit-hvoy-cctest.html),
  [prompt injection in proxies](https://toby-bridges.github.io/api-relay-audit/guides/detect-prompt-injection-llm-api-proxies.html),
  [Web3 wallet prompt injection](https://toby-bridges.github.io/api-relay-audit/guides/web3-wallet-prompt-injection-ai-agents.html),
  [OpenClaw and Hermes skill](https://toby-bridges.github.io/api-relay-audit/guides/openclaw-hermes-skill-api-relay-audit.html)
- Contributors / Credits: [CONTRIBUTORS.md](./CONTRIBUTORS.md)
- Security policy: [SECURITY.md](./SECURITY.md)
- Contributing guide: [CONTRIBUTING.md](./CONTRIBUTING.md)
- Social: [X @li9292](https://x.com/li9292)

## FAQ

### What is an API relay or LLM proxy?

An API relay or LLM proxy is a third-party service between you and an AI provider such as Anthropic or OpenAI. It forwards your requests upstream, but it can also inject hidden instructions, swap models, truncate context, rewrite tool output, or leak credentials in error responses.

### Is it safe to enter my API key?

API Relay Audit runs locally, so your API key is sent only to the relay URL you specify. The standalone version is a single Python file with zero Python package dependencies, which makes it easier to inspect before running.

### What does prompt injection mean here?

Prompt injection means the relay may prepend or insert hidden instructions into your request. API Relay Audit compares expected and actual token usage, tries prompt-extraction probes, and records evidence when the relay appears to add or reveal hidden prompt content.

### What is model substitution?

Model substitution means the relay claims to provide one model but may expose evidence signals for another model identity, route, or upstream channel. API Relay Audit checks non-Claude identity patterns, anchor phrases, stream model identity, latency variance, and channel evidence where available; those signals require corroboration before making provider-level claims.

### What is tool-call rewriting?

Tool-call rewriting means the relay modifies package-install commands or tool-like output in the model response. API Relay Audit sends pinned package commands and compares the returned text to detect proxy-layer supply-chain tampering.

### What are SSE anomalies?

SSE anomalies are stream-level integrity issues in Anthropic-style streaming responses. API Relay Audit checks event types, usage monotonicity, thinking signatures, and stream model identity when the relay supports that format.

### What Web3 wallet risks does it check?

With the `web3` or `full` profile, API Relay Audit checks transfer guidance, signed-transaction refusal, and private-key refusal behavior before wallet-related traffic is trusted.

### What does `inconclusive` mean?

`Inconclusive` means the tool could not determine a clean or anomalous result for that step. A blocked probe, unsupported format, or ambiguous response is not treated as safe; it remains visible in the final report.

### How does this compare with hvoy.ai or cctest.ai?

They serve different needs. hvoy.ai is useful for relay reputation lookup, cctest.ai focuses on one-click testing and channel fingerprinting, and API Relay Audit focuses on local, open-source, repeatable security auditing with structured Markdown reports.

## License

AGPL-3.0-only. See [LICENSE](./LICENSE).

This keeps modified network-service deployments accountable to the same public source-availability standard as the relay ecosystem evidence we audit.

## Citation

If you use API Relay Audit in research, security reports, or public relay evaluations, please cite the software with [CITATION.cff](./CITATION.cff). The citation file also records the two academic papers that inform the audit model: Liu et al., *Your Agent Is Mine* (arXiv:2604.08407) and Zhang et al., *Real Money, Fake Models* (arXiv:2603.01919).

## How to Contribute

You do not need to write code to help. Good first contributions are small,
reproducible, and evidence-focused:

- Report a detector gap with a sanitized reproduction.
- Add documentation examples for profiles, flags, or relay behavior.
- Improve OpenClaw or Hermes install notes from a real local setup.
- Translate Quick Start or clarify `clean`, `anomaly`, and `inconclusive`.

Start with:

- [Detector Gap](https://github.com/toby-bridges/api-relay-audit/issues/new?template=detector-gap.yml)
- [Documentation Example](https://github.com/toby-bridges/api-relay-audit/issues/new?template=documentation-example.yml)
- [Agent Skill Feedback](https://github.com/toby-bridges/api-relay-audit/issues/new?template=agent-skill-feedback.yml)
- [CONTRIBUTING.md](./CONTRIBUTING.md)

Avoid publishing real API keys or private relay traffic, and keep changes scoped
to one behavior or document.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=toby-bridges/api-relay-audit&type=Date)](https://www.star-history.com/#toby-bridges/api-relay-audit&Date)

<details id="chinese-readme">
<summary>中文 README</summary>

## API Relay Audit 是什么？

`api-relay-audit` 是一个本地运行的 AI API 中转站 / LLM proxy 安全审计工具。它把 API relay audit、prompt injection audit、model substitution signals、Web3 relay audit 拆成独立查询意图，避免把不同风险压成一个口号；你的 API Key 只会发送到你指定的中转站 URL。

当你使用第三方 AI API 中转站、OpenAI-compatible proxy、Claude-compatible proxy，或者 Web3 agent 工作流时，可以用它在信任该中转站之前生成一份可复查的 Markdown 审计报告。

## 你会得到什么

- 一个本地运行的 14 步审计工具，输出结构化 Markdown 报告
- 双分发形态: `audit.py` 单文件零依赖版 + `api_relay_audit/` 模块化开发版
- `--profile general|web3|full` 三种运行模式
- `LOW / MEDIUM / HIGH` 总结论，加每一步的细项结果

## 查询意图边界

| Query family | 用户意图 | Profile / Steps | 证据边界 |
|---|---|---|---|
| API relay audit | 审计第三方中转站、镜像、网关、LLM proxy 或 resale API。 | 默认 `general`；完整覆盖用 `full` | 输出本地报告，不是安全认证。 |
| Prompt injection audit | 检测隐藏 prompt 注入、prompt 泄漏、指令覆盖和提取行为。 | `general`；Step 3-6 | 记录 prompt 证据，但不公开私有 prompt 或 secret。 |
| Model substitution signals | 收集模型身份、stream、延迟和上游 channel 信号。 | `general`；Step 5、10、13、14 | self-ID、延迟和 channel fingerprint 是信号，不能单独证明 provider 替换。 |
| Web3 relay audit | 在 agent 接触签名、交易或钱包相关内容前检查中转行为。 | `web3` 或 `full`；Step 11 | profile-gated；普通 relay audit 不等于钱包安全。 |

正式契约在 [docs/query-families.md](./docs/query-families.md)。README、Pages、issue template 和 skill description 都应该保留这些边界。

## 30 秒快速开始

```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py

python audit.py --key <YOUR_KEY> --url <BASE_URL> --output report.md

# Web3 / 钱包用户
python audit.py --key <YOUR_KEY> --url <BASE_URL> --profile web3 --output report.md
```

## 核心覆盖

- Prompt 安全: token injection、prompt extraction、instruction override、jailbreak
- Relay 完整性: context truncation、tool-call substitution、error leakage、stream integrity
- 模型身份: 非 Claude 身份泄漏、模型替换信号、Claude / OpenAI 兼容中转行为
- Web3 风险: 转账指引、签名拒绝、私钥泄漏拒绝

## Agent Skill 支持

API Relay Audit 也可以作为 agent skill 使用。

- **OpenClaw Skill:** 在 OpenClaw agent 把 coding、tool 或钱包相关流量交给第三方 relay 前，先运行本地审计。
- **Hermes Skill:** 作为 Hermes Agent skill 安装，在 agent workflow 中运行同一套本地 14 步审计。

这些 skill 不给中转站颁发安全认证，只帮助 agent 在信任 relay 前生成本地、可复查的 Markdown 报告。

## 什么时候使用

- 你正在使用第三方 AI API 中转站、镜像、网关或 LLM proxy。
- 你想检查 Claude / OpenAI 兼容代理是否注入 prompt、替换模型、截断上下文或改写工具输出。
- 你准备把中转站用于生产流量、coding agent 自动化、包安装建议，或钱包相关操作。
- 你需要本地、可复现的审计报告，而不是把 API Key 输入到网页工具。

## 它不声称什么

- 它不为任何中转站颁发“安全认证”。
- 它不替代人工安全审查或线上监控。
- 它不会把 `inconclusive` 当成 `clean`；被拦截或无法判断的探针会保留在报告里。

## 证据边界

模型自然语言自称 Qwen、DeepSeek、GPT 或 Claude，只能作为 identity consistency signal，不能单独证明真实上游供应商或平台替换了模型。

更强的结论需要 raw response JSON、request id、provider/model metadata、stream signature、transparent-log hash 和可复现实验共同支撑。公开提交只接受脱敏报告证据；不要提交 API Key、raw headers、完整 response body、钱包材料、私有中转流量或用户数据。

## 工作方式

```text
你的机器
  -> audit.py / scripts/audit.py
  -> 你指定的 relay endpoint
  -> Markdown report + 可选 hash-only transparent log
  -> 可选：脱敏 evidence issue，等待 maintainer review
```

社区证据会被 GitHub Actions 做格式检查，但公开发布仍需要 maintainer review。运营方回应走单独通道，敏感漏洞走 [SECURITY.md](./SECURITY.md) 的 disclosure 路径。

## 项目状态

| 指标 | 当前值 |
|---|---:|
| 版本 | `v2.3` |
| 审计步骤 | 14 |
| 风险矩阵 | 6D |
| pytest collected tests | 764 |
| CLI flags | 21 |
| Runtime profiles | `general`, `web3`, `full` |

## 如何贡献

你不需要写代码也能帮忙：可以提交检测缺口、文档示例、翻译改进，或 OpenClaw / Hermes 安装反馈。

- [Detector Gap](https://github.com/toby-bridges/api-relay-audit/issues/new?template=detector-gap.yml)
- [Documentation Example](https://github.com/toby-bridges/api-relay-audit/issues/new?template=documentation-example.yml)
- [Agent Skill Feedback](https://github.com/toby-bridges/api-relay-audit/issues/new?template=agent-skill-feedback.yml)

请不要提交真实 API Key、私有中转站流量、钱包材料或未脱敏审计报告。

## 主要入口

- 在线页 / GitHub Pages: [toby-bridges.github.io/api-relay-audit](https://toby-bridges.github.io/api-relay-audit/)
- 中文独立页: [toby-bridges.github.io/api-relay-audit/zh/](https://toby-bridges.github.io/api-relay-audit/zh/)
- 贡献者 / Credits: [CONTRIBUTORS.md](./CONTRIBUTORS.md)
- 安全政策: [SECURITY.md](./SECURITY.md)
- 贡献指南: [CONTRIBUTING.md](./CONTRIBUTING.md)
- 社交媒体: [X @li9292](https://x.com/li9292)

</details>
