<p align="center">
  <img alt="API Relay Audit - AI API Relay Security Audit. Prompt Injection, Model Substitution, Tool Rewriting, SSE Anomalies. Runs locally; your API key is sent only to the relay URL you choose." src="./assets/readme-banner.png">
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

API Relay Audit is a local security audit tool for AI API relays and LLM proxies. It detects prompt injection, model substitution, tool rewriting, SSE anomalies, error leakage, and Web3 wallet risks. Your API key is sent only to the relay URL you choose.

Use it when you rely on a third-party AI API relay, OpenAI-compatible proxy, Claude-compatible proxy, or Web3 agent workflow and want a repeatable Markdown report before trusting that relay with production or wallet-related traffic.

## AI API Relay Security Audit

- **Detect relay tampering:** prompt injection, prompt extraction, identity substitution, context truncation, tool-call rewriting, error-response leakage, and SSE stream anomalies.
- **Run locally:** the standalone `audit.py` uses only Python stdlib plus `curl`; your API key is sent only to the relay URL you choose.
- **Produce reviewable evidence:** each run generates a structured Markdown report with per-step findings and a final `LOW / MEDIUM / HIGH` verdict.

## Quick Start

```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py

python audit.py --key <YOUR_KEY> --url <BASE_URL> --output report.md

# Web3 / wallet users
python audit.py --key <YOUR_KEY> --url <BASE_URL> --profile web3 --output report.md
```

## Detect Prompt Injection and Model Substitution

API Relay Audit checks whether a relay modifies the request or response path between you and the model:

- Prompt safety: token injection, prompt extraction, instruction override, jailbreak resistance
- Relay integrity: context truncation, tool-call substitution, error leakage, stream integrity
- Model identity: non-Claude identity leaks, model substitution, Claude/OpenAI-compatible relay behavior
- Web3 wallet safety: transfer guidance, signed-transaction refusal, private-key refusal

## Audit LLM Proxies Locally

The project has two distribution modes:

- `audit.py`: zero-dependency standalone script for quick local audits
- `api_relay_audit/` plus `scripts/`: modular development version with tests

Runtime profiles:

- `general`: default AI API relay and LLM proxy checks
- `web3`: wallet-safety probes for Web3 agent flows
- `full`: general plus Web3 checks

## When to Use It

- You use a third-party AI API relay, mirror, gateway, or LLM proxy.
- You want to check whether a Claude-compatible or OpenAI-compatible proxy injects prompts, swaps models, truncates context, or rewrites tool output.
- You are testing relay behavior before production traffic, coding-agent automation, package-install suggestions, or wallet-related actions.
- You need a local, repeatable audit report instead of a web tool that asks for your API key.

## What It Does Not Claim

- It does not certify that a relay is safe.
- It does not replace manual security review or operational monitoring.
- It does not treat `inconclusive` as `clean`; blocked probes and ambiguous responses stay visible in the report.

## Web3 Wallet Safety Checks

With `--profile web3` or `--profile full`, API Relay Audit adds wallet-oriented prompt injection probes inspired by signature-isolation risks:

- ETH transfer guidance checks
- Signed-transaction refusal checks
- Private-key leak refusal checks

These probes are model-agnostic, but they are intentionally profile-gated so general relay audits stay focused.

## Example Report And Live Page

- GitHub Pages: [toby-bridges.github.io/api-relay-audit](https://toby-bridges.github.io/api-relay-audit/)
- Chinese landing page: [toby-bridges.github.io/api-relay-audit/zh/](https://toby-bridges.github.io/api-relay-audit/zh/)
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

Model substitution means the relay claims to provide one model but routes you to another model or leaks a different model identity. API Relay Audit checks non-Claude identity patterns, anchor phrases, and stream model identity signals where available.

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

## How to Contribute

Good first contributions are small, reproducible, and evidence-focused: documentation examples, deterministic detector tests, or clearer wording around `clean`, `anomaly`, and `inconclusive` results.

Start with [CONTRIBUTING.md](./CONTRIBUTING.md), avoid publishing real API keys or private relay traffic, and keep changes scoped to one behavior or document.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=toby-bridges/api-relay-audit&type=Date)](https://www.star-history.com/#toby-bridges/api-relay-audit&Date)

<details id="chinese-readme">
<summary>中文 README</summary>

## API Relay Audit 是什么？

`api-relay-audit` 是一个本地运行的 AI API 中转站 / LLM proxy 安全审计工具。它检测 prompt injection、模型替换、工具调用改写、SSE 流异常、错误响应泄漏，以及 Web3 钱包相关风险；你的 API Key 只会发送到你指定的中转站 URL。

当你使用第三方 AI API 中转站、OpenAI-compatible proxy、Claude-compatible proxy，或者 Web3 agent 工作流时，可以用它在信任该中转站之前生成一份可复查的 Markdown 审计报告。

## 你会得到什么

- 一个本地运行的 14 步审计工具，输出结构化 Markdown 报告
- 双分发形态: `audit.py` 单文件零依赖版 + `api_relay_audit/` 模块化开发版
- `--profile general|web3|full` 三种运行模式
- `LOW / MEDIUM / HIGH` 总结论，加每一步的细项结果

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
- 模型身份: 非 Claude 身份泄漏、模型替换、Claude / OpenAI 兼容中转行为
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

## 主要入口

- 在线页 / GitHub Pages: [toby-bridges.github.io/api-relay-audit](https://toby-bridges.github.io/api-relay-audit/)
- 中文独立页: [toby-bridges.github.io/api-relay-audit/zh/](https://toby-bridges.github.io/api-relay-audit/zh/)
- 贡献者 / Credits: [CONTRIBUTORS.md](./CONTRIBUTORS.md)
- 安全政策: [SECURITY.md](./SECURITY.md)
- 贡献指南: [CONTRIBUTING.md](./CONTRIBUTING.md)
- 社交媒体: [X @li9292](https://x.com/li9292)

</details>
