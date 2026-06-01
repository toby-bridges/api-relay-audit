<p align="center">
  <img alt="API Relay Audit - AI API Relay Security Audit. Prompt Injection, Model Substitution, Tool Rewriting, SSE Anomalies. Runs Locally, Your API Key Stays Local." src="./assets/readme-banner.png">
</p>

# API Relay Audit

<p align="center">
  Security audit for third-party AI API relay / proxy services.
</p>

<p align="center">
  <a href="#readme-zh"><img alt="README 中文" src="https://img.shields.io/badge/README-%E4%B8%AD%E6%96%87-111111?style=for-the-badge"></a>
  <a href="#readme-en"><img alt="README English" src="https://img.shields.io/badge/README-English-f5f5f5?style=for-the-badge&labelColor=111111&color=f5f5f5"></a>
</p>

<p align="center">
  <a href="https://toby-bridges.github.io/api-relay-audit/"><img alt="GitHub Pages" src="https://img.shields.io/badge/GitHub%20Pages-Live%20Site-0a7f5a?style=for-the-badge"></a>
  <a href="https://x.com/li9292"><img alt="X @li9292" src="https://img.shields.io/badge/X-%40li9292-111111?style=for-the-badge"></a>
  <a href="https://github.com/toby-bridges"><img alt="GitHub toby-bridges" src="https://img.shields.io/badge/GitHub-toby--bridges-24292f?style=for-the-badge"></a>
</p>

<p align="center">
  <a href="./ROADMAP.md"><strong>ROADMAP</strong></a>
  ·
  <a href="./FOR_JOHN.md"><strong>Engineering Diary</strong></a>
  ·
  <a href="./SKILL.md"><strong>OpenClaw Skill</strong></a>
  ·
  <a href="./skills/api-relay-audit/SKILL.md"><strong>Hermes Skill</strong></a>
</p>

---

<a id="readme-zh"></a>

## 中文

`api-relay-audit` 用来审计第三方 AI API 中转站 / 反代 / relay 是否在请求与响应链路里做了不该做的事: hidden prompt 注入、prompt 泄漏、指令覆盖、上下文截断、工具调用改写、错误响应泄漏、SSE 流异常，以及 Web3 场景下的钱包安全风险。

### 你会得到什么

- 一个本地运行的 14 步审计工具，输出结构化 Markdown 报告
- 双分发形态: `audit.py` 单文件零依赖版 + `api_relay_audit/` 模块化开发版
- `--profile general|web3|full` 三种运行模式
- `LOW / MEDIUM / HIGH` 总结论，加每一步的细项结果

### 30 秒快速开始

```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py

python audit.py --key <YOUR_KEY> --url <BASE_URL> --output report.md

# Web3 / 钱包用户
python audit.py --key <YOUR_KEY> --url <BASE_URL> --profile web3 --output report.md
```

### 核心覆盖

- Prompt 安全: token injection、prompt extraction、instruction override、jailbreak
- Relay 完整性: context truncation、tool-call substitution、error leakage、stream integrity
- Web3 风险: 转账指引、签名拒绝、私钥泄漏拒绝
- Informational checks: infrastructure fingerprint、latency variance

### 主要入口

- 在线页 / GitHub Pages: [toby-bridges.github.io/api-relay-audit](https://toby-bridges.github.io/api-relay-audit/)
- 路线图与明确不做: [ROADMAP.md](./ROADMAP.md)
- 工程记录: [FOR_JOHN.md](./FOR_JOHN.md)
- 贡献者 / Credits: [CONTRIBUTORS.md](./CONTRIBUTORS.md)
- 社交媒体: [X @li9292](https://x.com/li9292)

---

<a id="readme-en"></a>

## English

`api-relay-audit` audits third-party AI API relays / proxies for hidden prompt injection, prompt leakage, instruction override, context truncation, tool-call rewriting, error-response leakage, SSE stream anomalies, and wallet-safety risks in Web3 flows.

### What you get

- A local 14-step audit that produces a structured Markdown report
- Dual distribution: zero-dependency standalone `audit.py` plus modular `api_relay_audit/`
- Three runtime profiles: `general`, `web3`, and `full`
- One final `LOW / MEDIUM / HIGH` verdict plus per-step details

### Quick Start

```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py

python audit.py --key <YOUR_KEY> --url <BASE_URL> --output report.md

# Web3 / wallet users
python audit.py --key <YOUR_KEY> --url <BASE_URL> --profile web3 --output report.md
```

### Coverage

- Prompt safety: token injection, prompt extraction, instruction override, jailbreak
- Relay integrity: context truncation, tool-call substitution, error leakage, stream integrity
- Web3 safety: transfer guidance, sign refusal, private-key refusal
- Informational checks: infrastructure fingerprint, latency variance

### Key links

- GitHub Pages: [toby-bridges.github.io/api-relay-audit](https://toby-bridges.github.io/api-relay-audit/)
- Shipped / deferred / explicitly not doing: [ROADMAP.md](./ROADMAP.md)
- Engineering diary: [FOR_JOHN.md](./FOR_JOHN.md)
- Contributors / Credits: [CONTRIBUTORS.md](./CONTRIBUTORS.md)
- Social: [X @li9292](https://x.com/li9292)

## License

AGPL-3.0-only. See [LICENSE](./LICENSE).

This keeps modified network-service deployments accountable to the same public
source-availability standard as the relay ecosystem evidence we audit.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=toby-bridges/api-relay-audit&type=Date)](https://www.star-history.com/#toby-bridges/api-relay-audit&Date)
