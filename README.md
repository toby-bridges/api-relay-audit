# API Relay Audit

Security audit tool for third-party AI API relay/proxy services. Detects hidden prompt injection, prompt leakage, instruction override, and context truncation.

[中文说明](#中文说明)

## Features

| Test | Method | What it detects |
|------|--------|-----------------|
| **Infrastructure Recon** | DNS/WHOIS/SSL/HTTP headers | CDN, hosting, certificate issues, system type |
| **Token Injection** | Delta method (expected vs actual `input_tokens`) | Hidden system prompt injection |
| **Prompt Extraction** | 3 attack vectors (verbatim, translation, JSON) | Leakable hidden prompts |
| **Instruction Conflict** | Cat test + identity override | User system prompt being overridden |
| **Jailbreak** | 3 methods (diagnostic, Base64, role play) | Weak anti-extraction defenses |
| **Context Length** | 5 canary markers + binary search | Context truncation below advertised limit |

## Quick Start

```bash
# Install
pip install httpx

# Run full audit
python scripts/audit.py \
  --key YOUR_API_KEY \
  --url https://api.example.com/v1 \
  --model claude-opus-4-6 \
  --output report.md
```

## CLI Options

| Flag | Required | Description | Default |
|------|----------|-------------|---------|
| `--key` | Yes | API Key | - |
| `--url` | Yes | Base URL (e.g. `https://xxx.com/v1`) | - |
| `--model` | No | Model name | `claude-opus-4-6` |
| `--output` | No | Report output path | stdout |
| `--skip-infra` | No | Skip infrastructure recon | `False` |
| `--skip-context` | No | Skip context length test | `False` |
| `--timeout` | No | Request timeout (seconds) | `120` |

## Standalone Context Test

```bash
python scripts/context-test.py \
  --key YOUR_API_KEY \
  --url https://api.example.com/v1 \
  --model claude-opus-4-6
```

## Risk Levels

| Level | Criteria | Recommendation |
|-------|----------|----------------|
| LOW | No injection + instructions work + full context | Safe to use |
| MEDIUM | Minor injection (<100 tokens) or prompt extractable | OK for simple tasks |
| HIGH | Injection >500 tokens or instructions overridden | Not recommended |

## Project Structure

```
api_relay_audit/          # Shared Python modules
  client.py               # API client (Anthropic + OpenAI + curl fallback)
  reporter.py             # Markdown report generator
scripts/
  audit.py                # Main 7-step audit
  context-test.py         # Standalone context test
  extract-data.py         # Extract structured data from reports
web/
  index.html              # Dashboard (single-page, vanilla JS)
  data-example.json       # Example data (sanitized)
deploy/
  deploy-nas.sh           # Docker/nginx deployment script
```

## Web Dashboard

Deploy the results dashboard to any server with Docker:

```bash
./deploy/deploy-nas.sh <HOST> <USER> <PASSWORD> <PORT>
```

Then visit `http://<HOST>:<PORT>` to see the security ranking and detailed reports.

## Requirements

- Python 3.7+
- `httpx` (`pip install httpx`)
- `curl` (for SSL fallback, pre-installed on macOS/Linux)
- Optional: `dig`, `whois`, `openssl` (for infrastructure recon)

## License

MIT

---

## 中文说明

全面审计第三方 AI API 中转站（反代/转发站）的安全性、可靠性和透明度。

### 功能列表

- **基础设施摸底** — DNS/WHOIS/SSL/CDN 识别
- **Token 注入检测** — 差额法精确测量隐藏 prompt 注入量
- **Prompt 提取测试** — 3 种攻击手法提取隐藏 system prompt
- **指令冲突测试** — 猫叫测试 + 身份覆盖测试
- **越狱防护评估** — 测试中转站是否有反提取机制
- **上下文长度验证** — 5 标记词 + 二分查找精确边界
- **API 格式自动检测** — 自动识别 Anthropic 原生 / OpenAI 兼容格式

### 快速开始

```bash
pip install httpx

python scripts/audit.py \
  --key sk-xxxxx \
  --url https://api.example.com/v1 \
  --model claude-opus-4-6 \
  --output report.md
```

### 风险等级

| 等级 | 判定条件 | 建议 |
|------|----------|------|
| LOW | 无注入 + 指令正常 + 上下文完整 | 可放心使用 |
| MEDIUM | 轻微注入（<100 tokens）或 prompt 可提取 | 简单任务可用 |
| HIGH | 注入 >500 tokens 或指令被覆盖 | 不推荐使用 |
