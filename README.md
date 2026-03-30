# API Relay Audit

Security audit tool for third-party AI API relay/proxy services. Detects hidden prompt injection, prompt leakage, instruction override, and context truncation.

## 7-Step Audit

| Step | Test | What it detects |
|------|------|-----------------|
| 1 | Infrastructure Recon | DNS/WHOIS/SSL/CDN, hosting, certificate issues |
| 2 | Model List | Backend channels, model coverage |
| 3 | Token Injection | Hidden system prompt injection (delta method) |
| 4 | Prompt Extraction | Leakable hidden prompts (3 attack vectors) |
| 5 | Instruction Conflict | User system prompt being overridden (cat test + identity test) |
| 6 | Jailbreak | Weak anti-extraction defenses (3 methods) |
| 7 | Context Length | Truncation below advertised limit (canary markers + binary search) |

---

## Choose Your Way

### Option A: One-Liner (Zero Install)

For anyone who just wants to test a relay quickly. No git clone, no pip install.

```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py
python audit.py --key <YOUR_KEY> --url <BASE_URL>
```

Requirements: Python 3.7+ and `curl` (pre-installed on macOS/Linux/WSL).

---

### Option B: OpenClaw Skill

For [OpenClaw](https://github.com/openclaw/openclaw) users. The agent downloads the script, runs the audit, and interprets results for you.

**Install the skill**, then just tell the agent:

> "Test this relay: https://api.example.com/v1 with key sk-xxx"

The skill file is [`SKILL.md`](./SKILL.md) in this repo. It follows the OpenClaw skill format and is fully self-contained.

---

### Option C: Claude Code / Developer Setup

For developers who want to modify, extend, or contribute. The modular codebase with full test suite.

```bash
git clone https://github.com/toby-bridges/api-relay-audit.git
cd api-relay-audit
pip install httpx
python scripts/audit.py --key <YOUR_KEY> --url <BASE_URL> --output report.md
```

#### Project Structure

```
audit.py                  # Standalone version (zero-dependency, curl-only)
SKILL.md                  # OpenClaw skill definition
api_relay_audit/          # Shared Python modules
  client.py               #   API client (Anthropic + OpenAI + curl fallback)
  reporter.py             #   Markdown report generator
  context.py              #   Context length test algorithm
scripts/
  audit.py                #   Main 7-step audit (modular version, requires httpx)
  context-test.py         #   Standalone context length test
  extract-data.py         #   Extract structured data from reports
tests/                    #   80 pytest unit tests
web/
  index.html              #   Dashboard (single-page, vanilla JS)
deploy/
  deploy-nas.sh           #   Docker/nginx deployment script
```

#### Run Tests

```bash
pip install httpx pytest
python -m pytest tests/ -v
```

---

## CLI Options

All three options share the same CLI interface:

| Flag | Required | Description | Default |
|------|----------|-------------|---------|
| `--key` | Yes | API Key | - |
| `--url` | Yes | Base URL (e.g. `https://xxx.com/v1`) | - |
| `--model` | No | Model name | `claude-opus-4-6` |
| `--output` | No | Report output path (markdown) | stdout |
| `--skip-infra` | No | Skip infrastructure recon | `False` |
| `--skip-context` | No | Skip context length test | `False` |
| `--timeout` | No | Request timeout (seconds) | `120` |

## Risk Levels

| Level | Criteria | Recommendation |
|-------|----------|----------------|
| LOW | No injection + instructions work + full context | Safe to use |
| MEDIUM | Minor injection (<100 tokens) or prompt extractable | OK for simple tasks |
| HIGH | Injection >500 tokens or instructions overridden | Not recommended |

## License

MIT

---

## 中文说明

全面审计第三方 AI API 中转站（反代/转发站）的安全性、可靠性和透明度。

### 三种使用方式

**方式 A — 一行命令（零安装）：**
```bash
curl -sO https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py
python audit.py --key <你的KEY> --url <中转站地址>
```

**方式 B — OpenClaw Skill：** 安装 [`SKILL.md`](./SKILL.md) 后，直接对 agent 说"测试这个中转站"。

**方式 C — 开发者模式：** `git clone` 后使用模块化代码，可修改、扩展、跑测试。

### 风险等级

| 等级 | 判定条件 | 建议 |
|------|----------|------|
| LOW | 无注入 + 指令正常 + 上下文完整 | 可放心使用 |
| MEDIUM | 轻微注入（<100 tokens）或 prompt 可提取 | 简单任务可用 |
| HIGH | 注入 >500 tokens 或指令被覆盖 | 不推荐使用 |
