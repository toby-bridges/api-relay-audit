# API Relay Audit

by [@li9292](https://x.com/li9292)

Security audit tool for third-party AI API relay/proxy services. Detects hidden prompt injection, prompt leakage, instruction override, context truncation, tool-call package substitution (AC-1.a), and error response header leakage (AC-2 adjacent).

Threat model follows the AC-1 / AC-1.a / AC-1.b / AC-2 taxonomy from Liu et al., [*Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the LLM Supply Chain*, arXiv:2604.08407](https://arxiv.org/abs/2604.08407).

## What's New in v2.2 (v3 Feature Release, PR 1)

v2.2 adds **Step 9: Error Response Header Leakage (AC-2 adjacent)**. Paper Figure 3 reports credential abuse at 4.25% of 400 free routers — twice as common as AC-1 code injection (2%). This step fires 5-6 deterministic broken requests (malformed JSON, invalid model, wrong content-type, missing fields, unknown endpoint, optional 256 KB oversized body) and scans the error body **and response headers** for echoed `Authorization` values, the first-8 API key prefix, upstream provider URLs (`api.anthropic.com` / `api.openai.com`), env var names (`OPENAI_API_KEY=`), filesystem paths, and stack-trace markers. The risk matrix expands to 4 dimensions — a `critical` or `high` leakage on its own escalates straight to HIGH, matching Step 8's severity. Two new flags ship alongside: `--skip-error-leakage` to opt out, and `--aggressive-error-probes` to enable the 256 KB oversized-context probe (warning: may incur metered billing on pay-as-you-go relays).

## What's New in v2

v2 added **Step 8: AC-1.a tool-call substitution detection**, which catches malicious relays that rewrite package-install commands on the return path (e.g. `pip install requests` → `reqeusts` typosquat) by asking the model to echo four pinned install commands verbatim and diffing the result token-by-token. The risk matrix was extended to three dimensions — a single tool-call substitution on its own escalates straight to HIGH, independent of injection/instruction-override signals. Two flags ship alongside: `--skip-tool-substitution` to opt out, and `--warmup N` to fire N benign requests before the audit as a partial mitigation for AC-1.b request-count-gated backdoors.

## 9-Step Audit

| Step | Test | What it detects |
|------|------|-----------------|
| 1 | Infrastructure Recon | DNS/WHOIS/SSL/CDN, hosting, certificate issues |
| 2 | Model List | Backend channels, model coverage |
| 3 | Token Injection | Hidden system prompt injection (delta method) |
| 4 | Prompt Extraction | Leakable hidden prompts (3 attack vectors) |
| 5 | Instruction Conflict | User system prompt being overridden (cat test + identity test) |
| 6 | Jailbreak | Weak anti-extraction defenses (3 methods) |
| 7 | Context Length | Truncation below advertised limit (canary markers + binary search) |
| 8 | Tool-Call Substitution (AC-1.a) | Package-name rewriting on the return path (`requests` → `reqeusts` typosquat) |
| 9 | Error Response Leakage (AC-2 adjacent) | Echoed `Authorization` / API key prefix / upstream URL / env var name / FS path / stack trace in error responses |

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
| `--skip-tool-substitution` | No | Skip AC-1.a tool-call substitution test | `False` |
| `--skip-error-leakage` | No | Skip Step 9 AC-2 adjacent error response leakage test | `False` |
| `--aggressive-error-probes` | No | Enable 256 KB oversized-context probe in Step 9 (may incur billing) | `False` |
| `--warmup` | No | Send N benign requests before the audit (partial AC-1.b mitigation) | `0` |
| `--timeout` | No | Request timeout (seconds) | `120` |

## Risk Levels

| Level | Criteria | Recommendation |
|-------|----------|----------------|
| LOW | No injection + instructions work + full context + no tool-call substitution + no error leakage | Safe to use |
| MEDIUM | Minor injection (<100 tokens) OR prompt extractable OR Step 8/9 inconclusive OR Step 9 medium-only leakage | OK for simple tasks |
| HIGH | Injection >100 tokens AND instructions overridden, OR any tool-call substitution (Step 8), OR Step 9 critical/high leakage (credential echo, upstream URL, env var) | Not recommended |

## Author

[@li9292](https://x.com/li9292)

## License

MIT

---

## 中文说明

全面审计第三方 AI API 中转站（反代/转发站）的安全性、可靠性和透明度。

### v2 新增

v2 新增**第 8 步：AC-1.a 工具调用改写检测**，通过让模型逐字复述四条固定的包安装命令（pip/npm/cargo/go），按 token 对比返回文本，识别恶意中转站在返回路径上偷换包名（例如 `requests` → `reqeusts` 拼写投毒）。风险矩阵升级为三维判定——只要检测到任何一次工具调用改写，单独就会直接升级为 HIGH，无需其他指标叠加。同步新增两个 CLI 开关：`--skip-tool-substitution` 跳过第 8 步，`--warmup N` 在审计前先发 N 次无害请求，作为对 AC-1.b 请求次数门控后门的部分缓解。

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
