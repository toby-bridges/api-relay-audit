# Native host verification

These opt-in scripts exercise the installed MCP wheel through genuine local
Codex and Claude Code executables. They run on the existing Mac using fresh
temporary state, synthetic credentials and loopback providers. They do not
require another computer, an account login or a paid model request.

The [recorded results](verification.json) are a dated acceptance snapshot,
not a guarantee about other host versions. Ordinary pytest and hosted CI do
not run these native executables.

## Reproduce from the repository

Use Python 3.10+, curl, a POSIX system and installed native host executables.
The recorded runtime is macOS with Python 3.14.3. Claude Code must be at least
2.1.286, whose bare mode includes the required isolation fixes. Codex must
support app-server experimental `mcpServer/tool/call`; the script also requires
a public model catalog embedded in its executable and fails if unavailable.

From the repository root:

```sh
python3 -m venv connectors/mcp/.venv
connectors/mcp/.venv/bin/python -m pip install ./connectors/mcp build pytest
connectors/mcp/.venv/bin/python -m build connectors/mcp
connectors/mcp/.venv/bin/python connectors/mcp/native/codex_host.py --output connectors/mcp/reports/native-codex.json
connectors/mcp/.venv/bin/python connectors/mcp/native/claude_host.py --output connectors/mcp/reports/native-claude.json
```

Both scripts require exactly one matching candidate wheel in `dist/` and
record its SHA-256. They install it into a private temporary directory using
`pip --no-index --no-deps`. The interpreter's environment supplies the already
installed SDK dependencies. Native calls use the installed package and its
bundled engine rather than importing the adapter from the source tree. Only
sanitized assertions, versions, counters and hashes are printed or saved.
Temporary state, reports and fixture installations are removed after each run.

`codex` and `claude` are resolved through PATH; Claude also accepts an explicit
`--claude /absolute/path/to/binary`. The scripts do not install or update hosts.

## What the tests establish

| Host | Actual path exercised | Acceptance |
| --- | --- | --- |
| Codex app-server | Native initialization, ephemeral thread, MCP discovery and direct native tool dispatch; no model turn | Exactly one server and three tools; connectivity is unrated; errors are fixed labels; quick audit preserves HIGH and skipped steps; an active audit can be cancelled; stdin EOF reaps the MCP server, audit and curl descendants. |
| Claude Code | Headless native tool scheduler driven by a separate scripted Anthropic Messages/SSE provider | Three scenarios: connectivity, completed HIGH audit plus cancellation, and host exit during an actual slow relay request. Native discovery sees only the three configured tools; observed descendants do not survive exit. |

The relay being audited is a separate fixture. It deliberately puts a synthetic
key and untrusted text in responses and failures. Assertions scan full MCP
tool results and native outputs, and the Claude provider scans tool-result
content before consuming it. Native cleanup is observed before any emergency
harness cleanup; forced termination or surviving descendants fail acceptance.

Codex stdout includes the operator-requested `config/read` response. It
intentionally contains the generated synthetic environment and local provider
address. That single successful response is classified by its outstanding
request ID and expected result structure. Every line is scanned; only this
administrative response may contain those fixture markers. Errors, unmatched
responses, notifications, stderr and all tool responses retain strict checks.
Only the administrative marker count is retained, never the raw config.

## Isolation and remaining gates

Codex receives a fresh `CODEX_HOME` in its child environment, an ephemeral auth
backend, disabled apps/plugins/telemetry/updates, and the executable's public
bundled catalog. Its provider URL points to the fixture; managed requirements
that conflict with the tested choices cause failure. Claude receives a fresh
`CLAUDE_CONFIG_DIR`, bare mode, strict MCP configuration, no settings sources,
no built-in tools or session persistence, and disabled nonessential traffic.
The parent environment and existing host settings are not changed. Personal
credentials are not supplied or configured for these tests.

This is configuration isolation, not a firewall or packet-capture result.
It does not prove the absence of all host bootstrap access or physical network
egress. It also does not prove GUI setup, real model tool selection, real
provider/account policies, Cursor/VS Code compatibility, Linux runtime or a
fresh-machine install. A separate clean user account or VM is useful later
for installation acceptance; it is not required for these native protocol tests.
The adapter still inherits the unchanged v2.5.0 engine's `curl -sk` TLS behavior.

Official references checked 2026-10-14:
[Codex app-server](https://learn.chatgpt.com/docs/app-server),
[Codex config](https://learn.chatgpt.com/docs/config-file/config-reference),
[Codex environment](https://learn.chatgpt.com/docs/config-file/environment-variables),
[Claude headless](https://code.claude.com/docs/en/headless),
[Claude CLI](https://code.claude.com/docs/en/cli-reference),
[Claude environment](https://code.claude.com/docs/en/env-vars),
[Claude gateway protocol](https://code.claude.com/docs/en/llm-gateway-protocol).
