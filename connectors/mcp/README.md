# API Relay Audit MCP — local distribution candidate

Use API Relay Audit from an assistant through three local stdio tools. This
adapter starts the unchanged **v2.5.0** standalone engine, fixed to commit
`75bdac000051871c9f088a3be58e6f17a8854ffb`. It shares the released detection
rules and ratings with the CLI and retains private evidence on your computer.
The optional [official Python MCP SDK](https://github.com/modelcontextprotocol/python-sdk/tree/v2.3.0)
is pinned to `mcp==2.3.0`; the standalone CLI remains Python stdlib plus curl.

Package `api-relay-audit-mcp`, version `2.5.0.dev1`, is a **local, unpublished
candidate**. It has not been uploaded to PyPI, submitted to a registry, or
installed in a native assistant host. Package version and engine version are
separate: the bundled engine is the verified released v2.5.0 script.

## Tools

| Tool | Input | Result and effects |
| --- | --- | --- |
| `check_connectivity` | `target_id` | Sends two metered chat probes to one configured relay. Returns successful API formats; risk and coverage remain null. |
| `run_audit` | `target_id`, `mode`: `quick` (default) or `full` | Starts metered probes and promptly returns a local job ID. Both use the general profile and skip infrastructure. Quick also skips context and latency-variance tests; full includes them. |
| `get_audit_result` | `job_id`, `action`: `status` (default) or `cancel` | Returns status and, when completed, the existing rating, flag counts and coverage step numbers. Cancel stops the local audit process group. |

Example assistant request: "Run a quick audit of the configured target `relay`,
then check the job result." These tools accept no URL, API key, model, report
path or executable arguments. They expose no raw Markdown, flag messages,
response bodies, model names or target URLs to the host model.

A connectivity success is not a safety rating. LOW can coexist with
INCONCLUSIVE extraction evidence or skipped tests. Counts do not replace the
engine's risk matrix, and the summary does not certify that a relay is safe.
Both audit modes skip infrastructure and Web3 coverage and disable warm-up;
`full` describes the more thorough general audit rather than every CLI probe.
Review the original local JSON report before acting on a finding. That report
contains unredacted evidence and is not a public export.

## Local setup

Python **3.10+**, curl and a POSIX system are required. Development verification
uses macOS. Linux is a supported design target but has not been runtime-tested;
Windows is rejected because the process-group and descriptor safeguards require
POSIX behavior.

From this verified repository checkout, install into an isolated environment:

```bash
python3 -m venv /absolute/path/to/connector-venv
/absolute/path/to/connector-venv/bin/python -m pip install ./connectors/mcp
```

Create a private report directory. Copy `config.example.json` to a private
configuration file, replace the absolute report path, and configure only relay
targets you intend to test. The report directory must already exist. Target IDs
are local aliases, bound to `url`, a Claude model name and a dedicated `key_env`
name. Set `targets` to `{}` when checking server startup without network access.
Installed wheels also contain `config.example.json` and the four client templates
inside `api_relay_audit_mcp`; `importlib.resources.files("api_relay_audit_mcp")`
locates them without a repository checkout.

| Configuration field | Default | Accepted range / meaning |
| --- | --- | --- |
| `report_root` | Required | Existing absolute directory for private reports. |
| `targets` | `{}` | Local alias to `{url, model, key_env}`. |
| `timeout_seconds` | `30` | Connectivity deadline, 1–30 seconds. |
| `audit_timeout_seconds` | `300` | Total audit deadline, 1–1800 seconds. |
| `max_jobs` | `32` | Job capacity per server lifetime, 1–128. |

Provide each dedicated credential through the host's environment mechanism,
using a variable name such as `API_RELAY_AUDIT_RELAY_KEY`. Do not place its
value in chat, tool arguments, CLI arguments or the configuration file. The
server and selected audit child hold that credential in their OS environments;
this design does not protect against another process with permission to inspect
them. Startup and reading a result make no provider requests. Starting a
connectivity check or audit can incur provider charges; cancellation cannot
undo requests already sent.

Launch with either installed entry point:

```bash
/absolute/path/to/connector-venv/bin/api-relay-audit-mcp --config /absolute/path/to/private/connector.json
/absolute/path/to/connector-venv/bin/python -m api_relay_audit_mcp --config /absolute/path/to/private/connector.json
```

Stdout carries MCP only. The child receives its selected credential through
`--key-env`; diagnostics are discarded. Proxy environment variables are not
forwarded. A private, empty curl configuration prevents user curl defaults
from changing the configured request destination.

**Inherited v2.5.0 transport limitation:** the byte-identical standalone engine
uses `curl -sk`, which bypasses TLS certificate verification. Requiring HTTPS
in target configuration does not authenticate that server's certificate.
Review this limitation before supplying a real credential. Addressing it would
require a separately reviewed engine change and a new engine baseline.

## Job lifecycle and private evidence

One metered operation runs at a time; competing requests return `connector_busy`.
Audit jobs remain associated with the server that started them. Poll the returned
job ID with `get_audit_result`; cancel it with `action="cancel"` when needed.
The configured job limit bounds retained job metadata and summaries. It does
not impose a general memory ceiling on the unchanged CLI's raw HTTP handling.
Jobs do not resume after server restart.
Shutdown, cancellation and total timeout terminate and reap audit descendants,
including curl processes. SIGTERM/SIGINT and normal stdin closure run that
cleanup. SIGKILL, machine failure or a crashed interpreter cannot run cleanup;
operating-system supervision is required to guarantee termination in those cases.

Captured CLI JSON reports are capped at 1 MiB and summarized by selecting
allowlisted fields. The adapter does not cap raw HTTP response memory inside
the unchanged engine. A completed job's `report_file` names its private JSON
file under `report_root`; generated files have mode `0600`.
Untrusted relay text is never forwarded as tool instructions. File access refuses
traversal, symlinks and non-regular files. Protect the report directory and its
ancestors from modification by other users. Retained reports remain sensitive;
local summaries are not a replacement for a separate reviewed public export.

## Client templates

Templates in `examples/` are not installed configuration. Replace the absolute
Python/config paths, supply the dedicated variable in the host environment,
and merge the named server entry with your existing configuration.

| Host | Template | Destination | Verification boundary |
| --- | --- | --- | --- |
| Claude Code | `examples/claude-code.json` | Project `.mcp.json` | Official configuration shape; native session unverified. |
| Codex | `examples/codex.toml` | `[mcp_servers.relay-audit]` in `config.toml` | Configuration recipe; native session unverified. |
| Cursor | `examples/cursor.json` | `.cursor/mcp.json` | Official configuration shape; native session unverified. |
| VS Code / Copilot | `examples/vscode-copilot.json` | Portable project `.mcp.json` | Official portable shape; native session unverified. |

Official references checked 2026-10-14:
[Claude Code](https://code.claude.com/docs/en/mcp),
[Codex configuration](https://learn.chatgpt.com/docs/config-file/config-reference),
[Cursor](https://cursor.com/docs/mcp),
[VS Code](https://code.visualstudio.com/docs/agent-customization/mcp-servers).
SDK stdio tests are distinct from installing and invoking the connector in
these hosts. DSH distribution remains independent. Remote hosting requires
a separate HTTP, authentication and deployment phase.

## Build and verify

```bash
/absolute/path/to/connector-venv/bin/python -m pip install build pytest
/absolute/path/to/connector-venv/bin/python -m build connectors/mcp
/absolute/path/to/connector-venv/bin/python -m pytest connectors/mcp/tests/ -q
```

Wheel and source archive contain the exact released standalone script as
`api_relay_audit_mcp/_audit.py`. The build copies it from the repository rather
than maintaining another checked-in script. A source archive carries that
generated copy so it can rebuild independently of the repository. Both build
paths refuse bytes that differ from the engine SHA-256 in `provenance.json`:
`fd99409bf745090a26bb4616fd33fbe0d873de08cfe077df413b2b93845f151d`.

Tests use synthetic credentials and local loopback fixtures. They cover real
stdio initialization, schemas, status/cancel, private evidence exclusion,
bounded input, process cleanup and package contents. Real-provider behavior,
Linux runtime, native host activation and public package/registry acceptance
remain unverified. Public distribution needs a separate approved release step;
the candidate package name has not been reserved or verified available.

## License and provenance

Adapter and bundled engine use the repository's **AGPL-3.0-only** license;
`LICENSE` is included in the distribution. The optional MCP SDK uses **MIT**.
The bundle records source repository, fixed commit, engine hash and package
version in `api_relay_audit_mcp/provenance.json`. This independent adapter does
not imply endorsement by an assistant host or SDK maintainer.
