"""Optional stdio entry point. No audit or diagnostic output reaches stdout."""
import argparse
from contextlib import asynccontextmanager
import json
import logging
import os
from pathlib import Path
import signal
import stat
import sys
from typing import Any, Literal

import anyio
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError
from mcp.types import CallToolResult, TextContent, ToolAnnotations

from . import __version__
from .adapter import Configuration, Connector


class PrivateMCPServer(MCPServer):
    """Do not reflect SDK validation errors or unknown peer-supplied names."""

    async def call_tool(self, name: str, arguments: dict[str, Any], context=None):
        schemas = {
            "check_connectivity": ({"target_id"}, {"target_id"}),
            "run_audit": ({"target_id"}, {"target_id", "mode"}),
            "get_audit_result": ({"job_id"}, {"job_id", "action"}),
        }

        def failure(code):
            payload = {"ok": False, "error": code}
            return CallToolResult(content=[TextContent(text=json.dumps(payload))],
                                  structured_content=payload, is_error=True)

        if name not in schemas:
            return failure("unknown_tool")
        required, allowed = schemas[name]
        if not isinstance(arguments, dict) or not required <= arguments.keys() or not arguments.keys() <= allowed:
            return failure("invalid_tool_arguments")
        if any(type(value) is not str for value in arguments.values()):
            return failure("invalid_tool_arguments")
        if name == "run_audit" and arguments.get("mode", "quick") not in ("quick", "full"):
            return failure("invalid_tool_arguments")
        if name == "get_audit_result" and arguments.get("action", "status") not in ("status", "cancel"):
            return failure("invalid_tool_arguments")
        try:
            return await super().call_tool(name, arguments, context)
        except UnexpectedToolError:
            return failure("connector_failed")
        except ToolError:
            return failure("invalid_tool_arguments")
        except Exception:
            return failure("connector_failed")


def build_server(connector: Connector):
    @asynccontextmanager
    async def lifespan(_server):
        try:
            yield None
        finally:
            await connector.close()

    server = PrivateMCPServer("API Relay Audit", version=__version__, lifespan=lifespan, log_level="CRITICAL")

    @server.tool(structured_output=True, annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                            idempotentHint=False, openWorldHint=True))
    async def check_connectivity(target_id: str) -> dict[str, Any]:
        """Send two metered chat probes to one preconfigured target.

        target_id is a local configuration alias. No URL, credential, model, or
        executable input is accepted. Success is connectivity, not a safety rating.
        """
        return await connector.check_connectivity(target_id)

    @server.tool(structured_output=True, annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                            idempotentHint=False, openWorldHint=True))
    async def run_audit(target_id: str, mode: Literal["quick", "full"] = "quick") -> dict[str, Any]:
        """Start metered audit probes against one preconfigured target.

        Returns a local job ID promptly. Poll get_audit_result for completion.
        Both modes use the general profile and skip infrastructure checks.
        Quick also skips context and latency-variance tests; full includes them.
        Review evidence locally. A LOW rating does not certify relay safety.
        """
        return await connector.run_audit(target_id, mode)

    @server.tool(structured_output=True, annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                            idempotentHint=True, openWorldHint=False))
    async def get_audit_result(job_id: str, action: Literal["status", "cancel"] = "status") -> dict[str, Any]:
        """Read a local job's status and allowlisted summary, or cancel it.

        No target URL, credentials, model reply, flag message or raw evidence is
        returned. Cancellation stops the local audit process and descendants;
        requests already sent to the relay may still be billed.
        """
        return await connector.get_audit_result(job_id, action)

    return server


class ArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "Invalid local connector arguments.\n")


def read_configuration(path: Path):
    """Read bounded regular-file configuration without echoing private input."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024:
            raise ValueError("invalid_configuration")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError("invalid_configuration")
        return Configuration.model_validate(json.loads(raw))
    finally:
        os.close(fd)


async def run_stdio(connector: Connector):
    """Unwind the server and reap independent audit groups on host termination."""
    server = build_server(connector)
    async with anyio.create_task_group() as tasks:
        async def receive_signals():
            with anyio.open_signal_receiver(signal.SIGTERM, signal.SIGINT) as signals:
                async for _signum in signals:
                    tasks.cancel_scope.cancel()
                    return

        tasks.start_soon(receive_signals)
        try:
            await server.run_stdio_async()
        finally:
            tasks.cancel_scope.cancel()
            with anyio.CancelScope(shield=True):
                await connector.close()


def main():
    parser = ArgumentParser(allow_abbrev=False, description="Local stdio MCP adapter for API Relay Audit v2.5.0.")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.CRITICAL, stream=sys.stderr)
    try:
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("preview_requires_posix")
        connector = Connector(read_configuration(Path(args.config).expanduser()))
    except Exception:
        print("Invalid local connector configuration.", file=sys.stderr)
        return 2
    try:
        anyio.run(run_stdio, connector)
    except Exception:
        print("Local connector server failed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
