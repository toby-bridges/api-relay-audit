"""Bounded local jobs and allowlisted summaries of the unchanged audit CLI."""
from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import tempfile
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

import anyio
from pydantic import BaseModel, ConfigDict, Field, ValidationError

MAX_REPORT_BYTES = 1024 * 1024
_PACKAGED_SCRIPT = Path(__file__).with_name("_audit.py")
AUDIT_SCRIPT = (_PACKAGED_SCRIPT if _PACKAGED_SCRIPT.is_file()
                else Path(__file__).resolve().parents[3] / "audit.py")


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")


class Target(StrictModel):
    url: str
    model: str
    key_env: str


class Configuration(StrictModel):
    report_root: str
    targets: dict[str, Target] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=30, ge=1, le=30)
    audit_timeout_seconds: int = Field(default=300, ge=1, le=1800)
    max_jobs: int = Field(default=32, ge=1, le=128)


class Coverage(StrictModel):
    skipped_steps: list[str]
    risk_matrix_inconclusive_steps: list[str]
    crashed_steps: list[str]


class Flag(StrictModel):
    level: Literal["red", "yellow", "green"]
    message: str


class Report(BaseModel):
    # Unknown fields can contain evidence: select a fresh allowlisted object.
    model_config = ConfigDict(strict=True, extra="ignore")
    schema_version: Literal[1]
    report_type: Literal["audit", "connectivity"]
    generated_at: str
    target: str
    model: str
    profile: Literal["general", "web3", "full"]
    tool_version: str
    tool_commit: str
    risk_level: Literal["LOW", "MEDIUM", "HIGH"] | None
    flags: list[Flag]
    coverage: Coverage | None
    markdown: str
    connectivity: dict | None = None


def error(code: str) -> dict:
    """Never echo caller input, exceptions, credentials, or relay responses."""
    return {"ok": False, "error": code}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_field")
        result[key] = value
    return result


def summarize(raw: bytes) -> dict:
    try:
        if len(raw) > MAX_REPORT_BYTES:
            return error("report_too_large")
        data = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(data, dict) or type(data.get("schema_version")) is not int:
            return error("invalid_report")
        report = Report.model_validate(data)
        if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", report.tool_version):
            return error("invalid_report")
        if not re.fullmatch(r"(?:[0-9a-f]{7,40})?", report.tool_commit):
            return error("invalid_report")
        counts = Counter(flag.level for flag in report.flags)
        result = {
            "ok": True,
            "schema_version": 1,
            "report_type": report.report_type,
            "tool_version": report.tool_version,
            "tool_commit": report.tool_commit,
            "profile": report.profile,
            "risk_level": report.risk_level,
            "flag_counts_by_level": {level: counts[level] for level in ("red", "yellow", "green")},
            "coverage": None,
            "evidence_requires_local_review": True,
        }
        if report.report_type == "audit":
            if report.coverage is None or report.risk_level is None:
                return error("invalid_report")
            result["coverage"] = {}
            for field in Coverage.model_fields:
                steps = getattr(report.coverage, field)
                result["coverage"][field] = {
                    "count": len(steps),
                    "step_numbers": sorted({int(match.group(1)) for step in steps
                        if (match := re.match(r"^Step (1[0-4]|[1-9])(?: |$)", step))}),
                }
        else:
            if report.risk_level is not None or report.coverage is not None:
                return error("invalid_report")
            connectivity = report.connectivity
            if not isinstance(connectivity, dict) or type(connectivity.get("success")) is not bool:
                return error("invalid_report")
            formats = connectivity.get("successful_formats")
            if not isinstance(formats, list) or any(x not in ("Anthropic Chat", "OpenAI Chat") for x in formats):
                return error("invalid_report")
            if connectivity["success"] != bool(formats):
                return error("invalid_report")
            result["connectivity"] = {
                "success": connectivity["success"],
                "successful_formats": formats,
            }
        return result
    except (ValueError, TypeError, UnicodeError, ValidationError, RecursionError):
        return error("invalid_report")


@dataclass
class Job:
    job_id: str
    mode: str
    status: str = "running"
    task: asyncio.Task | None = None
    result: dict | None = None
    error_code: str | None = None
    report_file: str | None = None
    cancel_requested: bool = False

    def snapshot(self) -> dict:
        value = {"ok": True, "job_id": self.job_id, "status": self.status, "mode": self.mode}
        if self.result is not None:
            value["result"] = self.result
        if self.error_code is not None:
            value["error"] = self.error_code
        if self.report_file is not None:
            value["report_file"] = self.report_file
        return value


class ExecutionError(Exception):
    def __init__(self, code):
        self.code = code


class Connector:
    """All path, network, credential and executable choices stay local."""

    def __init__(self, config: Configuration):
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("preview_requires_posix")
        root = Path(config.report_root).expanduser()
        if not root.is_absolute() or not root.is_dir():
            raise ValueError("invalid_configuration")
        for target_id, target in config.targets.items():
            url = urlsplit(target.url)
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", target_id):
                raise ValueError("invalid_configuration")
            if url.scheme not in ("https", "http") or not url.hostname or url.username or url.password or url.query or url.fragment:
                raise ValueError("invalid_configuration")
            if url.scheme == "http" and url.hostname not in ("127.0.0.1", "localhost", "::1"):
                raise ValueError("invalid_configuration")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", target.model) or "claude" not in target.model.lower():
                raise ValueError("invalid_configuration")
            if not re.fullmatch(r"API_RELAY_AUDIT_[A-Z0-9_]+", target.key_env):
                raise ValueError("invalid_configuration")
        self.root = root.resolve(strict=True)
        self._root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.config = config
        self.running: set[asyncio.subprocess.Process] = set()
        self.jobs: dict[str, Job] = {}
        self.lock = asyncio.Lock()
        self._closing = False
        self._closed = asyncio.Event()
        self._executions: set[asyncio.Task] = set()

    def read_report(self, relative_path: str) -> dict:
        """Internal compatibility helper, never exposed as an arbitrary path tool."""
        if self._closing or not isinstance(relative_path, str):
            return error("invalid_report_path")
        path = Path(relative_path)
        if not relative_path or path.is_absolute() or ".." in path.parts or path.suffix != ".json":
            return error("invalid_report_path")
        descriptors = []
        try:
            directory = os.dup(self._root_fd)
            descriptors.append(directory)
            for part in path.parts[:-1]:
                directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                descriptors.append(directory)
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            descriptors.append(fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return error("invalid_report_path")
            if info.st_size > MAX_REPORT_BYTES:
                return error("report_too_large")
            with os.fdopen(os.dup(fd), "rb") as stream:
                return summarize(stream.read(MAX_REPORT_BYTES + 1))
        except (OSError, ValueError):
            return error("invalid_report_path")
        finally:
            for fd in reversed(descriptors):
                os.close(fd)

    def _credential(self, target_id):
        target = self.config.targets.get(target_id) if isinstance(target_id, str) else None
        if target is None:
            return None, None, "unknown_target"
        key = os.environ.get(target.key_env)
        if not key:
            return None, None, "credential_unavailable"
        if self._closing:
            return None, None, "connector_closed"
        return target, key, None

    async def _stop(self, process: asyncio.subprocess.Process):
        # Kill descendants even if the parent has exited while a pipe remains open.
        with anyio.CancelScope(shield=True):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()

    async def _execute(self, target: Target, key: str, options: list[str], deadline: int):
        if self._closing:
            raise ExecutionError("connector_closed")
        owner = asyncio.current_task()
        self._executions.add(owner)
        try:
            return await self._execute_child(target, key, options, deadline)
        finally:
            self._executions.discard(owner)

    async def _execute_child(self, target: Target, key: str, options: list[str], deadline: int):
        process = None
        child_env = {name: os.environ[name] for name in ("PATH", "LANG", "LC_ALL") if name in os.environ}
        child_env["API_RELAY_AUDIT_CONNECTOR_KEY"] = key
        # An empty curl default file prevents real-user curlrc from adding URLs,
        # redirects or output paths. The user's environment is never changed.
        with tempfile.TemporaryDirectory(prefix="api-relay-audit-mcp-") as curl_config:
            config_file = Path(curl_config) / ".curlrc"
            config_file.touch(mode=0o600)
            child_env["CURL_HOME"] = curl_config
            try:
                with anyio.CancelScope(shield=True):
                    spawn = asyncio.create_task(asyncio.create_subprocess_exec(
                        sys.executable, "-S", str(AUDIT_SCRIPT),
                        "--key-env", "API_RELAY_AUDIT_CONNECTOR_KEY",
                        "--url", target.url, "--model", target.model,
                        "--format", "json", "--timeout", str(max(1, min(30, deadline // 3))),
                        *options, cwd=AUDIT_SCRIPT.parent, env=child_env, start_new_session=True,
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                    ))
                    try:
                        process = await asyncio.shield(spawn)
                    except asyncio.CancelledError:
                        # Join an in-flight spawn before cleanup, including a
                        # direct asyncio cancellation during server shutdown.
                        process = await spawn
                        self.running.add(process)
                        raise
                    self.running.add(process)

                async def receive():
                    raw = bytearray()
                    while chunk := await process.stdout.read(64 * 1024):
                        raw.extend(chunk)
                        if len(raw) > MAX_REPORT_BYTES:
                            raise ExecutionError("report_too_large")
                    await process.wait()
                    return bytes(raw), process.returncode

                return await asyncio.wait_for(receive(), deadline)
            except asyncio.TimeoutError:
                raise
            except OSError:
                raise ExecutionError("execution_failed") from None
            finally:
                if process is not None:
                    await self._stop(process)
                    self.running.discard(process)

    async def check_connectivity(self, target_id: str) -> dict:
        target, key, code = self._credential(target_id)
        if code:
            return error(code)
        if self.lock.locked():
            return error("connector_busy")
        async with self.lock:
            try:
                raw, returncode = await self._execute(target, key, ["--connectivity"], self.config.timeout_seconds)
                result = summarize(raw)
                if not result.get("ok"):
                    return result
                if returncode not in (0, 1) or result.get("report_type") != "connectivity":
                    return error("connectivity_failed")
                if result["connectivity"]["success"] != (returncode == 0):
                    return error("invalid_report")
                return result
            except asyncio.TimeoutError:
                return error("connectivity_timeout")
            except ExecutionError as exc:
                return error(exc.code)

    async def run_audit(self, target_id: str, mode: str = "quick") -> dict:
        if mode not in ("quick", "full"):
            return error("invalid_mode")
        target, key, code = self._credential(target_id)
        if code:
            return error(code)
        if self.lock.locked():
            return error("connector_busy")
        if len(self.jobs) >= self.config.max_jobs:
            return error("job_limit")
        await self.lock.acquire()
        job = Job(uuid4().hex, mode)
        self.jobs[job.job_id] = job
        job.task = asyncio.create_task(self._run_job(job, target, key))
        return job.snapshot()

    def _save_report(self, job: Job, raw: bytes):
        filename = f"{job.job_id}.json"
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self._root_fd)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
        except BaseException:
            os.unlink(filename, dir_fd=self._root_fd)
            raise
        job.report_file = filename

    async def _run_job(self, job: Job, target: Target, key: str):
        options = ["--skip-infra", "--profile", "general", "--warmup", "0"]
        if job.mode == "quick":
            options.extend(["--skip-context", "--skip-latency-variance"])
        try:
            raw, returncode = await self._execute(target, key, options, self.config.audit_timeout_seconds)
            result = summarize(raw)
            if not result.get("ok"):
                job.error_code = result["error"]
                job.status = "failed"
            elif returncode != 0 or result.get("report_type") != "audit":
                job.error_code = "audit_failed"
                job.status = "failed"
            else:
                self._save_report(job, raw)
                job.result = result
                job.status = "completed"
        except asyncio.TimeoutError:
            job.status = "timed_out"
            job.error_code = "audit_timeout"
        except asyncio.CancelledError:
            job.status = "cancelled"
        except ExecutionError as exc:
            job.status = "failed"
            job.error_code = exc.code
        except Exception:
            job.status = "failed"
            job.error_code = "audit_failed"
        finally:
            self.lock.release()

    async def get_audit_result(self, job_id: str, action: str = "status") -> dict:
        if action not in ("status", "cancel"):
            return error("invalid_action")
        job = self.jobs.get(job_id) if isinstance(job_id, str) else None
        if job is None:
            return error("unknown_job")
        if action == "cancel" and job.status == "running":
            # A task cancelled before its first instruction has no finally block.
            # Mark it, cancel it and ensure the shared slot is released as well.
            if not job.cancel_requested:
                job.cancel_requested = True
                job.task.cancel()
            with anyio.CancelScope(shield=True):
                await asyncio.shield(asyncio.gather(job.task, return_exceptions=True))
            if job.status == "running":
                job.status = "cancelled"
                if self.lock.locked():
                    self.lock.release()
        return job.snapshot()

    async def close(self):
        if self._closing:
            await self._closed.wait()
            return
        self._closing = True
        try:
            with anyio.CancelScope(shield=True):
                for job in self.jobs.values():
                    if job.status == "running":
                        await self.get_audit_result(job.job_id, "cancel")
                executions = list(self._executions)
                for task in executions:
                    task.cancel()
                if executions:
                    await asyncio.shield(asyncio.gather(*executions, return_exceptions=True))
                for process in list(self.running):
                    await self._stop(process)
                    self.running.discard(process)
                os.close(self._root_fd)
        finally:
            self._closed.set()
