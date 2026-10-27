"""stdio transport: spawn a local MCP server command and speak newline-delimited JSON-RPC.

Only use this on packages you run yourself. The scanner does not sandbox the
child process; see SANDBOX-01 in CHECKS.md for the planned sandboxed runner.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import time
from collections import deque
from collections.abc import Mapping, Sequence
from typing import Any

from mcpprobe.transport.base import RpcResponse, Transport, TransportError
from mcpprobe.transport.evidence import EvidenceLog
from mcpprobe.transport.ratelimit import RateLimiter

STDERR_TAIL_LINES = 200
#: Protect against a server that floods stdout with one enormous line.
MAX_LINE_BYTES = 10_000_000


class StdioTransport(Transport):
    """Child-process MCP server driven over stdin/stdout."""

    name = "stdio"

    def __init__(
        self,
        command: str | Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
        timeout: float = 15.0,
        evidence: EvidenceLog | None = None,
        limiter: RateLimiter | None = None,
        inherit_env: bool = True,
    ) -> None:
        super().__init__(evidence=evidence, limiter=limiter)
        self.argv: list[str] = list(shlex.split(command) if isinstance(command, str) else command)
        if not self.argv:
            raise TransportError("empty stdio command")
        self.env = dict(env or {})
        self.cwd = cwd
        self.timeout = timeout
        self.inherit_env = inherit_env
        self.proc: asyncio.subprocess.Process | None = None
        self.stderr_tail: deque[str] = deque(maxlen=STDERR_TAIL_LINES)
        self._pending: dict[int | str, asyncio.Future[dict[str, Any]]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self.unsolicited: list[dict[str, Any]] = []

    @property
    def display(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)

    async def start(self) -> None:
        if self.proc is not None:
            return
        env = dict(os.environ) if self.inherit_env else {}
        env.update(self.env)
        try:
            self.proc = await asyncio.create_subprocess_exec(
                *self.argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=self.cwd,
                limit=MAX_LINE_BYTES,
            )
        except (OSError, ValueError) as exc:
            raise TransportError(f"cannot start {self.display}: {exc}") from exc
        self._reader_task = asyncio.create_task(self._read_stdout())
        self._stderr_task = asyncio.create_task(self._read_stderr())

    async def _read_stdout(self) -> None:
        assert self.proc and self.proc.stdout
        while True:
            try:
                line = await self.proc.stdout.readline()
            except (ValueError, asyncio.LimitOverrunError):
                self.stderr_tail.append("[mcpprobe] stdout line exceeded limit; dropped")
                continue
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                msg = json.loads(text)
            except ValueError:
                self.stderr_tail.append(f"[non-JSON stdout] {text[:200]}")
                continue
            if isinstance(msg, dict) and "id" in msg and ("result" in msg or "error" in msg):
                fut = self._pending.pop(msg["id"], None)
                if fut and not fut.done():
                    fut.set_result(msg)
                    continue
            self.unsolicited.append(msg if isinstance(msg, dict) else {"raw": msg})
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(TransportError("server closed stdout"))
        self._pending.clear()

    async def _read_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        while True:
            try:
                line = await self.proc.stderr.readline()
            except (ValueError, asyncio.LimitOverrunError):
                continue
            if not line:
                break
            self.stderr_tail.append(line.decode("utf-8", errors="replace").rstrip())

    async def send_raw(
        self, text: str, *, label: str, want_id: int | str | None, note: str | None = None
    ) -> RpcResponse:
        """Write one line to the child's stdin and (optionally) await a reply."""
        await self.start()
        assert self.proc and self.proc.stdin
        await self.limiter.acquire()
        fut: asyncio.Future[dict[str, Any]] | None = None
        if want_id is not None:
            fut = asyncio.get_running_loop().create_future()
            self._pending[want_id] = fut
        started = time.monotonic()
        error_text: str | None = None
        message: dict[str, Any] | None = None
        try:
            self.proc.stdin.write(text.encode("utf-8") + b"\n")
            await self.proc.stdin.drain()
            if fut is not None:
                message = await asyncio.wait_for(fut, self.timeout)
        except TimeoutError:
            error_text = "timeout waiting for response"
            self._pending.pop(want_id, None)  # type: ignore[arg-type]
        except (BrokenPipeError, ConnectionResetError, TransportError) as exc:
            error_text = f"{type(exc).__name__}: {exc}"
        elapsed_ms = (time.monotonic() - started) * 1000
        body = json.dumps(message).encode("utf-8") if message is not None else b""
        rec = self.evidence.record(
            transport="stdio",
            method=label,
            url=self.display,
            request_body=text,
            response_body=body,
            elapsed_ms=elapsed_ms,
            note=note,
            error=error_text,
        )
        return RpcResponse(
            method=label,
            status=None,
            headers={},
            body=body,
            message=message,
            evidence=rec,
            elapsed_ms=elapsed_ms,
            error_text=error_text,
            stream_messages=[message] if message else [],
        )

    async def rpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        note: str | None = None,
        protocol_version: str | None = None,
        **kwargs: Any,
    ) -> RpcResponse:
        msg = self.build_message(method, params, protocol_version=protocol_version)
        return await self.send_raw(json.dumps(msg), label=method, want_id=msg["id"], note=note)

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        msg = self.build_message(method, params, notification=True)
        await self.send_raw(json.dumps(msg), label=method, want_id=None, note="notification")

    async def close(self) -> None:
        if self.proc is None:
            return
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            try:
                await asyncio.wait_for(self.proc.wait(), 2.0)
            except TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        finally:
            for task in (self._reader_task, self._stderr_task):
                if task:
                    task.cancel()
            self.proc = None
