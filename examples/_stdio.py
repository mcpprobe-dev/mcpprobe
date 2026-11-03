"""Tiny newline-delimited JSON-RPC loop shared by the example MCP servers.

Standard library only. It answers ``initialize``, ``tools/list``, ``prompts/list``,
``resources/list`` and ``tools/call`` on stdin/stdout, like tests/fake_stdio_server.py.
These servers are teaching material: they never read files, never open network
connections and discard every tool argument they receive.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any


def serve(name: str, tools: list[dict[str, Any]], call: Callable[[str, dict[str, Any]], str]) -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            _write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        msg_id = msg.get("id")
        if msg_id is None:
            continue  # notification
        method = msg.get("method")
        params = msg.get("params") or {}
        if method == "initialize":
            result: dict[str, Any] = {
                "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": name, "version": "0.0.1"},
            }
        elif method == "tools/list":
            result = {"tools": tools}
        elif method in {"prompts/list", "resources/list"}:
            result = {method.split("/")[0]: []}
        elif method == "tools/call":
            text = call(str(params.get("name")), params.get("arguments") or {})
            result = {"content": [{"type": "text", "text": text}]}
        else:
            _write({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}})
            continue
        _write({"jsonrpc": "2.0", "id": msg_id, "result": result})


def _write(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
