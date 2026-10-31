"""Page through the official MCP Registry list API and normalise its entries.

API shape (verified 2026-10-31 against the registry repository's
``docs/reference/api/openapi.yaml`` and the "Registry aggregators" page on
modelcontextprotocol.io):

* ``GET {base}/v0.1/servers?limit=&cursor=&version=latest`` returns
  ``{"servers": [ServerResponse], "metadata": {"nextCursor": str|null, "count": int}}``.
* ``ServerResponse`` is ``{"server": ServerDetail, "_meta": {"io.modelcontextprotocol.registry/official":
  {"status": "active"|"deprecated"|"deleted", "publishedAt", "updatedAt", "isLatest"}}}``.
* ``ServerDetail.remotes[]`` items are ``{"type": "streamable-http"|"sse", "url", "headers"?}``;
  ``ServerDetail.packages[]`` items carry ``registryType``, ``identifier``, ``version``, ``transport``.
* The cursor is opaque: pass ``metadata.nextCursor`` back unchanged; empty/null means done.

The openapi file lists only ``/v0.1`` paths. ``/v0/servers`` (named in older docs) is
accepted via ``--api-path`` and the normaliser also reads a flat (unwrapped) item shape,
but neither was verified against the live service, which is not reachable from the
build environment. Aggregators are asked to scrape "regularly but infrequently"; one
full fetch per report is well within that.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx

from mcpprobe import USER_AGENT
from mcpprobe.registry.common import WorkDir, read_json, write_json, write_jsonl

DEFAULT_BASE = "https://registry.modelcontextprotocol.io"
DEFAULT_API_PATH = "/v0.1/servers"
DEFAULT_PAGE_LIMIT = 100
#: Seconds between two registry requests.
REGISTRY_INTERVAL = 1.0
OFFICIAL_META = "io.modelcontextprotocol.registry/official"
PUBLISHER_META = "io.modelcontextprotocol.registry/publisher-provided"
REMOTE_TYPES = ("streamable-http", "sse")


class FetchStoppedError(Exception):
    """The registry refused (HTTP 429/403) or failed; state is saved and the fetch can resume."""


@dataclass(slots=True)
class FetchResult:
    pages_fetched: int = 0
    pages_total: int = 0
    done: bool = False
    entries: int = 0
    planned_url: str | None = None
    notes: list[str] = field(default_factory=list)


def page_url(base: str, api_path: str, limit: int, cursor: str | None) -> str:
    params: dict[str, str] = {"limit": str(limit), "version": "latest"}
    if cursor:
        params["cursor"] = cursor
    return base.rstrip("/") + api_path + "?" + urlencode(params)


def _official(item: dict[str, Any], server: dict[str, Any]) -> dict[str, Any]:
    for meta in (item.get("_meta"), server.get("_meta")):
        if isinstance(meta, dict) and isinstance(meta.get(OFFICIAL_META), dict):
            return dict(meta[OFFICIAL_META])
    return {}


def _publisher_tools(server: dict[str, Any]) -> tuple[list[dict[str, Any]] | None, bool]:
    """Tool definitions a publisher put under ``_meta``: (full definitions or None, names-only seen)."""
    meta = server.get("_meta")
    provided = meta.get(PUBLISHER_META) if isinstance(meta, dict) else None
    if not isinstance(provided, dict):
        return None, False
    names_only = False
    for value in provided.values():
        tools = value.get("tools") if isinstance(value, dict) else None
        if not isinstance(tools, list) or not tools:
            continue
        defs = [t for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)]
        if defs and any("description" in t or "inputSchema" in t or "annotations" in t for t in defs):
            return defs, False
        if all(isinstance(t, str) for t in tools):
            names_only = True
    return None, names_only


def normalise_item(item: dict[str, Any]) -> dict[str, Any] | None:
    """Turn one list item (wrapped v0.1 shape or flat) into the pipeline's entry shape."""
    server = item.get("server") if isinstance(item.get("server"), dict) else item
    if not isinstance(server, dict) or not isinstance(server.get("name"), str):
        return None
    official = _official(item, server)
    remotes = []
    for r in server.get("remotes") or []:
        if isinstance(r, dict) and isinstance(r.get("url"), str):
            remotes.append(
                {
                    "type": str(r.get("type") or ""),
                    "url": r["url"],
                    "has_headers": bool(r.get("headers")),
                }
            )
    packages = []
    for p in server.get("packages") or []:
        if not isinstance(p, dict):
            continue
        transport = p.get("transport")
        packages.append(
            {
                "registry_type": str(p.get("registryType") or p.get("registry_type") or ""),
                "identifier": str(p.get("identifier") or p.get("name") or ""),
                "version": str(p.get("version") or ""),
                "transport": str(transport.get("type") if isinstance(transport, dict) else transport or ""),
            }
        )
    tools, names_only = _publisher_tools(server)
    return {
        "name": server["name"],
        "version": str(server.get("version") or ""),
        "status": str(official.get("status") or server.get("status") or "active"),
        "is_latest": official.get("isLatest"),
        "published_at": official.get("publishedAt"),
        "remotes": remotes,
        "packages": packages,
        "tools": tools,
        "tool_names_only": names_only,
    }


def build_entries(pages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalise every page; keep the latest version of each name; drop deleted entries."""
    by_name: dict[str, dict[str, Any]] = {}
    for page in pages:
        for item in page.get("servers") or []:
            if not isinstance(item, dict):
                continue
            entry = normalise_item(item)
            if entry is None or entry["is_latest"] is False:
                continue
            by_name[entry["name"]] = entry  # later pages win when isLatest is absent
    return [e for e in sorted(by_name.values(), key=lambda e: e["name"]) if e["status"] != "deleted"]


def load_pages(wd: WorkDir) -> list[dict[str, Any]]:
    if not wd.pages.exists():
        return []
    return [read_json(p) for p in sorted(wd.pages.glob("page-*.json"))]


async def fetch_registry(
    wd: WorkDir,
    *,
    base: str = DEFAULT_BASE,
    api_path: str = DEFAULT_API_PATH,
    limit: int = DEFAULT_PAGE_LIMIT,
    max_pages: int | None = None,
    dry_run: bool = False,
    restart: bool = False,
    interval: float = REGISTRY_INTERVAL,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    httpx_transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 30.0,
) -> FetchResult:
    """Fetch (or resume fetching) the registry into ``wd`` and rebuild ``entries.jsonl``.

    Resumable: ``fetch-state.json`` holds the next cursor; each page is saved as soon as
    it arrives. A 429 or 403 from the registry stops the fetch (state kept) instead of
    retrying.
    """
    wd.ensure()
    state: dict[str, Any] = {}
    if wd.fetch_state.exists() and not restart:
        state = read_json(wd.fetch_state)
    if state.get("base") not in (None, base) or state.get("api_path") not in (None, api_path):
        raise FetchStoppedError(
            "the working directory was fetched from another registry/API path; use --restart"
        )
    result = FetchResult(pages_total=int(state.get("pages", 0)), done=bool(state.get("done")))
    cursor = state.get("next_cursor")
    if result.done:
        result.notes.append("registry already fully fetched; use --restart to fetch again")
    if dry_run:
        if not result.done:
            result.planned_url = page_url(base, api_path, limit, cursor)
            result.notes.append(
                f"dry run: would GET {result.planned_url}, then follow metadata.nextCursor "
                f"at one request per {interval:g} s"
            )
        return result
    if restart and wd.pages.exists():
        for p in wd.pages.glob("page-*.json"):
            p.unlink()
    wd.pages.mkdir(parents=True, exist_ok=True)
    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        timeout=timeout,
        follow_redirects=False,
        transport=httpx_transport,
    ) as client:
        while not result.done and (max_pages is None or result.pages_fetched < max_pages):
            if result.pages_fetched:
                await sleep(interval)
            url = page_url(base, api_path, limit, cursor)
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                raise FetchStoppedError(f"registry request failed: {type(exc).__name__}: {exc}") from exc
            if resp.status_code in (429, 403):
                raise FetchStoppedError(
                    f"registry answered HTTP {resp.status_code}; stopped (re-run later to resume from the saved cursor)"
                )
            if resp.status_code != 200:
                raise FetchStoppedError(f"registry answered HTTP {resp.status_code} for {url}")
            try:
                page = resp.json()
            except json.JSONDecodeError as exc:
                raise FetchStoppedError(f"registry returned non-JSON for {url}") from exc
            if not isinstance(page, dict) or not isinstance(page.get("servers"), list):
                raise FetchStoppedError(f"unexpected registry response shape for {url} (no 'servers' list)")
            result.pages_total += 1
            result.pages_fetched += 1
            write_json(wd.pages / f"page-{result.pages_total:05d}.json", page)
            raw_meta = page.get("metadata")
            meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
            next_cursor = meta.get("nextCursor") or meta.get("next_cursor")
            if next_cursor and next_cursor == cursor:
                raise FetchStoppedError("registry returned the same cursor twice; stopping to avoid a loop")
            cursor = next_cursor or None
            result.done = cursor is None
            write_json(
                wd.fetch_state,
                {
                    "base": base,
                    "api_path": api_path,
                    "limit": limit,
                    "next_cursor": cursor,
                    "pages": result.pages_total,
                    "done": result.done,
                },
            )
    entries = build_entries(load_pages(wd))
    result.entries = write_jsonl(wd.entries, entries)
    return result
