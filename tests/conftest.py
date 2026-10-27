from __future__ import annotations

import sys
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

import pytest

from tests.fake_server import FakeMcpServer, make_config

HERE = Path(__file__).parent
STDIO_SERVER = HERE / "fake_stdio_server.py"


def stdio_command(*flags: str) -> list[str]:
    return [sys.executable, str(STDIO_SERVER), *flags]


@pytest.fixture
def make_server() -> Callable[..., Any]:
    """Async factory: ``async with make_server(require_auth=True) as srv``."""

    @asynccontextmanager
    async def _factory(
        preset: str = "secure", host: str = "127.0.0.1", **overrides: Any
    ) -> AsyncIterator[FakeMcpServer]:
        async with FakeMcpServer(make_config(preset, **overrides), host=host) as srv:
            yield srv

    return _factory


@pytest.fixture
def live_server() -> Callable[..., Any]:
    """Sync factory for CLI tests: ``with live_server("vulnerable") as srv``."""

    @contextmanager
    def _factory(
        preset: str = "secure", host: str = "127.0.0.1", **overrides: Any
    ) -> Iterator[FakeMcpServer]:
        srv = FakeMcpServer(make_config(preset, **overrides), host=host).start()
        try:
            yield srv
        finally:
            srv.stop()

    return _factory


@pytest.fixture(autouse=True)
def _isolated_token_store(tmp_path, monkeypatch):
    """Never touch the real ~/.config token store from tests."""
    monkeypatch.setenv("MCPPROBE_TOKEN_STORE", str(tmp_path / "tokens.json"))


async def run(
    url_or_cmd: str | list[str],
    *,
    stdio: bool = False,
    only=None,
    skip=None,
    txt_lookup=None,
    authorisation=None,
    headers=None,
    **opts,
):
    """Run a full scan against a fake target at a high rate cap (test-only override)."""
    from mcpprobe.checks import ScanOptions
    from mcpprobe.scanner import ScanConfig, run_scan

    options = ScanOptions(**opts)
    cfg = ScanConfig(
        target=url_or_cmd if isinstance(url_or_cmd, str) else " ".join(url_or_cmd),
        stdio=stdio,
        rate=1000,
        options=options,
        only=only,
        skip=skip,
        timeout=10,
        txt_lookup=txt_lookup,
        authorisation=authorisation,
        headers=headers or {},
        _unsafe_allow_any_rate=True,
    )
    report, _evidence = await run_scan(cfg)
    return report


def by_id(report, check_id: str):
    return [f for f in report.findings if f.id == check_id]


def status_of(report, check_id: str):
    return next(c for c in report.checks if c.check_id == check_id)


def no_txt(_name: str) -> list[str]:
    return []
