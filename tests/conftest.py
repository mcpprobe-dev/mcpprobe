from __future__ import annotations

import sys
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from tests.fake_server import FakeConfig, FakeMcpServer

HERE = Path(__file__).parent
STDIO_SERVER = HERE / "fake_stdio_server.py"


def stdio_command(*flags: str) -> list[str]:
    return [sys.executable, str(STDIO_SERVER), *flags]


@pytest.fixture
def make_server() -> Callable[..., object]:
    """Factory fixture: ``async with make_server(require_auth=True) as srv``."""

    @asynccontextmanager
    async def _factory(**overrides: object) -> AsyncIterator[FakeMcpServer]:
        cfg = FakeConfig(**overrides)  # type: ignore[arg-type]
        async with FakeMcpServer(cfg) as srv:
            yield srv

    return _factory


async def run(url_or_cmd: str | list[str], *, stdio: bool = False, only=None, skip=None, **opts):
    """Run a full scan against a fake target at a high rate cap."""
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
    )
    report, evidence = await run_scan(cfg)
    return report


def by_id(report, check_id: str):
    return [f for f in report.findings if f.id == check_id]


def status_of(report, check_id: str):
    return next(c for c in report.checks if c.check_id == check_id)
