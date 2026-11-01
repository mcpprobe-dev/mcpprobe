"""Pipeline for the "State of MCP server security" report over the official MCP Registry.

Stages, each resumable from a working directory:

1. :mod:`~mcpprobe.registry.fetch`: page through the registry list API and write
   ``entries.jsonl`` (one normalised entry per server).
2. :mod:`~mcpprobe.registry.select`: split entries into remote (``remotes[]`` with a
   streamable-http or SSE URL) and package-only, dedupe hosts, apply exclusions.
3. :mod:`~mcpprobe.registry.static`: META-01/06/07 on tool definitions the registry
   entry itself carries (for every entry, including package-only ones).
4. :mod:`~mcpprobe.registry.batch`: a polite, passive scan of each remote host with a
   reduced *survey profile* of checks, checkpointed to ``scan.jsonl``.
5. :mod:`~mcpprobe.registry.aggregate`: anonymised aggregates with 95% intervals.
6. :mod:`~mcpprobe.registry.render`: Markdown report and SVG charts, with a guard that
   refuses to write a report that names a third-party host.

Nothing here stores a response body from a third party: only check outcomes, counts and
the negotiated protocol revision / edge label are kept.
"""

from __future__ import annotations

from mcpprobe.registry.common import (
    MAX_CONCURRENCY,
    PER_HOST_INTERVAL,
    STATIC_CHECKS,
    SURVEY_CHECKS,
    Outcome,
)

__all__ = ["MAX_CONCURRENCY", "PER_HOST_INTERVAL", "STATIC_CHECKS", "SURVEY_CHECKS", "Outcome"]
