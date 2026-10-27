"""Scanner identification and opt-out handling.

* Every request carries ``User-Agent: mcpprobe/<version> (+https://mcpprobe.tech/scanning-policy)``.
* Before any MCP request is sent to an HTTP target, the scanner fetches
  ``/.well-known/mcpprobe-opt-out`` on the target's origin. A ``200`` response
  means the operator of that host does not want to be scanned and the run is
  aborted with a clear message. This cannot be disabled from the command line.
* All traffic passes through one rate limiter (default 5 requests/second).
"""

from __future__ import annotations

from mcpprobe import POLICY_URL, USER_AGENT
from mcpprobe.checks._util import origin_of
from mcpprobe.transport import HttpTransport

OPT_OUT_PATH = "/.well-known/mcpprobe-opt-out"


class OptOutError(Exception):
    """The target host has published an opt-out document."""


def opt_out_url(target: str) -> str:
    return origin_of(target) + OPT_OUT_PATH


async def check_opt_out(http: HttpTransport, target: str) -> None:
    """Raise :class:`OptOutError` if the host opted out; otherwise return quietly."""
    url = opt_out_url(target)
    resp = await http.get(url, note="opt-out check", label="GET(opt-out)")
    if resp.status == 200:
        body = resp.body.decode("utf-8", errors="replace").strip()
        excerpt = body.splitlines()[0][:200] if body else ""
        raise OptOutError(
            f"{origin_of(target)} publishes {OPT_OUT_PATH}; scanning is not permitted. "
            + (f"Message from host: {excerpt!r}. " if excerpt else "")
            + f"See {POLICY_URL}."
        )


__all__ = ["OPT_OUT_PATH", "POLICY_URL", "USER_AGENT", "OptOutError", "check_opt_out", "opt_out_url"]
