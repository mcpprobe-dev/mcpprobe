"""mcpprobe: a security scanner for Model Context Protocol (MCP) servers.

The package is organised as follows:

- :mod:`mcpprobe.transport` -- a deliberately low-level MCP client (streamable
  HTTP and stdio) that can send malformed or non-conformant requests and
  records every exchange as evidence.
- :mod:`mcpprobe.checks` -- the plugin framework and the individual checks.
- :mod:`mcpprobe.authz` -- the hard authorisation gate for active mode.
- :mod:`mcpprobe.report` -- JSON, SARIF 2.1.0 and terminal reporters.
- :mod:`mcpprobe.scanner` -- the orchestrator tying everything together.
"""

from __future__ import annotations

__version__ = "0.2.0"

POLICY_URL = "https://mcpprobe.tech/scanning-policy"
USER_AGENT = f"mcpprobe/{__version__} (+{POLICY_URL})"

__all__ = ["POLICY_URL", "USER_AGENT", "__version__"]
