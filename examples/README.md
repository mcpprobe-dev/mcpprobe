# Attack labs

Tiny MCP servers that reproduce two well-documented attacks on MCP tool metadata, so you
can watch mcpprobe flag them and see what the fixed version looks like.

| Lab | Attack | Check |
|---|---|---|
| [tool-poisoning/](tool-poisoning/) | Instructions to the model hidden in a tool description | META-01 |
| [rug-pull/](rug-pull/) | A tool description that changes after it was approved | META-02 (and META-01) |

Both servers are Python standard library only and speak MCP over stdio. They are
harmless by construction: they never read files, never open a network connection, and
discard every tool argument. The only URL and email address in them use the reserved
`.invalid` top-level domain, which cannot resolve. Do not connect them to an agent that
has access to real data anyway; they exist to be scanned.

Run them from a clone of this repository with mcpprobe installed
(`pipx install mcpprobe-scanner`, or `pip install -e .` from the repo root).
`tests/test_examples.py` runs the same commands and checks the same findings.
