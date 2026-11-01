"""META-01 precision and recall on a fixed corpus.

The benign corpus is real-world style tool and argument descriptions. None of
them may raise a META-01 indicator at medium severity or above: a poisoning
detector that cries wolf is as useless as one that misses the demo.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpprobe.checks.poisoning import analyse_text
from mcpprobe.models import Severity

CORPUS_PATH = Path(__file__).parent / "data" / "meta01_corpus.json"
_CORPUS = json.loads(CORPUS_PATH.read_text("utf-8"))
BENIGN: list[str] = _CORPUS["benign"]
POISONED: list[str] = _CORPUS["poisoned"]


@pytest.mark.parametrize("text", BENIGN)
def test_benign_descriptions_stay_below_medium(text: str) -> None:
    loud = [i for i in analyse_text(text) if i.severity >= Severity.MEDIUM]
    assert not loud, f"false positive on benign text {text!r}: {[(i.kind, i.matches) for i in loud]}"


@pytest.mark.parametrize("text", POISONED)
def test_poisoned_descriptions_fire_at_medium_or_above(text: str) -> None:
    loud = [i for i in analyse_text(text) if i.severity >= Severity.MEDIUM]
    assert loud, f"missed poisoned text {text!r}"


def test_demo_run_command_is_high_with_both_phrases() -> None:
    text = POISONED[0]
    ind = analyse_text(text)
    assert max(i.severity for i in ind) == Severity.HIGH
    matches = [m.lower() for i in ind for m in i.matches]
    assert any("always call this first" in m for m in matches)
    assert any("full conversation" in m for m in matches)


def test_corpus_size() -> None:
    assert len(BENIGN) >= 30 and len(POISONED) >= 11


# ----------------------------------------------------------------------------- real descriptions
REAL_PATH = Path(__file__).parent / "data" / "meta01_real_benign.json"
_REAL = json.loads(REAL_PATH.read_text("utf-8"))


def _loud_real(split: str) -> list[str]:
    rows = _REAL[split]
    siblings: dict[str, list[str]] = {}
    for r in rows:
        if r["kind"] == "tool" and r["name"]:
            siblings.setdefault(r["source"], []).append(r["name"])
    return [
        r["text"]
        for r in rows
        if any(
            i.severity >= Severity.MEDIUM
            for i in analyse_text(
                r["text"], other_tool_names=siblings.get(r["source"], []), own_name=r["name"]
            )
        )
    ]


@pytest.mark.parametrize("split", ["tuning", "heldout"])
def test_real_descriptions_rarely_reach_medium(split: str) -> None:
    """Thousands of real descriptions from published MCP servers: medium+ must stay rare.

    0.3.0 raised medium or above on 2.8% of these texts (22.5% of packages); the bound
    is a regression guard, not a target.
    """
    rows = _REAL[split]
    loud = _loud_real(split)
    assert len(rows) >= 900
    assert len(loud) / len(rows) <= 0.002, loud


@pytest.mark.parametrize(
    "text",
    [
        "Always use this tool to look up the current exchange rate.",
        "Use this tool to search the knowledge base. You must provide a query.",
        "You must call list_projects first to obtain a project ID.",
        "IMPORTANT: you should always call this tool before creating an issue.",
        "This tool must be used before any write operation on the board.",
        "Call this first when something returns nothing.",
        "Deprecated: use search_v2 instead.",
        "Paths such as ~/.ssh or /etc are rejected.",
        "Never read, open or echo any .env file.",
        "Example: https://docs.example.com/guide",
    ],
)
def test_ordinary_imperative_phrasing_raises_nothing(text: str) -> None:
    loud = [
        i
        for i in analyse_text(text, other_tool_names=["list_projects", "search_v2"])
        if i.severity >= Severity.MEDIUM
    ]
    assert not loud, [(i.kind, i.matches) for i in loud]


def test_planted_instruction_case_stays_high() -> None:
    from tests.fake_server import POISONED_TOOLS

    add = next(t for t in POISONED_TOOLS if t["name"] == "add")
    ind = analyse_text(
        add["description"], other_tool_names=[t["name"] for t in POISONED_TOOLS], own_name="add"
    )
    assert max(i.severity for i in ind) == Severity.HIGH
