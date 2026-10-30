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
