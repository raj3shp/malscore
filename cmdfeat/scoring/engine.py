"""Turn feature records into a maliciousness score with an explanation.

The score is a deterministic function of the signals that fired (see
:mod:`cmdfeat.scoring.signals`).  It is **not** a probability and not a trained
model: it is a transparent, auditable weighting whose every point can be traced
to a named signal and a MITRE technique.

Aggregation uses a *noisy-OR* of the signal weights rather than a sum::

    combined = 1 - prod(1 - weight_i)

so that many weak signals accumulate but never overflow, one strong signal
dominates, and the result stays in ``[0, 1)`` before being scaled to 0-100.
Signals within the same tactic are damped (a command that trips three redundant
persistence checks should not score as if it did three independent things).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .signals import SCRIPT_SIGNALS, SIGNALS, Signal

Record = Dict[str, object]

#: Score bands for the verdict label.  Lower bound inclusive.
BANDS: Tuple[Tuple[int, str], ...] = (
    (80, "critical"),
    (60, "high"),
    (35, "medium"),
    (15, "low"),
    (0, "benign"),
)
#: Within one tactic, the n-th strongest signal is multiplied by DAMPING**n.
TACTIC_DAMPING = 0.55


@dataclass
class Hit:
    """A signal that fired on a record."""

    signal: Signal

    @property
    def id(self) -> str:
        return self.signal.id

    @property
    def weight(self) -> float:
        return self.signal.weight

    @property
    def tactic(self) -> str:
        return self.signal.tactic

    @property
    def title(self) -> str:
        return self.signal.title

    @property
    def techniques(self) -> Tuple[str, ...]:
        return self.signal.techniques


@dataclass
class Assessment:
    """The result of scoring one command or one script."""

    score: int
    verdict: str
    hits: List[Hit]
    command: str = ""
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    per_statement: List["Assessment"] = field(default_factory=list)
    line: int = 0
    note: str = ""

    def as_dict(self, include_statements: bool = True) -> Dict[str, object]:
        data: Dict[str, object] = {
            "score": self.score,
            "verdict": self.verdict,
            "tactics": self.tactics,
            "techniques": self.techniques,
            "signals": [
                {
                    "id": hit.id,
                    "title": hit.title,
                    "weight": round(hit.weight, 2),
                    "tactic": hit.tactic,
                    "techniques": list(hit.techniques),
                }
                for hit in self.hits
            ],
        }
        if self.command:
            data["command"] = self.command
        if self.line:
            data["line"] = self.line
        if self.note:
            data["note"] = self.note
        if include_statements and self.per_statement:
            data["statements"] = [s.as_dict(include_statements=False) for s in self.per_statement]
        return data


def verdict_for(score: int) -> str:
    """Map a 0-100 score to a verdict band."""
    for lower, label in BANDS:
        if score >= lower:
            return label
    return "benign"


def _combine(weights: Sequence[float]) -> float:
    """Noisy-OR of a list of weights, each in [0, 1]."""
    product = 1.0
    for weight in weights:
        product *= (1.0 - max(0.0, min(1.0, weight)))
    return 1.0 - product


def _damped_weights(hits: Sequence[Hit]) -> List[float]:
    """Damp redundant signals that share a tactic before combining."""
    by_tactic: Dict[str, List[float]] = {}
    for hit in hits:
        by_tactic.setdefault(hit.tactic, []).append(hit.weight)
    weights: List[float] = []
    for tactic_weights in by_tactic.values():
        for rank, weight in enumerate(sorted(tactic_weights, reverse=True)):
            weights.append(weight * (TACTIC_DAMPING ** rank))
    return weights


def _collect(hits: Sequence[Hit]) -> Tuple[List[str], List[str]]:
    tactics: List[str] = []
    techniques: List[str] = []
    for hit in hits:
        if hit.tactic not in tactics:
            tactics.append(hit.tactic)
        for technique in hit.techniques:
            if technique not in techniques:
                techniques.append(technique)
    return tactics, techniques


def find_hits(record: Record, signals: Sequence[Signal] = SIGNALS) -> List[Hit]:
    """Every signal whose test passes on ``record``."""
    hits: List[Hit] = []
    for signal in signals:
        try:
            if signal.test(record):
                hits.append(Hit(signal))
        except Exception:                          # pragma: no cover - defensive
            continue
    return hits


def score_record(record: Record, command: str = "", line: int = 0) -> Assessment:
    """Score a single feature record."""
    hits = find_hits(record)
    combined = _combine(_damped_weights(hits))
    score = int(round(combined * 100))
    hits.sort(key=lambda h: h.weight, reverse=True)
    tactics, techniques = _collect(hits)
    return Assessment(
        score=score,
        verdict=verdict_for(score),
        hits=hits,
        command=command or str(record.get("command", "")),
        tactics=tactics,
        techniques=techniques,
        line=line,
    )
