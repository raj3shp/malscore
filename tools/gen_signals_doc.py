#!/usr/bin/env python3
"""Generate docs/signals.md from the live signal catalogue.

Usage::

    python tools/gen_signals_doc.py > docs/signals.md

Reads ``malscore.SIGNALS`` and ``malscore.SESSION_SIGNALS`` so the reference can
never drift from the code.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from malscore import SESSION_SIGNALS, SIGNALS  # noqa: E402

TACTIC_ORDER = [
    "execution", "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
]


def _row(signal) -> str:
    return "| `%s` | %s | %.2f | %s |" % (
        signal.id, signal.title, signal.weight, " ".join(signal.techniques))


def main() -> None:
    out = sys.stdout.write
    out("# Signal reference\n\n")
    out("> This file is generated from `malscore/signals.py`. Regenerate with\n")
    out("> `python tools/gen_signals_doc.py > docs/signals.md`; do not edit by hand.\n\n")
    out("`malscore` carries **%d** command-level signals and **%d** session "
        "(cross-command)\n" % (len(SIGNALS), len(SESSION_SIGNALS)))
    out("signals. Each signal is a predicate over the extracted features plus a weight in\n")
    out("`(0, 1]`, a MITRE ATT&CK tactic, and one or more technique ids.\n\n")

    out("## How signals become a score\n\n")
    out("1. Every signal whose predicate is true on the command \"fires\".\n")
    out("2. Signals that share a tactic are **damped**: the strongest keeps its weight,\n")
    out("   the next is multiplied by 0.55, the next by 0.55², and so on — so three\n")
    out("   redundant persistence checks do not count as three independent findings.\n")
    out("3. The damped weights are combined with a **noisy-OR**, `1 − ∏(1 − wᵢ)`, which\n")
    out("   keeps the result in `[0, 1)`; it is scaled to the 0–100 score.\n\n")
    out("| score | verdict |\n| --- | --- |\n")
    for band in ("80–100 | `critical`", "60–79 | `high`", "35–59 | `medium`",
                 "15–34 | `low`", "0–14 | `benign`"):
        out("| %s |\n" % band)

    out("\n## Command signals\n")
    by_tactic = {}
    for signal in SIGNALS:
        by_tactic.setdefault(signal.tactic, []).append(signal)
    for tactic in TACTIC_ORDER + sorted(set(by_tactic) - set(TACTIC_ORDER)):
        if tactic not in by_tactic:
            continue
        out("\n### %s\n\n" % tactic.replace("-", " ").title())
        out("| id | description | weight | techniques |\n| --- | --- | --- | --- |\n")
        for signal in sorted(by_tactic[tactic], key=lambda s: -s.weight):
            out(_row(signal) + "\n")

    out("\n## Session signals\n\n")
    out("These fire only across multiple commands scored together with\n")
    out("`Analyzer.assess_session` (see [usage](usage.md)).\n\n")
    out("| id | description | weight | tactic | techniques |\n")
    out("| --- | --- | --- | --- | --- |\n")
    for signal in SESSION_SIGNALS.values():
        out("| `%s` | %s | %.2f | %s | %s |\n" % (
            signal.id, signal.title, signal.weight, signal.tactic, " ".join(signal.techniques)))


if __name__ == "__main__":
    main()
