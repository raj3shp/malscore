"""Split a shell script into logical statements, without executing anything.

Telemetry delivers one command line per event; a script is many of them.  This
module turns script text into :class:`Statement` objects that look like the
command lines the feature extractors already understand:

* ``#`` comments (including the shebang) are dropped;
* backslash-newline continuations, trailing ``|`` / ``&&`` / ``||`` and quotes
  that span lines are joined into one statement;
* here-document bodies are kept *apart* from the command that consumes them,
  so ``cat > unit.service <<EOF`` does not turn the unit file's lines into
  commands -- the scorer decides what the body means (see
  :func:`cmdfeat.scoring.engine.assess_script`).

Like the lexer, the splitter is approximate and never raises.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

HEREDOC_DELIM_RE = re.compile(r"""(-?)[ \t]*(?:'([^']*)'|"([^"]*)"|\\?([A-Za-z_][\w.-]*))""")
CONTINUATION_OPS = ("|", "&&", "||")


@dataclass
class Heredoc:
    """A here-document attached to a statement."""

    delimiter: str
    body: str = ""
    strip_tabs: bool = False
    start_line: int = 0          # 1-based line of the first body line


@dataclass
class Statement:
    """One logical command line in a script."""

    text: str
    line: int                    # 1-based first line
    end_line: int
    heredocs: List[Heredoc] = field(default_factory=list)


def _scan(line: str, quote: str) -> Tuple[str, str, List[Tuple[str, bool]]]:
    """Strip a comment from ``line`` and track quote state across lines.

    Returns ``(kept_text, quote_state_after, heredoc_delimiters)``; ``quote`` is
    the quote character still open from the previous line ("" for none).
    """
    out: List[str] = []
    delims: List[Tuple[str, bool]] = []
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(line[i:i + 2])
            i += 2
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "#" and (i == 0 or line[i - 1] in " \t;|&()"):
            break                                   # comment to end of line
        if line.startswith("<<", i) and not line.startswith("<<<", i):
            match = HEREDOC_DELIM_RE.match(line, i + 2)
            if match:
                delimiter = match.group(2) or match.group(3) or match.group(4) or ""
                if delimiter:
                    delims.append((delimiter, match.group(1) == "-"))
                    out.append(line[i:match.end()])
                    i = match.end()
                    continue
        out.append(ch)
        i += 1
    return "".join(out), quote, delims


def split_script(text: str, first_line: int = 1) -> List[Statement]:
    """Split ``text`` into statements; ``first_line`` offsets reported line numbers."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    statements: List[Statement] = []
    buffer: List[str] = []
    start: Optional[int] = None
    quote = ""
    pending: List[Heredoc] = []
    index = 0

    def flush(end_index: int) -> None:
        nonlocal buffer, start, pending
        joined = "".join(buffer).strip()
        if joined:
            statements.append(Statement(text=joined, line=start or first_line,
                                        end_line=end_index + first_line, heredocs=pending))
        buffer, start, pending = [], None, []

    while index < len(lines):
        raw = lines[index]
        if start is None:
            start = index + first_line
        kept, quote, delims = _scan(raw, quote)
        pending.extend(Heredoc(delimiter=d, strip_tabs=t) for d, t in delims)

        if quote:                                   # quote spans the newline
            buffer.append(kept + "\n")
            index += 1
            continue
        stripped = kept.rstrip()
        if stripped.endswith("\\") and not stripped.endswith("\\\\"):
            buffer.append(stripped[:-1] + " ")
            index += 1
            if index < len(lines):
                continue
        else:
            buffer.append(kept)

        # here-document bodies follow the line that opened them
        consumed = index
        for heredoc in [h for h in pending if not h.body and not h.start_line]:
            heredoc.start_line = consumed + 2 + first_line - 1
            body: List[str] = []
            cursor = consumed + 1
            while cursor < len(lines):
                candidate = lines[cursor].lstrip("\t") if heredoc.strip_tabs else lines[cursor]
                if candidate.rstrip() == heredoc.delimiter:
                    break
                body.append(candidate)
                cursor += 1
            heredoc.body = "\n".join(body)
            consumed = cursor
        if consumed != index:
            flush(consumed)
            index = consumed + 1
            continue

        if stripped.endswith(CONTINUATION_OPS) and index + 1 < len(lines):
            buffer.append(" ")
            index += 1
            continue
        flush(index)
        index += 1

    if buffer:
        flush(len(lines) - 1)
    return statements


def looks_like_script(text: str) -> bool:
    """True when input should be treated as a multi-statement script."""
    return "\n" in text.strip() or text.startswith("#!")
