"""A small, forgiving, **non-executing** POSIX-ish shell lexer.

The lexer exists so that structural questions ("does a download feed a shell?",
"what is the executable of the third pipeline stage?") can be answered from a
parse tree rather than from substring matching.

Design rules:

* It never executes, expands, globs or resolves anything.  Every value stays an
  inert string.
* It never raises on malformed input.  Unterminated quotes, stray operators and
  binary junk are tolerated and parsing continues.
* It is deliberately *approximate*: shell grammar is enormous, and a good
  decomposition into words, operators, redirections and pipeline stages is
  worth far more than exact POSIX conformance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Operators, longest match first.  ``2>`` style file-descriptor prefixes are
# folded into the operator as they are lexed.
OPERATORS: Tuple[str, ...] = (
    "2>&1", "1>&2", "&>>", "2>>", "<<<", "&&", "||", ";;", "|&", "&>", ">>",
    ">&", "<<", "2>", "|", "&", ";", "<", ">", "(", ")", "\n",
)
SEPARATORS = frozenset({"|", "||", "&&", ";", "&", ";;", "\n", "|&", "(", ")"})
REDIRECTS = frozenset({">", ">>", "<", "<<", "<<<", "2>", "2>>", "&>", "&>>", ">&", "|&"})
NO_TARGET_REDIRECTS = frozenset({"2>&1", "1>&2"})


@dataclass
class Token:
    """A single lexical token."""

    kind: str                  # "word" | "op"
    text: str                  # as written, including quotes
    value: str                 # unquoted value (words only)
    quoted: bool = False
    fd: Optional[str] = None   # file descriptor prefix for redirect operators


@dataclass
class SimpleCommand:
    """One "simple command": an argv plus its redirections.

    A command line such as ``curl -s URL | bash && echo done`` yields three
    simple commands, the first two joined by ``|`` (same pipeline) and the third
    joined by ``&&`` (new pipeline).
    """

    argv: List[str] = field(default_factory=list)
    redirects: List[Tuple[str, str]] = field(default_factory=list)
    pipeline_id: int = 0
    pipeline_index: int = 0     # position inside its pipeline (0 = first stage)
    pipeline_length: int = 1


@dataclass
class ParsedCommand:
    """Result of lexing one command line."""

    raw: str
    tokens: List[Token] = field(default_factory=list)
    commands: List[SimpleCommand] = field(default_factory=list)
    substitutions: List[str] = field(default_factory=list)   # text inside $( ), ` ` and <( )
    ansi_c_quote_count: int = 0


def _match_operator(text: str, index: int) -> Optional[str]:
    for op in OPERATORS:
        if text.startswith(op, index):
            return op
    return None


def _find_closing(text: str, start: int, open_ch: str, close_ch: str) -> int:
    """Index just past the matching close character, or ``len(text)``."""
    depth = 0
    i = start
    n = len(text)
    quote = ""
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            i += 1
            continue
        if ch == "\\":
            i += 2
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def tokenize(command: str) -> ParsedCommand:
    """Lex ``command`` into words, operators and simple commands."""
    parsed = ParsedCommand(raw=command)
    if not command:
        return parsed

    text = command
    n = len(text)
    i = 0
    buf: List[str] = []          # unquoted value under construction
    raw_buf: List[str] = []      # text as written
    quoted = False

    def flush_word() -> None:
        nonlocal quoted
        if not raw_buf:
            return
        parsed.tokens.append(Token(kind="word", text="".join(raw_buf), value="".join(buf), quoted=quoted))
        buf.clear()
        raw_buf.clear()
        quoted = False

    while i < n:
        ch = text[i]

        # ---- escapes -----------------------------------------------------
        if ch == "\\":
            raw_buf.append(ch)
            if i + 1 < n:
                raw_buf.append(text[i + 1])
                buf.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue

        # ---- single quotes ----------------------------------------------
        if ch == "'":
            close = text.find("'", i + 1)
            if close == -1:
                close = n
                body = text[i + 1:]
            else:
                body = text[i + 1:close]
            quoted = True
            raw_buf.append(text[i:min(close + 1, n)])
            buf.append(body)
            i = min(close + 1, n)
            continue

        # ---- double quotes -----------------------------------------------
        if ch == '"':
            j = i + 1
            body: List[str] = []
            while j < n:
                cj = text[j]
                if cj == "\\" and j + 1 < n:
                    body.append(text[j + 1])
                    j += 2
                    continue
                if cj == '"':
                    break
                if cj == "$" and text.startswith("$(", j):
                    end = _find_closing(text, j + 1, "(", ")")
                    parsed.substitutions.append(text[j + 2:max(end - 1, j + 2)])
                    body.append(text[j:end])
                    j = end
                    continue
                if cj == "`":
                    close_bt = text.find("`", j + 1)
                    close_bt = n if close_bt == -1 else close_bt
                    parsed.substitutions.append(text[j + 1:close_bt])
                    body.append(text[j:close_bt + 1])
                    j = close_bt + 1
                    continue
                body.append(cj)
                j += 1
            quoted = True
            raw_buf.append(text[i:min(j + 1, n)])
            buf.append("".join(body))
            i = min(j + 1, n)
            continue

        # ---- $'...' / $(...) / $((...)) / $VAR -----------------------------
        if ch == "$" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "(":
                if text.startswith("$((", i):        # arithmetic expansion
                    end = _find_closing(text, i + 2, "(", ")")
                    end = _find_closing(text, end - 1, "(", ")") if end < n else end
                else:
                    end = _find_closing(text, i + 1, "(", ")")
                parsed.substitutions.append(text[i + 2:max(end - 1, i + 2)])
                raw_buf.append(text[i:end])
                buf.append(text[i:end])
                i = end
                continue
            if nxt == "'":
                parsed.ansi_c_quote_count += 1
                close = text.find("'", i + 2)
                close = n if close == -1 else close
                quoted = True
                raw_buf.append(text[i:min(close + 1, n)])
                buf.append(text[i + 2:close])
                i = min(close + 1, n)
                continue
            raw_buf.append(ch)
            buf.append(ch)
            i += 1
            continue

        # ---- backtick substitution ----------------------------------------
        if ch == "`":
            close = text.find("`", i + 1)
            if close == -1:
                close = n
            parsed.substitutions.append(text[i + 1:close])
            raw_buf.append(text[i:min(close + 1, n)])
            buf.append(text[i:min(close + 1, n)])
            i = min(close + 1, n)
            continue

        # ---- process substitution <( ) / >( ) -------------------------------
        if ch in "<>" and i + 1 < n and text[i + 1] == "(":
            end = _find_closing(text, i + 1, "(", ")")
            parsed.substitutions.append(text[i + 2:max(end - 1, i + 2)])
            raw_buf.append(text[i:end])
            buf.append(text[i:end])
            i = end
            continue

        # ---- whitespace ----------------------------------------------------
        if ch.isspace() and ch != "\n":
            flush_word()
            i += 1
            continue

        # ---- operators ------------------------------------------------------
        op = _match_operator(text, i)
        if op is not None:
            fd = None
            if op[0] in "<>" and buf and "".join(buf).isdigit() and len(buf) <= 2:
                fd = "".join(buf)          # e.g. "3>" -- fold the fd into the op
                buf.clear()
                raw_buf.clear()
                quoted = False
            flush_word()
            parsed.tokens.append(Token(kind="op", text=op, value=op, fd=fd))
            i += len(op)
            continue

        # ---- ordinary character ---------------------------------------------
        raw_buf.append(ch)
        buf.append(ch)
        i += 1

    flush_word()
    parsed.commands = _build_commands(parsed.tokens)
    return parsed


def _build_commands(tokens: List[Token]) -> List[SimpleCommand]:
    """Group tokens into :class:`SimpleCommand` objects."""
    current = SimpleCommand()
    pipeline_id = 0
    pipeline_index = 0
    pending_redirect: Optional[str] = None
    commands: List[SimpleCommand] = []

    def close(op: str) -> None:
        nonlocal current, pipeline_index, pipeline_id
        if current.argv or current.redirects:
            current.pipeline_id = pipeline_id
            current.pipeline_index = pipeline_index
            commands.append(current)
        if op in ("|", "|&"):
            pipeline_index += 1
        else:
            pipeline_id += 1
            pipeline_index = 0
        current = SimpleCommand()

    for token in tokens:
        if token.kind == "op":
            if token.text in NO_TARGET_REDIRECTS:
                current.redirects.append((token.text, ""))
            elif token.text in REDIRECTS and token.text not in SEPARATORS:
                pending_redirect = (token.fd or "") + token.text
            elif token.text in SEPARATORS:
                close(token.text)
            continue
        if pending_redirect is not None:
            current.redirects.append((pending_redirect, token.value))
            pending_redirect = None
            continue
        current.argv.append(token.value)

    close("")

    lengths = {}
    for command in commands:
        lengths[command.pipeline_id] = lengths.get(command.pipeline_id, 0) + 1
    for command in commands:
        command.pipeline_length = lengths[command.pipeline_id]
    return commands
