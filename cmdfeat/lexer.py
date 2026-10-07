"""A small, forgiving, **non-executing** POSIX-ish shell lexer.

The lexer exists so that structural questions ("does a download feed a shell?",
"what is the executable of the third pipeline stage?") can be answered from a
parse tree rather than from substring matching.

Design rules:

* It never executes, expands, globs or resolves anything.  Every value stays an
  inert string.
* It never raises on malformed input.  Unterminated quotes, stray operators and
  binary junk are recorded as flags (``unbalanced_quotes``) and parsing
  continues, because real telemetry contains all of that.
* It is deliberately *approximate*: shell grammar is enormous, and for feature
  extraction a good decomposition into words, operators, redirections and
  pipeline stages is worth far more than exact POSIX conformance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Operators, longest match first.  ``2>`` style file-descriptor prefixes are
# handled separately (see ``_fd_prefix``).
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
    start: int
    end: int
    quoted: bool = False
    single_quoted: bool = False
    double_quoted: bool = False
    has_substitution: bool = False
    has_expansion: bool = False
    fd: Optional[str] = None   # file descriptor prefix for redirect operators


@dataclass
class SimpleCommand:
    """One "simple command": an argv plus its redirections.

    A command line such as ``curl -s URL | bash && echo done`` yields three
    simple commands, the first two joined by ``|`` (same pipeline) and the third
    joined by ``&&`` (new pipeline).
    """

    argv: List[str] = field(default_factory=list)
    words: List[Token] = field(default_factory=list)
    redirects: List[Tuple[str, str]] = field(default_factory=list)
    preceding_op: str = ""      # operator that introduced this command ("" for the first)
    following_op: str = ""      # operator that terminates it
    pipeline_id: int = 0
    pipeline_index: int = 0     # position inside its pipeline (0 = first stage)
    pipeline_length: int = 1
    subshell_depth: int = 0
    from_substitution: bool = False

    @property
    def text(self) -> str:
        return " ".join(token.text for token in self.words)

    @property
    def head(self) -> str:
        """First word as written (may be an assignment or a wrapper)."""
        return self.argv[0] if self.argv else ""


@dataclass
class ParsedCommand:
    """Result of lexing one command line."""

    raw: str
    tokens: List[Token] = field(default_factory=list)
    commands: List[SimpleCommand] = field(default_factory=list)
    substitutions: List[str] = field(default_factory=list)   # text inside $( ) and ` `
    operators: List[str] = field(default_factory=list)
    single_quote_count: int = 0
    double_quote_count: int = 0
    escape_count: int = 0
    expansion_count: int = 0
    backtick_count: int = 0
    dollar_paren_count: int = 0
    ansi_c_quote_count: int = 0
    unbalanced_quotes: bool = False
    has_heredoc: bool = False
    max_pipeline_length: int = 1
    max_subshell_depth: int = 0

    @property
    def words(self) -> List[Token]:
        return [t for t in self.tokens if t.kind == "word"]


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
    word_start = 0
    flags = {"quoted": False, "single": False, "double": False,
             "subst": False, "expand": False}

    def reset_flags() -> None:
        for key in flags:
            flags[key] = False

    def flush_word(end: int) -> None:
        if not raw_buf:
            return
        parsed.tokens.append(
            Token(
                kind="word",
                text="".join(raw_buf),
                value="".join(buf),
                start=word_start,
                end=end,
                quoted=flags["quoted"],
                single_quoted=flags["single"],
                double_quoted=flags["double"],
                has_substitution=flags["subst"],
                has_expansion=flags["expand"],
            )
        )
        buf.clear()
        raw_buf.clear()
        reset_flags()

    while i < n:
        ch = text[i]

        # ---- escapes -----------------------------------------------------
        if ch == "\\":
            parsed.escape_count += 1
            if not raw_buf:
                word_start = i
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
            if not raw_buf:
                word_start = i
            close = text.find("'", i + 1)
            if close == -1:
                parsed.unbalanced_quotes = True
                close = n
                body = text[i + 1:]
            else:
                body = text[i + 1:close]
                parsed.single_quote_count += 1
            flags["quoted"] = flags["single"] = True
            raw_buf.append(text[i:min(close + 1, n)])
            buf.append(body)
            i = min(close + 1, n)
            continue

        # ---- double quotes -----------------------------------------------
        if ch == '"':
            if not raw_buf:
                word_start = i
            j = i + 1
            body: List[str] = []
            closed = False
            while j < n:
                cj = text[j]
                if cj == "\\" and j + 1 < n:
                    parsed.escape_count += 1
                    body.append(text[j + 1])
                    j += 2
                    continue
                if cj == '"':
                    closed = True
                    break
                if cj == "$":
                    if text.startswith("$(", j):
                        end = _find_closing(text, j + 1, "(", ")")
                        parsed.substitutions.append(text[j + 2:max(end - 1, j + 2)])
                        parsed.dollar_paren_count += 1
                        flags["subst"] = True
                        body.append(text[j:end])
                        j = end
                        continue
                    parsed.expansion_count += 1
                    flags["expand"] = True
                elif cj == "`":
                    close_bt = text.find("`", j + 1)
                    close_bt = n if close_bt == -1 else close_bt
                    parsed.substitutions.append(text[j + 1:close_bt])
                    parsed.backtick_count += 1
                    flags["subst"] = True
                    body.append(text[j:close_bt + 1])
                    j = close_bt + 1
                    continue
                body.append(cj)
                j += 1
            if not closed:
                parsed.unbalanced_quotes = True
            else:
                parsed.double_quote_count += 1
            flags["quoted"] = flags["double"] = True
            raw_buf.append(text[i:min(j + 1, n)])
            buf.append("".join(body))
            i = min(j + 1, n)
            continue

        # ---- $'...' / $"..." / $(...) / ${...} / $VAR ---------------------
        if ch == "$" and i + 1 < n:
            nxt = text[i + 1]
            if not raw_buf:
                word_start = i
            if nxt == "(":
                if text.startswith("$((", i):        # arithmetic expansion
                    end = _find_closing(text, i + 2, "(", ")")
                    end = _find_closing(text, end - 1, "(", ")") if end < n else end
                else:
                    end = _find_closing(text, i + 1, "(", ")")
                parsed.substitutions.append(text[i + 2:max(end - 1, i + 2)])
                parsed.dollar_paren_count += 1
                flags["subst"] = flags["quoted"] = flags["quoted"]  # keep flags stable
                flags["subst"] = True
                raw_buf.append(text[i:end])
                buf.append(text[i:end])
                i = end
                continue
            if nxt == "'":
                parsed.ansi_c_quote_count += 1
                close = text.find("'", i + 2)
                close = n if close == -1 else close
                if close == n:
                    parsed.unbalanced_quotes = True
                flags["quoted"] = flags["single"] = True
                raw_buf.append(text[i:min(close + 1, n)])
                buf.append(text[i + 2:close])
                i = min(close + 1, n)
                continue
            parsed.expansion_count += 1
            flags["expand"] = True
            raw_buf.append(ch)
            buf.append(ch)
            i += 1
            continue

        # ---- backtick substitution ----------------------------------------
        if ch == "`":
            if not raw_buf:
                word_start = i
            close = text.find("`", i + 1)
            if close == -1:
                parsed.unbalanced_quotes = True
                close = n
            else:
                parsed.backtick_count += 1
            parsed.substitutions.append(text[i + 1:close])
            flags["subst"] = True
            raw_buf.append(text[i:min(close + 1, n)])
            buf.append(text[i:min(close + 1, n)])
            i = min(close + 1, n)
            continue

        # ---- process substitution <( ) / >( ) -------------------------------
        if ch in "<>" and i + 1 < n and text[i + 1] == "(":
            if not raw_buf:
                word_start = i
            end = _find_closing(text, i + 1, "(", ")")
            parsed.substitutions.append(text[i + 2:max(end - 1, i + 2)])
            parsed.dollar_paren_count += 1
            flags["subst"] = True
            raw_buf.append(text[i:end])
            buf.append(text[i:end])
            i = end
            continue

        # ---- whitespace ----------------------------------------------------
        if ch.isspace() and ch != "\n":
            flush_word(i)
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
                reset_flags()
            flush_word(i)
            if op in ("<<", "<<<"):
                parsed.has_heredoc = op == "<<"
            parsed.tokens.append(
                Token(kind="op", text=op, value=op, start=i, end=i + len(op), fd=fd)
            )
            parsed.operators.append(op)
            i += len(op)
            continue

        # ---- ordinary character ---------------------------------------------
        if not raw_buf:
            word_start = i
        raw_buf.append(ch)
        buf.append(ch)
        i += 1

    flush_word(n)
    _build_commands(parsed)
    return parsed


def _build_commands(parsed: ParsedCommand) -> None:
    """Group tokens into :class:`SimpleCommand` objects."""
    current = SimpleCommand()
    pipeline_id = 0
    pipeline_index = 0
    depth = 0
    pending_redirect: Optional[str] = None
    commands: List[SimpleCommand] = []

    def close(op: str) -> None:
        nonlocal current, pipeline_index, pipeline_id
        current.following_op = op
        if current.argv or current.redirects:
            current.pipeline_id = pipeline_id
            current.pipeline_index = pipeline_index
            current.subshell_depth = depth
            commands.append(current)
        if op == "|" or op == "|&":
            pipeline_index += 1
        else:
            pipeline_id += 1
            pipeline_index = 0
        current = SimpleCommand(preceding_op=op)

    for token in parsed.tokens:
        if token.kind == "op":
            if token.text in NO_TARGET_REDIRECTS:
                current.redirects.append((token.text, ""))
                continue
            if token.text in REDIRECTS and token.text not in SEPARATORS:
                pending_redirect = (token.fd or "") + token.text
                continue
            if token.text in SEPARATORS:
                if token.text == "(":
                    depth += 1
                    parsed.max_subshell_depth = max(parsed.max_subshell_depth, depth)
                    close("(")
                    continue
                if token.text == ")":
                    close(")")
                    depth = max(0, depth - 1)
                    continue
                close(token.text)
                continue
            continue
        if pending_redirect is not None:
            current.redirects.append((pending_redirect, token.value))
            pending_redirect = None
            continue
        current.argv.append(token.value)
        current.words.append(token)

    close("")

    # annotate pipeline lengths
    lengths = {}
    for command in commands:
        lengths[command.pipeline_id] = lengths.get(command.pipeline_id, 0) + 1
    for command in commands:
        command.pipeline_length = lengths.get(command.pipeline_id, 1)
    parsed.commands = commands
    parsed.max_pipeline_length = max(lengths.values()) if lengths else 1


def parse_nested(parsed: ParsedCommand, max_depth: int = 2) -> List[SimpleCommand]:
    """Parse the contents of ``$( )`` / backtick substitutions one level deep.

    Commands hidden inside a substitution are real command executions, so their
    executables must participate in tool detection (``$(curl -s URL)``).
    """
    nested: List[SimpleCommand] = []
    frontier = list(parsed.substitutions)
    depth = 0
    while frontier and depth < max_depth:
        next_frontier: List[str] = []
        for text in frontier:
            if not text or not text.strip():
                continue
            sub = tokenize(text)
            for command in sub.commands:
                command.from_substitution = True
                nested.append(command)
            next_frontier.extend(sub.substitutions)
        frontier = next_frontier
        depth += 1
    return nested
