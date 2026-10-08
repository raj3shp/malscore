"""Shared per-command analysis context.

Building the context is the only expensive step: it lexes the command line,
resolves *effective* executables (unwrapping ``sudo``/``env``/``xargs``...),
descends into command substitutions, shell ``-c`` payloads and remote command
arguments, and extracts paths, URLs, IPs and ports once.  Every feature group
then reads from this context instead of re-scanning the string.

Everything here is read-only string analysis.  No command is ever executed,
expanded or resolved.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set
from urllib.parse import urlsplit

from .lexer import ParsedCommand, SimpleCommand, tokenize

# --------------------------------------------------------------------------
# executable resolution
# --------------------------------------------------------------------------
#: Programs that run *another* program; the interesting executable is the one
#: they wrap, so resolution skips over them (recording them separately).
WRAPPER_VALUE_FLAGS: Dict[str, Set[str]] = {
    "sudo": {"-u", "-g", "-p", "-C", "-h", "-r", "-t", "--user", "--group", "--prompt"},
    "doas": {"-u", "-C"},
    "env": {"-u", "--unset", "-C", "--chdir", "-S"},
    "nohup": set(),
    "setsid": set(),
    "stdbuf": {"-i", "-o", "-e"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p"},
    "time": {"-f", "-o", "--format", "--output"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "xargs": {"-I", "-i", "-n", "-P", "-d", "-a", "-E", "-e", "-s", "-L",
              "--max-args", "--max-procs", "--delimiter", "--arg-file", "--replace"},
    "watch": {"-n", "--interval"},
    "strace": {"-o", "-p", "-e", "-s", "-E"},
    "ltrace": {"-o", "-p", "-e", "-s"},
    "flock": {"-w", "-E", "--timeout"},
    "unbuffer": set(),
    "chroot": set(),
    "proxychains": set(),
    "faketime": set(),
}
#: Wrappers whose first positional argument is not the program (a duration, a
#: directory, ...) and must be skipped as well.
WRAPPER_POSITIONAL_SKIP = {"timeout": 1, "chroot": 1, "faketime": 1}

SHELLS = frozenset({"bash", "sh", "dash", "zsh", "fish", "ksh", "mksh", "csh",
                    "tcsh", "ash", "busybox", "rbash", "pdksh", "yash"})
SCRIPT_INTERPRETERS = frozenset({
    "python", "python2", "python3", "perl", "ruby", "php", "node", "nodejs",
    "awk", "gawk", "mawk", "nawk", "sed", "expect", "lua", "tclsh", "powershell",
    "pwsh", "Rscript", "julia", "groovy", "jshell", "deno", "bun",
})
INTERPRETERS = SHELLS | SCRIPT_INTERPRETERS
#: Flags that introduce an inline script payload, per interpreter family.
INLINE_SCRIPT_FLAGS = {"-c", "-e", "--command", "--eval", "-E", "--exec"}
#: Shell reserved words that can precede a command on the same line
#: (``then curl ... | sh``); they are skipped so the real program is resolved.
PREFIX_KEYWORDS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{"})
#: Reserved words that start or end a construct rather than run a program.
NON_EXECUTING_KEYWORDS = frozenset({"for", "case", "select", "function", "in",
                                    "fi", "done", "esac", "}"})
#: Tools that take a bare port number as a positional argument (nc host 4444).
PORT_POSITIONAL_TOOLS = frozenset({"nc", "ncat", "netcat", "telnet", "socat", "tftp", "rsh"})


def is_flag(token: str) -> bool:
    """True for ``-x`` / ``--long`` style option tokens."""
    return len(token) > 1 and token.startswith("-") and token != "--"


def flag_letters(tokens: Iterable[str]) -> Set[str]:
    """Expand clustered short options into individual flags.

    ``grep -rPo`` and ``rm -rvf`` mean the same as ``-r -P -o`` and ``-r -v -f``;
    membership tests for flags such as "recursive" must see the letters, not the
    cluster. Numeric options (``kill -9``) and long options are left alone.
    """
    letters: Set[str] = set()
    for token in tokens:
        if not token.startswith("-") or token.startswith("--") or len(token) < 3:
            continue
        body = token[1:].split("=", 1)[0]
        if body.isalpha():
            letters.update("-" + char for char in body)
    return letters


def is_assignment(token: str) -> bool:
    """True for ``VAR=value`` prefixes (environment assignments)."""
    if "=" not in token or token.startswith("="):
        return False
    name = token.split("=", 1)[0]
    return bool(name) and all(ch.isalnum() or ch == "_" for ch in name) and not name[0].isdigit()


@dataclass
class Execution:
    """One resolved program execution inside a command line."""

    name: str                         # executable as written (may include a path)
    basename: str                     # basename, lowercased
    argv: List[str]                   # argv of the effective program
    args: List[str]                   # argv[1:]
    wrappers: List[str] = field(default_factory=list)
    assignments: List[str] = field(default_factory=list)
    command: Optional[SimpleCommand] = None

    @property
    def positionals(self) -> List[str]:
        return [a for a in self.args if not is_flag(a) and not is_assignment(a)]


def resolve_execution(command: SimpleCommand) -> Optional[Execution]:
    """Find the effective executable of a simple command.

    ``sudo -u svc env FOO=1 timeout 30 python3 app.py`` resolves to ``python3``
    with wrappers ``[sudo, env, timeout]``.
    """
    argv = list(command.argv)
    wrappers: List[str] = []
    assignments: List[str] = []
    index = 0
    guard = 0
    while index < len(argv) and guard < 24:
        guard += 1
        token = argv[index]
        if is_assignment(token):
            assignments.append(token)
            index += 1
            continue
        if not wrappers and token in PREFIX_KEYWORDS:
            index += 1
            continue
        if not wrappers and token in NON_EXECUTING_KEYWORDS:
            return None
        base = token.rsplit("/", 1)[-1].lower()
        if base in WRAPPER_VALUE_FLAGS and index + 1 < len(argv):
            wrappers.append(base)
            value_flags = WRAPPER_VALUE_FLAGS[base]
            index += 1
            skip_positional = WRAPPER_POSITIONAL_SKIP.get(base, 0)
            while index < len(argv):
                current = argv[index]
                if is_flag(current):
                    index += 2 if current in value_flags else 1
                    continue
                if is_assignment(current):
                    assignments.append(current)
                    index += 1
                    continue
                if current == "--":
                    index += 1
                    continue
                if skip_positional > 0:
                    skip_positional -= 1
                    index += 1
                    continue
                break
            continue
        break
    if index >= len(argv):
        # e.g. bare "sudo -l" or "sudo" alone: the wrapper is the execution
        if wrappers:
            name = wrappers[-1]
            return Execution(name=name, basename=name, argv=argv,
                             args=argv[1:] if argv else [], wrappers=wrappers[:-1],
                             assignments=assignments, command=command)
        return None
    name = argv[index]
    return Execution(
        name=name,
        basename=name.rsplit("/", 1)[-1].lower(),
        argv=argv[index:],
        args=argv[index + 1:],
        wrappers=wrappers,
        assignments=assignments,
        command=command,
    )


def inline_payload(execution: Execution) -> Optional[str]:
    """Return the inline script passed via ``-c``/``-e``, if any."""
    for index, token in enumerate(execution.args):
        if token in INLINE_SCRIPT_FLAGS and index + 1 < len(execution.args):
            return execution.args[index + 1]
        if token.startswith("--command=") or token.startswith("--eval="):
            return token.split("=", 1)[1]
    return None


#: ssh options that consume the following argument.
SSH_VALUE_FLAGS = frozenset({"-i", "-p", "-l", "-o", "-F", "-J", "-b", "-c", "-D", "-L", "-R", "-W"})


def remote_payload(execution: Execution) -> Optional[str]:
    """Return the command a remote/container runner is asked to run."""
    base = execution.basename
    args = execution.args
    if base == "ssh":
        skip_next = False
        cleaned: List[str] = []
        for token in args:
            if skip_next:
                skip_next = False
                continue
            if token in SSH_VALUE_FLAGS:
                skip_next = True
                continue
            if is_flag(token):
                continue
            cleaned.append(token)
        return " ".join(cleaned[1:]) if len(cleaned) >= 2 else None
    if base in ("docker", "podman", "nerdctl", "ctr", "crictl") and args:
        if args[0] in ("run", "exec"):
            positionals = [a for a in args[1:] if not is_flag(a)]
            if len(positionals) >= 2:
                return " ".join(positionals[1:])
        return None
    if base == "kubectl" and "--" in args:
        return " ".join(args[args.index("--") + 1:])
    if base == "chroot" and execution.positionals:
        return " ".join(execution.positionals[1:])
    if base == "su":
        return inline_payload(execution)
    return None


# --------------------------------------------------------------------------
# network indicators
# --------------------------------------------------------------------------
URL_RE = re.compile(
    r"(?i)\b(?P<scheme>[a-z][a-z0-9+.\-]{1,15})://(?P<rest>[^\s'\"`<>|;)\\]+)"
)
IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")
IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:])((?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?:%\w+)?)(?![\w:])")
HOST_PORT_RE = re.compile(r"(?<=[\w\].]):(\d{1,5})(?![\w.])")


@dataclass
class UrlRef:
    """A URL found in a command line, decomposed into parts."""

    raw: str
    scheme: str = ""
    host: str = ""
    port: Optional[int] = None
    path: str = ""
    host_is_ip: bool = False


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def extract_urls(text: str) -> List[UrlRef]:
    """Find URL-like substrings and split them into components."""
    urls: List[UrlRef] = []
    for match in URL_RE.finditer(text):
        raw = match.group(0).rstrip(".,;:!)\"'")
        try:
            parts = urlsplit(raw)
        except ValueError:
            continue
        host = parts.hostname or ""
        try:
            port = parts.port
        except ValueError:
            port = None
        urls.append(UrlRef(raw=raw, scheme=(parts.scheme or "").lower(), host=host, port=port,
                           path=parts.path or "", host_is_ip=bool(host) and _is_ip(host)))
    return urls


def extract_ipv4(text: str) -> List[str]:
    found: List[str] = []
    for match in IPV4_RE.finditer(text):
        try:
            ipaddress.IPv4Address(match.group(1))
        except ValueError:
            continue
        found.append(match.group(1))
    return found


def extract_ipv6(text: str) -> List[str]:
    found: List[str] = []
    for match in IPV6_CANDIDATE_RE.finditer(text):
        candidate = match.group(1).split("%")[0]
        if candidate.count(":") < 2:
            continue
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        found.append(candidate)
    return found


def extract_ports(text: str, urls: Sequence[UrlRef], argv_lists: Sequence[Sequence[str]]) -> List[int]:
    """Ports from URLs, ``host:port`` pairs and ``-p``/``--port`` options."""
    ports: List[int] = [u.port for u in urls if u.port]
    for match in HOST_PORT_RE.finditer(text):
        ports.append(int(match.group(1)))
    for argv in argv_lists:
        for index, token in enumerate(argv):
            if token in ("-p", "--port", "-P", "--source-port") and index + 1 < len(argv):
                if argv[index + 1].isdigit():
                    ports.append(int(argv[index + 1]))
            elif token.startswith("--port="):
                tail = token.split("=", 1)[1]
                if tail.isdigit():
                    ports.append(int(tail))
    return [p for p in ports if 0 < p <= 65535]


# --------------------------------------------------------------------------
# paths
# --------------------------------------------------------------------------
SED_EXPR_RE = re.compile(r"^[sy]([/|,#!:])(?:[^\1]|\\.)*\1")


@dataclass
class PathRef:
    """A filesystem path found in a command line."""

    raw: str
    basename: str = ""
    extension: str = ""
    from_redirect: bool = False

    @property
    def lowered(self) -> str:
        return self.raw.lower()


def looks_like_path(token: str) -> bool:
    """Heuristic: does this argument denote a filesystem path?

    Deliberately conservative -- ``sed`` expressions, URLs, option values and
    quoted remote commands are common sources of false positives, so they are
    filtered out explicitly.
    """
    if not token or token in ("-", "--"):
        return False
    if "://" in token:
        return False
    if any(ch.isspace() for ch in token):
        return False            # a quoted remote command, not a path
    if "$(" in token or "`" in token or token.startswith("$"):
        return False            # a substitution, not a path
    if token.startswith("-"):
        return False
    if SED_EXPR_RE.match(token):
        return False
    if token in (".", ".."):
        return True
    return token.startswith("~") or "/" in token


def make_path_ref(token: str, from_redirect: bool = False) -> PathRef:
    cleaned = token.rstrip(",;")
    basename = cleaned.rsplit("/", 1)[-1]
    extension = basename.rsplit(".", 1)[-1].lower() if "." in basename[1:] else ""
    return PathRef(raw=cleaned, basename=basename, extension=extension, from_redirect=from_redirect)


def _collect_paths(commands: Sequence[SimpleCommand]) -> List[PathRef]:
    paths: List[PathRef] = []
    seen: Set[str] = set()
    for command in commands:
        for token in command.argv[1:]:
            candidate = token.split("=", 1)[1] if "=" in token and (
                not token.startswith("-") or token.startswith("--")) else token
            if looks_like_path(candidate) and candidate not in seen:
                seen.add(candidate)
                paths.append(make_path_ref(candidate))
        for _op, target in command.redirects:
            if target and target not in seen:
                seen.add(target)
                paths.append(make_path_ref(target, from_redirect=True))
    return paths


# --------------------------------------------------------------------------
# context
# --------------------------------------------------------------------------
@dataclass
class CommandContext:
    """Everything the feature groups need about a single command line."""

    raw: str
    parsed: ParsedCommand
    executions: List[Execution] = field(default_factory=list)
    shell_payloads: List[str] = field(default_factory=list)
    script_payloads: List[str] = field(default_factory=list)
    remote_payloads: List[str] = field(default_factory=list)
    paths: List[PathRef] = field(default_factory=list)
    urls: List[UrlRef] = field(default_factory=list)
    ipv4s: List[str] = field(default_factory=list)
    ipv6s: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    scan_text: str = ""       # raw command plus inline script payloads, for keyword scanning
    lower: str = ""           # scan_text, lower-cased

    @property
    def basenames(self) -> List[str]:
        return [e.basename for e in self.executions]

    def uses(self, *names: str) -> bool:
        """True if any resolved executable basename matches one of ``names``."""
        wanted = set(names)
        return any(e.basename in wanted for e in self.executions)

    def executions_of(self, *names: str) -> List[Execution]:
        wanted = set(names)
        return [e for e in self.executions if e.basename in wanted]

    def path_matches(self, *prefixes: str) -> List[PathRef]:
        return [p for p in self.paths
                if any(p.lowered == prefix.rstrip("/") or p.lowered.startswith(prefix) for prefix in prefixes)]

    def basename_matches(self, *names: str) -> List[PathRef]:
        wanted = set(names)
        return [p for p in self.paths if p.basename.lower() in wanted]


def build_context(command: str) -> CommandContext:
    """Lex and analyse one command line into a :class:`CommandContext`."""
    parsed = tokenize(command)

    executions: List[Execution] = []
    shell_payloads: List[str] = []
    script_payloads: List[str] = []
    remote_payloads: List[str] = []

    def absorb(commands: Sequence[SimpleCommand]) -> None:
        for simple in commands:
            execution = resolve_execution(simple)
            if execution is None:
                continue
            executions.append(execution)
            payload = inline_payload(execution)
            if payload:
                (shell_payloads if execution.basename in SHELLS else script_payloads).append(payload)
            remote = remote_payload(execution)
            if remote:
                remote_payloads.append(remote)

    absorb(parsed.commands)

    # one level of descent: substitutions, shell -c payloads, remote commands
    nested_commands: List[SimpleCommand] = []
    for text in list(parsed.substitutions) + shell_payloads + remote_payloads:
        if text and text.strip():
            nested_commands.extend(tokenize(text).commands)
    absorb(nested_commands)

    all_commands = list(parsed.commands) + nested_commands
    scan_text = "\n".join([command] + script_payloads)

    urls = extract_urls(scan_text)
    ports = extract_ports(scan_text, urls, [c.argv for c in all_commands])
    for execution in executions:
        if execution.basename in PORT_POSITIONAL_TOOLS:
            for token in execution.positionals:
                if token.isdigit() and 0 < int(token) <= 65535:
                    ports.append(int(token))

    return CommandContext(
        raw=command,
        parsed=parsed,
        executions=executions,
        shell_payloads=shell_payloads,
        script_payloads=script_payloads,
        remote_payloads=remote_payloads,
        paths=_collect_paths(all_commands),
        urls=urls,
        ipv4s=extract_ipv4(scan_text),
        ipv6s=extract_ipv6(scan_text),
        ports=sorted(set(ports)),
        scan_text=scan_text,
        lower=scan_text.lower(),
    )
