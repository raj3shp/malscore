"""Shared per-event analysis context.

Building the context is the only expensive step: it lexes the command line,
resolves *effective* executables (unwrapping ``sudo``/``env``/``xargs``...),
descends into command substitutions, shell ``-c`` payloads and remote command
arguments, and extracts paths, URLs, IPs, domains and ports once.  Every
feature module then reads from this context instead of re-scanning the string.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import textutil as tu
from .events import Event
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
    nested: bool = False              # found inside a substitution/payload/remote command

    @property
    def flags(self) -> List[str]:
        return [a for a in self.args if is_flag(a)]

    @property
    def positionals(self) -> List[str]:
        return [a for a in self.args if not is_flag(a) and not is_assignment(a)]


def resolve_execution(command: SimpleCommand, nested: bool = False) -> Optional[Execution]:
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
                    if current in value_flags:
                        index += 2
                    elif "=" in current and current.startswith("--"):
                        index += 1
                    else:
                        index += 1
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
                             assignments=assignments, command=command, nested=nested)
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
        nested=nested,
    )


def inline_payload(execution: Execution) -> Optional[str]:
    """Return the inline script passed via ``-c``/``-e``, if any."""
    for index, token in enumerate(execution.args):
        if token in INLINE_SCRIPT_FLAGS and index + 1 < len(execution.args):
            return execution.args[index + 1]
        if token.startswith("--command=") or token.startswith("--eval="):
            return token.split("=", 1)[1]
    return None


def remote_payload(execution: Execution) -> Optional[str]:
    """Return the command a remote/container runner is asked to run."""
    base = execution.basename
    args = execution.args
    if base == "ssh":
        positionals = [a for a in args if not is_flag(a)]
        skip_next = False
        cleaned: List[str] = []
        for token in args:
            if skip_next:
                skip_next = False
                continue
            if token in ("-i", "-p", "-l", "-o", "-F", "-J", "-b", "-c", "-D", "-L", "-R", "-W"):
                skip_next = True
                continue
            if is_flag(token):
                continue
            cleaned.append(token)
        if len(cleaned) >= 2:
            return " ".join(cleaned[1:])
        return None
    if base in ("docker", "podman", "nerdctl", "ctr", "crictl") and args:
        if args[0] in ("run", "exec"):
            positionals = [a for a in args[1:] if not is_flag(a)]
            if len(positionals) >= 2:
                return " ".join(positionals[1:])
        return None
    if base == "kubectl" and "--" in args:
        return " ".join(args[args.index("--") + 1:])
    if base in ("nsenter", "unshare", "chroot") and execution.positionals:
        return " ".join(execution.positionals[1:]) if base == "chroot" else None
    if base == "su":
        payload = inline_payload(execution)
        return payload
    return None


# --------------------------------------------------------------------------
# context
# --------------------------------------------------------------------------
@dataclass
class CommandContext:
    """Everything the feature modules need about a single event."""

    event: Event
    raw: str
    lower: str
    parsed: ParsedCommand
    executions: List[Execution] = field(default_factory=list)
    basenames: List[str] = field(default_factory=list)
    shell_payloads: List[str] = field(default_factory=list)
    script_payloads: List[str] = field(default_factory=list)
    remote_payloads: List[str] = field(default_factory=list)
    all_words: List[str] = field(default_factory=list)
    args: List[str] = field(default_factory=list)
    paths: List[tu.PathRef] = field(default_factory=list)
    urls: List[tu.UrlRef] = field(default_factory=list)
    ipv4s: List[str] = field(default_factory=list)
    ipv6s: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    user_at_hosts: List[Tuple[str, str]] = field(default_factory=list)
    scan_text: str = ""       # raw command plus payloads, for keyword scanning

    # -- convenience predicates -------------------------------------------
    def uses(self, *names: str) -> bool:
        """True if any resolved executable basename matches one of ``names``."""
        wanted = set(names)
        return any(base in wanted for base in self.basenames)

    def executions_of(self, *names: str) -> List[Execution]:
        wanted = set(names)
        return [e for e in self.executions if e.basename in wanted]

    def count_uses(self, *names: str) -> int:
        wanted = set(names)
        return sum(1 for base in self.basenames if base in wanted)

    def any_wrapper(self, *names: str) -> bool:
        wanted = set(names)
        return any(w in wanted for e in self.executions for w in e.wrappers)

    def text_contains(self, *needles: str) -> bool:
        return any(needle in self.scan_text for needle in needles)

    def path_matches(self, *prefixes: str) -> List[tu.PathRef]:
        out = []
        for path in self.paths:
            low = path.lowered
            if any(low == p.rstrip("/") or low.startswith(p) for p in prefixes):
                out.append(path)
        return out

    def basename_matches(self, *names: str) -> List[tu.PathRef]:
        wanted = set(names)
        return [p for p in self.paths if p.basename.lower() in wanted]


def _collect_paths(commands: Sequence[SimpleCommand]) -> List[tu.PathRef]:
    paths: List[tu.PathRef] = []
    seen: Set[str] = set()
    for command in commands:
        for token in command.argv[1:] if command.argv else []:
            candidates: List[str] = []
            if "=" in token and not token.startswith("-"):
                candidates.append(token.split("=", 1)[1])
            elif token.startswith("--") and "=" in token:
                candidates.append(token.split("=", 1)[1])
            else:
                candidates.append(token)
            for candidate in candidates:
                if tu.looks_like_path(candidate) and candidate not in seen:
                    seen.add(candidate)
                    paths.append(tu.make_path_ref(candidate))
        for _op, target in command.redirects:
            if target and target not in seen:
                seen.add(target)
                paths.append(tu.make_path_ref(target, from_redirect=True))
    return paths


def build_context(event: Event) -> CommandContext:
    """Lex and analyse one event into a :class:`CommandContext`."""
    raw = event.command or ""
    parsed = tokenize(raw)

    executions: List[Execution] = []
    shell_payloads: List[str] = []
    script_payloads: List[str] = []
    remote_payloads: List[str] = []

    def absorb(commands: Sequence[SimpleCommand], nested: bool) -> None:
        for command in commands:
            execution = resolve_execution(command, nested=nested)
            if execution is None:
                continue
            executions.append(execution)
            payload = inline_payload(execution)
            if payload:
                if execution.basename in SHELLS:
                    shell_payloads.append(payload)
                else:
                    script_payloads.append(payload)
            remote = remote_payload(execution)
            if remote:
                remote_payloads.append(remote)

    absorb(parsed.commands, nested=False)

    # one level of descent: substitutions, shell -c payloads, remote commands
    nested_texts: List[str] = list(parsed.substitutions) + list(shell_payloads) + list(remote_payloads)
    nested_commands: List[SimpleCommand] = []
    for text in nested_texts:
        if not text or not text.strip():
            continue
        sub = tokenize(text)
        for command in sub.commands:
            command.from_substitution = True
        nested_commands.extend(sub.commands)
    absorb(nested_commands, nested=True)

    all_commands: List[SimpleCommand] = list(parsed.commands) + nested_commands
    all_words = [w for command in all_commands for w in command.argv]
    args = [w for command in all_commands for w in command.argv[1:]]

    scan_text = "\n".join([raw] + script_payloads)
    lower = scan_text.lower()

    urls = tu.extract_urls(scan_text)
    ipv4s = tu.extract_ipv4(scan_text)
    ipv6s = tu.extract_ipv6(scan_text)
    domains = tu.extract_domains(scan_text, [u.host for u in urls])
    ports = tu.extract_ports(scan_text, urls, [c.argv for c in all_commands])
    for execution in executions:
        if execution.basename in PORT_POSITIONAL_TOOLS:
            for token in execution.positionals:
                if token.isdigit() and 0 < int(token) <= 65535:
                    ports.append(int(token))
    user_at_hosts = [(m.group(1), m.group(2)) for m in tu.USER_AT_HOST_RE.finditer(scan_text)]

    return CommandContext(
        event=event,
        raw=raw,
        lower=lower,
        parsed=parsed,
        executions=executions,
        basenames=[e.basename for e in executions],
        shell_payloads=shell_payloads,
        script_payloads=script_payloads,
        remote_payloads=remote_payloads,
        all_words=all_words,
        args=args,
        paths=_collect_paths(all_commands),
        urls=urls,
        ipv4s=ipv4s,
        ipv6s=ipv6s,
        domains=domains,
        ports=sorted(set(ports)),
        user_at_hosts=user_at_hosts,
        scan_text=scan_text,
    )
