"""Command normalization (section 23 of the spec).

Normalization turns a concrete command line into a *template* so that
semantically equivalent commands collapse onto one key::

    curl https://example.com/a.sh   ->  curl <URL>
    curl https://example.com/b.sh   ->  curl <URL>
    ssh deploy@server1              ->  ssh <USER>@<HOST>
    kill -9 28841                   ->  kill -9 <NUM>

The template is rebuilt from the lexer's tokens rather than by running regular
expressions over the raw string, so operators keep their structural meaning and
quoting noise disappears.  The raw command is never destroyed by this step --
see ``--no-raw-command`` / ``--redact-secrets`` for that.
"""

from __future__ import annotations

import hashlib
import re
from typing import List, Optional

from .context import CommandContext, is_flag
from .lexer import Token
from .textutil import (
    BASE64_RE,
    DOMAIN_RE,
    UUID_RE,
    extract_ipv4,
    extract_ipv6,
    looks_like_filename,
)

PLACEHOLDERS = ("<URL>", "<IPV4>", "<IPV6>", "<HOST>", "<USER>", "<UUID>", "<HEX>",
                "<B64>", "<DATE>", "<TIME>", "<NUM>", "<PID>", "<HOME>")

URL_TOKEN_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://")
USER_AT_HOST_TOKEN_RE = re.compile(r"^([A-Za-z0-9._\-]{1,32})@([A-Za-z0-9._\-]+)(:.*)?$")
ISO_DATE_RE = re.compile(r"\b\d{4}[-/]\d{2}[-/]\d{2}\b")
COMPACT_DATE_RE = re.compile(r"(?<!\d)(?:20|19)\d{6}(?!\d)")
TIME_RE = re.compile(r"\b\d{2}:\d{2}(?::\d{2})?\b")
HEX_TOKEN_RE = re.compile(r"(?<![\w])(?:0x)?[A-Fa-f0-9]{16,}(?![\w])")
NUMBER_RUN_RE = re.compile(r"\d{2,}")
HOME_RE = re.compile(r"^(?:/home/[^/]+|/root|\$HOME|\$\{HOME\}|~)")
PROC_PID_RE = re.compile(r"^/proc/\d+")

#: Tools whose first positional argument is a remote host.
HOST_ARG_TOOLS = frozenset({"ssh", "sshpass", "scp", "sftp", "telnet", "rsh", "mosh",
                            "ping", "ping6", "traceroute", "mtr", "nc", "ncat", "netcat",
                            "dig", "nslookup", "host", "nmap", "rsync"})


def _normalize_inner(text: str) -> str:
    """Replace date/number/hex runs *inside* a token."""
    text = ISO_DATE_RE.sub("<DATE>", text)
    text = COMPACT_DATE_RE.sub("<DATE>", text)
    text = TIME_RE.sub("<TIME>", text)
    text = UUID_RE.sub("<UUID>", text)
    text = HEX_TOKEN_RE.sub("<HEX>", text)
    text = NUMBER_RUN_RE.sub("<NUM>", text)
    return text


def normalize_token(value: str, host_expected: bool = False) -> str:
    """Normalize a single argument value into its template form."""
    if not value:
        return value
    if is_flag(value):
        # Flags are part of the command's shape, so they survive normalization
        # verbatim ("-9", "-la"); only an attached value is normalized.
        if "=" in value:
            flag, _sep, tail = value.partition("=")
            return "%s=%s" % (flag, normalize_token(tail))
        return value
    if URL_TOKEN_RE.match(value):
        return "<URL>"
    match = USER_AT_HOST_TOKEN_RE.match(value)
    if match and not looks_like_filename(value):
        tail = match.group(3) or ""
        return "<USER>@<HOST>" + (_normalize_inner(tail) if tail else "")
    if extract_ipv4(value) and value.strip("[]").count(".") == 3 and value.replace(".", "").isdigit():
        return "<IPV4>"
    if extract_ipv6(value) and ":" in value and "/" not in value:
        return "<IPV6>"
    if UUID_RE.fullmatch(value):
        return "<UUID>"
    if value.lstrip("+-").isdigit():
        return "<NUM>"
    if HEX_TOKEN_RE.fullmatch(value):
        return "<HEX>"
    if len(value) >= 20 and BASE64_RE.fullmatch(value):
        return "<B64>"

    if PROC_PID_RE.match(value):
        return "/proc/<PID>" + _normalize_inner(value.split("/", 3)[3] if value.count("/") > 2 else "")
    if HOME_RE.match(value):
        rest = HOME_RE.sub("", value, count=1)
        return "~" + _normalize_inner(rest)
    if "/" in value:
        return _normalize_inner(value)
    if host_expected and value and not value.startswith("-"):
        return "<HOST>"
    if DOMAIN_RE.fullmatch(value) and not looks_like_filename(value):
        return "<HOST>"
    return _normalize_inner(value)


def normalize_command(ctx: CommandContext, max_length: int = 400) -> str:
    """Build the normalized template for a whole command line."""
    if not ctx.raw.strip():
        return ""
    parts: List[str] = []
    head_pending = True
    host_tool: Optional[str] = None
    host_consumed = False

    for token in ctx.parsed.tokens:
        if token.kind == "op":
            parts.append(token.text if token.text != "\n" else ";")
            head_pending = True
            host_tool = None
            host_consumed = False
            continue
        value = token.value
        if head_pending:
            base = value.rsplit("/", 1)[-1].lower()
            head_pending = False
            if base in HOST_ARG_TOOLS:
                host_tool = base
            parts.append(_normalize_inner(value) if "/" in value else value)
            continue
        expect_host = bool(host_tool) and not host_consumed and not is_flag(value)
        normalized = normalize_token(value, host_expected=expect_host)
        if expect_host and normalized == "<HOST>":
            host_consumed = True
        parts.append(normalized)

    template = " ".join(part for part in parts if part)
    template = re.sub(r"\s+", " ", template).strip()
    if len(template) > max_length:
        template = template[:max_length] + "..."
    return template


def command_fingerprint(normalized: str) -> str:
    """Short stable hash of a normalized command, handy as a grouping key."""
    return hashlib.sha1(normalized.encode("utf-8", "replace")).hexdigest()[:12]
