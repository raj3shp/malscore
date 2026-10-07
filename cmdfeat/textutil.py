"""Pure text helpers: entropy, character ratios and indicator extraction.

Everything here is read-only string analysis.  No command is ever executed,
expanded or resolved.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit, parse_qsl

URL_RE = re.compile(
    r"(?i)\b(?P<scheme>[a-z][a-z0-9+.\-]{1,15})://(?P<rest>[^\s'\"`<>|;)\\]+)"
)
IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")
IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:])((?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?:%\w+)?)(?![\w:])")
DOMAIN_RE = re.compile(
    r"(?<![\w.@/-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})(?![\w-])"
)
USER_AT_HOST_RE = re.compile(
    r"(?<![\w.@-])([a-zA-Z0-9._\-]{1,32})@((?:[a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+)(?![\w.-])"
)
HEX_STRING_RE = re.compile(r"(?<![\w])(?:0x)?[A-Fa-f0-9]{16,}(?![\w])")
HEX_ESCAPE_RE = re.compile(r"\\x[0-9A-Fa-f]{2}")
OCTAL_ESCAPE_RE = re.compile(r"\\[0-7]{3}")
URL_ENCODING_RE = re.compile(r"%[0-9A-Fa-f]{2}")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")
UUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
SED_EXPR_RE = re.compile(r"^[sy]([/|,#!:])(?:[^\1]|\\.)*\1")

#: Extensions that would otherwise be mistaken for domain names (``setup.py``).
FILE_LIKE_SUFFIXES = frozenset("""
py sh bash zsh js mjs cjs ts json yaml yml txt log csv tsv gz bz2 xz zip tar tgz md
conf cfg ini service socket timer target sql jar war xml html htm css png jpg jpeg gif
svg pdf deb rpm so a o bin dat db sqlite key pem crt cer p12 pfx pub lock env sample
properties toml rs go java c h cpp hpp rb pl php tpl j2 template bak old orig swp tmp
""".split())

#: Ports that are unremarkable in a corporate Linux estate.
COMMON_PORTS = frozenset({
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 135, 137, 138, 139, 143,
    161, 162, 389, 443, 445, 464, 465, 514, 587, 631, 636, 873, 989, 990, 993, 995,
    1433, 1521, 2049, 2181, 2379, 3000, 3128, 3260, 3306, 3389, 4369, 5000, 5432,
    5601, 5672, 6379, 8000, 8080, 8081, 8088, 8443, 8500, 9000, 9090, 9092, 9093,
    9100, 9200, 9300, 11211, 15672, 27017,
})

B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def shannon_entropy(text: str) -> float:
    """Shannon entropy (bits/char) of ``text``; 0.0 for empty input."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def char_ratios(text: str) -> Dict[str, float]:
    """Proportions of character classes, used as obfuscation *characteristics*."""
    if not text:
        return {"alnum": 0.0, "punct": 0.0, "digit": 0.0, "upper": 0.0,
                "space": 0.0, "escape": 0.0, "base64": 0.0, "nonprintable": 0.0}
    length = len(text)
    alnum = sum(ch.isalnum() for ch in text)
    digit = sum(ch.isdigit() for ch in text)
    upper = sum(ch.isupper() for ch in text)
    space = sum(ch.isspace() for ch in text)
    escape = text.count("\\")
    punct = sum((not ch.isalnum()) and (not ch.isspace()) for ch in text)
    b64 = sum(ch in B64_CHARS for ch in text)
    nonprint = sum((not ch.isprintable()) and ch not in "\t\n\r" for ch in text)
    return {
        "alnum": alnum / length, "punct": punct / length, "digit": digit / length,
        "upper": upper / length, "space": space / length, "escape": escape / length,
        "base64": b64 / length, "nonprintable": nonprint / length,
    }


# --------------------------------------------------------------------------
# network indicators
# --------------------------------------------------------------------------
@dataclass
class UrlRef:
    """A URL found in a command line, decomposed into parts."""

    raw: str
    scheme: str = ""
    host: str = ""
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    host_is_ip: bool = False
    query_param_count: int = 0

    @property
    def path_depth(self) -> int:
        return len([p for p in self.path.split("/") if p])


def _strip_trailing_punct(text: str) -> str:
    return text.rstrip(".,;:!)\"'")


def extract_urls(text: str) -> List[UrlRef]:
    """Find URL-like substrings and split them into components."""
    urls: List[UrlRef] = []
    for match in URL_RE.finditer(text):
        raw = _strip_trailing_punct(match.group(0))
        try:
            parts = urlsplit(raw)
        except ValueError:
            continue
        host = parts.hostname or ""
        port: Optional[int] = None
        try:
            port = parts.port
        except ValueError:
            port = None
        host_is_ip = False
        if host:
            try:
                ipaddress.ip_address(host.strip("[]"))
                host_is_ip = True
            except ValueError:
                host_is_ip = False
        urls.append(
            UrlRef(
                raw=raw, scheme=(parts.scheme or "").lower(), host=host, port=port,
                path=parts.path or "", query=parts.query or "",
                fragment=parts.fragment or "", host_is_ip=host_is_ip,
                query_param_count=len(parse_qsl(parts.query)) if parts.query else 0,
            )
        )
    return urls


def extract_ipv4(text: str) -> List[str]:
    found: List[str] = []
    for match in IPV4_RE.finditer(text):
        candidate = match.group(1)
        try:
            ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        found.append(candidate)
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


def classify_ip(address: str) -> Dict[str, bool]:
    """Classify an IP literal (private / loopback / link-local / multicast)."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return {}
    return {
        "private": bool(ip.is_private and not ip.is_loopback and not ip.is_link_local),
        "loopback": bool(ip.is_loopback),
        "link_local": bool(ip.is_link_local),
        "multicast": bool(ip.is_multicast),
        "public": bool(ip.is_global),
    }


def looks_like_filename(candidate: str) -> bool:
    """True when a dotted token is more likely a filename than a domain."""
    suffix = candidate.rsplit(".", 1)[-1].lower()
    return suffix in FILE_LIKE_SUFFIXES


def extract_domains(text: str, url_hosts: Sequence[str] = ()) -> List[str]:
    """Find hostname-like tokens, excluding obvious filenames and IPs."""
    domains: List[str] = []
    for host in url_hosts:
        if host and not _is_ip(host):
            domains.append(host.lower())
    for match in DOMAIN_RE.finditer(text):
        candidate = match.group(1)
        if _is_ip(candidate) or looks_like_filename(candidate):
            continue
        lowered = candidate.lower()
        if lowered not in domains:
            domains.append(lowered)
    return domains


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def domain_suffix(domain: str) -> str:
    """Last label of a domain (``example.co.uk`` -> ``uk``)."""
    return domain.rsplit(".", 1)[-1] if "." in domain else ""


def extract_ports(text: str, urls: Sequence[UrlRef], argv_lists: Sequence[Sequence[str]]) -> List[int]:
    """Ports from URLs, ``host:port`` pairs and ``-p``/``--port`` options."""
    ports: List[int] = [u.port for u in urls if u.port]
    for match in re.finditer(r"(?<=[\w\].]):(\d{1,5})(?![\w.])", text):
        value = int(match.group(1))
        if 0 < value <= 65535:
            ports.append(value)
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
@dataclass
class PathRef:
    """A filesystem path found in a command line."""

    raw: str
    absolute: bool = False
    depth: int = 0
    basename: str = ""
    extension: str = ""
    hidden: bool = False
    from_redirect: bool = False

    @property
    def lowered(self) -> str:
        return self.raw.lower()


def looks_like_path(token: str) -> bool:
    """Heuristic: does this argument denote a filesystem path?

    Deliberately conservative -- ``sed`` expressions, URLs, regexes and option
    values with slashes are common sources of false positives, so they are
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
    if token.startswith(("/", "./", "../", "~")):
        return True
    if "/" in token:
        # relative path such as src/main/App.java, but not a regex like [0-9]{2}/
        return not any(ch in token for ch in "*?[]{}()|^$") or token.count("/") >= 1
    return False


def make_path_ref(token: str, from_redirect: bool = False) -> PathRef:
    cleaned = token.rstrip(",;")
    basename = cleaned.rsplit("/", 1)[-1]
    extension = ""
    if "." in basename[1:]:
        extension = basename.rsplit(".", 1)[-1].lower()
    return PathRef(
        raw=cleaned,
        absolute=cleaned.startswith("/"),
        depth=len([p for p in cleaned.split("/") if p]),
        basename=basename,
        extension=extension,
        hidden=basename.startswith(".") and basename not in (".", ".."),
        from_redirect=from_redirect,
    )


def longest_token(tokens: Sequence[str]) -> str:
    return max(tokens, key=len) if tokens else ""


def count_matches(pattern: re.Pattern, text: str) -> int:
    return len(pattern.findall(text)) if text else 0
