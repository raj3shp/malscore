"""Redaction of secret-looking values in echoed command text.

Command lines routinely carry passwords, tokens and keys.  With ``--redact``,
those *values* are replaced before any command is printed, while the option
name and the command shape survive.  Scoring always runs on the original text,
so redaction never changes a score -- only what is shown.
"""

from __future__ import annotations

import re
from typing import List

REDACTED = "<REDACTED>"

#: --password=VALUE, --token VALUE, PGPASSWORD=VALUE, -p VALUE (for known tools)
_KEY_NAMES = (r"pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|auth|"
              r"credential|bearer|session[_-]?key|private[_-]?key|pgpassword|"
              r"mysql_pwd|client[_-]?secret")

PATTERNS: List[re.Pattern] = [
    re.compile(r"(?i)(--?(?:%s)[a-z0-9_-]*\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)" % _KEY_NAMES),
    re.compile(r"(?i)\b([A-Z0-9_]*(?:%s)[A-Z0-9_]*\s*=\s*)(\"[^\"]*\"|'[^']*'|\S+)" % _KEY_NAMES),
    re.compile(r"(?i)(--?(?:password|token|api-?key|secret)\s+)(\"[^\"]*\"|'[^']*'|[^\s-]\S*)"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)(\S+)"),
    re.compile(r"(?i)(\b[a-z0-9._%-]+:)([^@\s/]{3,})(@[a-z0-9.-]+)"),   # user:pass@host
    re.compile(r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END)", re.DOTALL),
]
#: Long, high-entropy looking blobs that are almost certainly key material.
BLOB_RE = re.compile(r"(?<![\w/+=])(?=[A-Za-z0-9+/]*[0-9])(?=[A-Za-z0-9+/]*[A-Z])"
                     r"[A-Za-z0-9+/]{32,}={0,2}(?![\w/+=])")


def redact(text: str) -> str:
    """Return ``text`` with credential-looking values replaced."""
    if not text:
        return text
    redacted = text
    for pattern in PATTERNS:
        if pattern.groups == 3:
            redacted = pattern.sub(lambda m: m.group(1) + REDACTED + m.group(3), redacted)
        else:
            redacted = pattern.sub(lambda m: m.group(1) + REDACTED, redacted)
    return BLOB_RE.sub(REDACTED, redacted)
