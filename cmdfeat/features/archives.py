"""Archive and compression features (section 18 of the spec).

Archiving is interesting mostly as the first half of a staging-then-transfer
pattern, so the features record direction (create vs extract), format and
whether the archive is written to a temporary location or streamed to stdout.
"""

from __future__ import annotations

from typing import Dict

from ..context import CommandContext
from ..schema import F, KIND_INDICATOR, KIND_STRUCTURAL

ARCHIVE_TOOLS = ("tar", "gzip", "gunzip", "zip", "unzip", "7z", "7za", "xz", "unxz",
                 "bzip2", "bunzip2", "zstd", "unzstd", "compress", "cpio", "ar", "rar", "unrar")
ARCHIVE_EXTENSIONS = {
    "tar": "tar", "tgz": "tar.gz", "gz": "gzip", "bz2": "bzip2", "xz": "xz", "zst": "zstd",
    "zip": "zip", "7z": "7z", "rar": "rar", "z": "compress", "lz4": "lz4", "cpio": "cpio",
}
CREATE_FLAGS = frozenset({"-c", "-cf", "-czf", "-cvf", "-czvf", "-cjf", "-cJf", "--create", "a"})
EXTRACT_FLAGS = frozenset({"-x", "-xf", "-xzf", "-xvf", "-xzvf", "-xjf", "--extract", "e", "x"})

FEATURES = [
    F("archive_tool_used", "bool", "archive", KIND_STRUCTURAL, "An archiving/compression tool is used."),
    F("archive_tool_name", "str", "archive", KIND_STRUCTURAL, "First archive tool basename.", ""),
    F("archive_creation", "bool", "archive", KIND_INDICATOR, "An archive is created or data compressed."),
    F("archive_extraction", "bool", "archive", KIND_INDICATOR, "An archive is extracted or decompressed."),
    F("archive_format", "str", "archive", KIND_STRUCTURAL, "Archive format inferred from the tool or file extension.", ""),
    F("archive_path", "str", "archive", KIND_STRUCTURAL, "First archive path referenced.", ""),
    F("archive_to_tmp", "bool", "archive", KIND_INDICATOR, "The archive path is in a temporary directory."),
    F("archive_to_stdout", "bool", "archive", KIND_INDICATOR, "The archive is streamed to stdout (tar -cf -, -O)."),
    F("archive_piped", "bool", "archive", KIND_INDICATOR, "The archive tool is part of a pipeline."),
    F("archive_size_bytes", "int", "archive", KIND_STRUCTURAL, "Archive size when the telemetry provides one, else -1.", -1),
    F("archive_excludes_used", "bool", "archive", KIND_STRUCTURAL, "Exclusion patterns are used."),
]


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute archive features for one event."""
    executions = ctx.executions_of(*ARCHIVE_TOOLS)
    first = executions[0] if executions else None
    args = [a for e in executions for a in e.args]
    flags = {a for a in args if a.startswith("-")} | {a for a in args[:1]}

    archive_paths = [p for p in ctx.paths if p.extension in ARCHIVE_EXTENSIONS
                     or p.raw.endswith((".tar.gz", ".tar.bz2", ".tar.xz"))]
    fmt = ""
    if archive_paths:
        fmt = ARCHIVE_EXTENSIONS.get(archive_paths[0].extension, archive_paths[0].extension)
    elif first:
        fmt = {"gzip": "gzip", "gunzip": "gzip", "bzip2": "bzip2", "xz": "xz",
               "zip": "zip", "unzip": "zip", "7z": "7z", "tar": "tar"}.get(first.basename, first.basename)

    creating = bool(flags & CREATE_FLAGS) or ctx.uses("gzip", "bzip2", "xz", "zstd", "zip", "compress")
    extracting = bool(flags & EXTRACT_FLAGS) or ctx.uses("gunzip", "bunzip2", "unxz", "unzip",
                                                         "unzstd", "unrar")
    if first and first.basename == "tar":
        joined = " ".join(args)
        creating = creating or any(f in joined for f in ("-c", "c"))  and "-x" not in joined
        extracting = extracting or "-x" in joined

    size = ctx.event.extra.get("archive_size") or ctx.event.extra.get("file_size")
    try:
        size_value = int(size) if size is not None else -1
    except (TypeError, ValueError):
        size_value = -1

    return {
        "archive_tool_used": int(bool(executions)),
        "archive_tool_name": first.basename if first else "",
        "archive_creation": int(bool(executions) and bool(creating)),
        "archive_extraction": int(bool(executions) and bool(extracting)),
        "archive_format": fmt,
        "archive_path": archive_paths[0].raw if archive_paths else "",
        "archive_to_tmp": int(any(p.lowered.startswith(("/tmp", "/var/tmp", "/dev/shm"))
                                  for p in archive_paths)),
        "archive_to_stdout": int(bool(executions) and ("-" in args or "-O" in args or "-c" in args)),
        "archive_piped": int(any(e.command is not None and e.command.pipeline_length > 1
                                 for e in executions)),
        "archive_size_bytes": size_value,
        "archive_excludes_used": int(any(a.startswith("--exclude") for a in args)),
    }
