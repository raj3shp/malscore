"""Output writers: JSONL, CSV and (optionally) a pandas DataFrame."""

from __future__ import annotations

import csv
import json
import sys
from typing import Dict, Iterable, List, Optional, Sequence

from .schema import FeatureRegistry


def write_jsonl(records: Iterable[Dict[str, object]], path: str) -> int:
    """Write one JSON object per line.  ``-`` writes to stdout."""
    handle = sys.stdout if path == "-" else open(path, "w", encoding="utf-8")
    count = 0
    try:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, default=str))
            handle.write("\n")
            count += 1
    finally:
        if handle is not sys.stdout:
            handle.close()
    return count


_CONTROL_CHARS = {c: "\\x%02x" % c for c in list(range(0, 9)) + list(range(11, 32)) + [127]}


def csv_safe(value: object) -> object:
    """Escape control characters so the CSV stays parseable.

    Command lines really do contain NUL and other control bytes; ``csv`` refuses
    to read them back. The escaped form keeps the row readable, and the
    ``has_null_byte`` / ``control_char_count`` features already record that the
    original contained them.
    """
    if isinstance(value, str) and any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return value.translate(_CONTROL_CHARS)
    return value


def write_csv(
    records: Sequence[Dict[str, object]],
    path: str,
    columns: Optional[Sequence[str]] = None,
) -> int:
    """Write records as CSV with a stable column order.

    Uses the standard library so the tool works without pandas; when pandas is
    installed :func:`to_dataframe` gives the same data as a DataFrame.
    """
    records = list(records)
    if not records:
        fieldnames: List[str] = list(columns or [])
    else:
        fieldnames = list(columns or records[0].keys())
    handle = sys.stdout if path == "-" else open(path, "w", encoding="utf-8", newline="")
    try:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            writer.writerow({key: csv_safe(record.get(key, "")) for key in fieldnames})
    finally:
        if handle is not sys.stdout:
            handle.close()
    return len(records)


def to_dataframe(records: Sequence[Dict[str, object]], registry: Optional[FeatureRegistry] = None):
    """Return a pandas DataFrame of the records (pandas required).

    Column order follows the registry when one is given, which keeps feature
    matrices aligned between runs.
    """
    try:
        import pandas as pd
    except ImportError as exc:                              # pragma: no cover
        raise ImportError(
            "pandas is not installed; use write_jsonl/write_csv, or "
            "'pip install pandas' to get DataFrame output."
        ) from exc

    frame = pd.DataFrame(list(records))
    if registry is not None:
        ordered = [name for name in registry.names() if name in frame.columns]
        remainder = [c for c in frame.columns if c not in ordered]
        frame = frame[ordered + remainder]
    return frame


def write_feature_catalogue(registry: FeatureRegistry, path: str, fmt: str = "markdown") -> int:
    """Dump the feature catalogue as markdown or JSON (used to build the README)."""
    handle = sys.stdout if path == "-" else open(path, "w", encoding="utf-8")
    try:
        if fmt == "json":
            json.dump(
                [
                    {"name": s.name, "dtype": s.dtype, "group": s.group,
                     "kind": s.kind, "description": s.description}
                    for s in registry.specs()
                ],
                handle, indent=2,
            )
            handle.write("\n")
        else:
            grouped = registry.by_group()
            for group in sorted(grouped):
                specs = grouped[group]
                handle.write("\n### `%s` (%d features)\n\n" % (group, len(specs)))
                handle.write("| feature | type | kind | description |\n")
                handle.write("| --- | --- | --- | --- |\n")
                for spec in specs:
                    handle.write("| `%s` | %s | %s | %s |\n"
                                 % (spec.name, spec.dtype, spec.kind, spec.description))
    finally:
        if handle is not sys.stdout:
            handle.close()
    return len(registry)
