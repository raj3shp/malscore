"""Input parsing: raw telemetry records -> :class:`Event` objects.

Different sources (auditd, eBPF/Falco, shell history exports, the synthetic
generator in this repo) name their fields differently and omit most of them.
Parsing therefore works on *aliases* and every field except the command line is
optional.  Nothing here ever executes or interprets a command -- values are
carried as inert strings.
"""

from __future__ import annotations

import datetime as dt
import gzip
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional

# --------------------------------------------------------------------------
# field aliases
# --------------------------------------------------------------------------
COMMAND_KEYS = ("cmdline", "command", "cmd", "command_line", "commandline",
                "proctitle", "exe_args", "args_string")
USER_KEYS = ("user", "username", "user_name", "acct", "auid_name", "subject_user")
TIME_KEYS = ("timestamp", "time", "@timestamp", "ts", "event_time", "start_time",
             "eventTime", "datetime")
HOST_KEYS = ("host", "hostname", "node", "computer", "host_name", "agent_host")
CWD_KEYS = ("cwd", "pwd", "working_directory", "workdir")
PID_KEYS = ("pid", "process_id", "proc_pid")
PPID_KEYS = ("ppid", "parent_pid", "parent_process_id")
PARENT_EXE_KEYS = ("parent_exe", "parent_executable", "parent", "pcomm",
                   "parent_name", "parent_process_name")
PARENT_CMD_KEYS = ("parent_cmdline", "parent_command", "parent_command_line", "pcmdline")
GPARENT_EXE_KEYS = ("grandparent_exe", "grandparent_executable", "grandparent",
                    "gparent_exe", "grandparent_process_name")
GPARENT_CMD_KEYS = ("grandparent_cmdline", "grandparent_command", "gparent_cmdline")
EXE_KEYS = ("exe", "executable", "process_exe", "comm", "process_name")
SESSION_KEYS = ("session_id", "session", "ses", "sid", "audit_session_id")
TTY_KEYS = ("tty", "terminal")
UID_KEYS = ("uid", "user_id", "ruid")
EUID_KEYS = ("euid", "effective_uid")
GID_KEYS = ("gid", "group_id", "rgid")
EGID_KEYS = ("egid", "effective_gid")
DEPTH_KEYS = ("process_depth", "depth", "ancestry_depth")
PARENT_USER_KEYS = ("parent_user", "puser", "parent_username")

_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.(\d{1,9}))?"
    r"\s*(Z|[+-]\d{2}:?\d{2})?$"
)


@dataclass
class Event:
    """One normalized command-execution event.

    Only :attr:`command` is really required; every other attribute may be
    ``None``/empty and the feature extractors degrade gracefully.
    """

    event_id: int
    line_number: int
    command: str = ""
    user: str = ""
    host: str = ""
    timestamp: Optional[dt.datetime] = None
    timestamp_raw: str = ""
    cwd: str = ""
    exe: str = ""
    pid: Optional[int] = None
    ppid: Optional[int] = None
    parent_exe: str = ""
    parent_cmdline: str = ""
    parent_user: str = ""
    grandparent_exe: str = ""
    grandparent_cmdline: str = ""
    process_depth: Optional[int] = None
    session_id: str = ""
    tty: str = ""
    uid: Optional[int] = None
    euid: Optional[int] = None
    gid: Optional[int] = None
    egid: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    parse_warnings: List[str] = field(default_factory=list)


def _first(record: Dict[str, Any], keys: Iterable[str]) -> Any:
    """Return the first present, non-empty value among ``keys``."""
    for key in keys:
        if key in record:
            value = record[key]
            if value is not None and value != "" and value != []:
                return value
    return None


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _as_command(value: Any) -> str:
    """Accept a string command line or an argv list (auditd/eBPF style)."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " ".join(str(part) for part in value)
    return str(value)


def parse_timestamp(value: Any) -> Optional[dt.datetime]:
    """Parse epoch numbers and common ISO 8601 spellings into aware datetimes.

    ``datetime.fromisoformat`` on Python 3.9 rejects a trailing ``Z`` and
    fractional-second variants, so ISO strings are parsed with an explicit
    regular expression instead.  Naive timestamps are assumed to be UTC.
    """
    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value)
        if seconds > 1e12:          # milliseconds
            seconds /= 1000.0
        elif seconds > 1e15:        # microseconds
            seconds /= 1e6
        return _EPOCH + dt.timedelta(seconds=seconds)

    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{9,19}(\.\d+)?", text):
        return parse_timestamp(float(text))

    match = _ISO_RE.match(text)
    if not match:
        return None
    year, month, day, hour, minute, second, frac, offset = match.groups()
    micro = int((frac or "0").ljust(6, "0")[:6])
    if offset in (None, "", "Z", "z"):
        tzinfo = dt.timezone.utc
    else:
        sign = 1 if offset[0] == "+" else -1
        digits = offset[1:].replace(":", "")
        tzinfo = dt.timezone(
            sign * dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
        )
    try:
        return dt.datetime(
            int(year), int(month), int(day), int(hour), int(minute),
            int(second or 0), micro, tzinfo=tzinfo,
        )
    except ValueError:
        return None


def event_from_record(record: Dict[str, Any], event_id: int, line_number: int) -> Event:
    """Build an :class:`Event` from an arbitrary telemetry dictionary."""
    known: set = set()

    def take(keys: Iterable[str]) -> Any:
        value = _first(record, keys)
        known.update(keys)
        return value

    command = _as_command(take(COMMAND_KEYS))
    user = take(USER_KEYS)
    raw_ts = take(TIME_KEYS)
    event = Event(
        event_id=event_id,
        line_number=line_number,
        command=command,
        user=str(user) if user is not None else "",
        host=str(take(HOST_KEYS) or ""),
        timestamp=parse_timestamp(raw_ts),
        timestamp_raw="" if raw_ts is None else str(raw_ts),
        cwd=str(take(CWD_KEYS) or ""),
        exe=str(take(EXE_KEYS) or ""),
        pid=_as_int(take(PID_KEYS)),
        ppid=_as_int(take(PPID_KEYS)),
        parent_exe=str(take(PARENT_EXE_KEYS) or ""),
        parent_cmdline=_as_command(take(PARENT_CMD_KEYS)),
        parent_user=str(take(PARENT_USER_KEYS) or ""),
        grandparent_exe=str(take(GPARENT_EXE_KEYS) or ""),
        grandparent_cmdline=_as_command(take(GPARENT_CMD_KEYS)),
        process_depth=_as_int(take(DEPTH_KEYS)),
        session_id=str(take(SESSION_KEYS) or ""),
        tty=str(take(TTY_KEYS) or ""),
        uid=_as_int(take(UID_KEYS)),
        euid=_as_int(take(EUID_KEYS)),
        gid=_as_int(take(GID_KEYS)),
        egid=_as_int(take(EGID_KEYS)),
    )
    event.extra = {k: v for k, v in record.items() if k not in known}
    if not command:
        event.parse_warnings.append("missing command line")
    if raw_ts and event.timestamp is None:
        event.parse_warnings.append("unparsable timestamp: %r" % (raw_ts,))
    return event


def _open_text(path: str) -> io.TextIOBase:
    if path == "-":
        import sys
        return sys.stdin
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def iter_events(
    path: str,
    strict: bool = False,
    max_events: Optional[int] = None,
) -> Iterator[Event]:
    """Yield :class:`Event` objects from a JSONL (or JSON array) file.

    JSON Lines is the primary format.  A whole-file JSON array of objects is
    also accepted because that is what many one-off exports look like; in that
    case ``line_number`` is the array index.

    Malformed lines are skipped (or raise when ``strict``), so a single bad
    record cannot abort a long ingest.
    """
    handle = _open_text(path)
    try:
        first = handle.read(1)
        while first and first.isspace():
            first = handle.read(1)
        rest = handle.read()
        text = (first or "") + rest
    finally:
        if handle is not None and path != "-":
            handle.close()

    event_id = 0
    if first == "[":                                   # JSON array
        try:
            records = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("input is not valid JSON: %s" % exc) from exc
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            yield event_from_record(record, event_id, index)
            event_id += 1
            if max_events is not None and event_id >= max_events:
                return
        return

    for index, line in enumerate(text.splitlines(), start=1):    # JSON Lines
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            if strict:
                raise ValueError("line %d is not valid JSON" % index)
            continue
        if not isinstance(record, dict):
            continue
        yield event_from_record(record, event_id, index)
        event_id += 1
        if max_events is not None and event_id >= max_events:
            return


def read_events(path: str, strict: bool = False,
                max_events: Optional[int] = None) -> List[Event]:
    """Eager version of :func:`iter_events`."""
    return list(iter_events(path, strict=strict, max_events=max_events))


def sort_events(events: List[Event]) -> List[Event]:
    """Chronological sort, stable on input order for events without timestamps.

    Behavioral baselines must never see the future, so ordering matters.  Events
    with no timestamp keep their relative input position by sorting on the
    (timestamp, line_number) pair with a sentinel for missing times.
    """
    def key(event: Event):
        if event.timestamp is None:
            return (1, 0.0, event.line_number)
        return (0, event.timestamp.timestamp(), event.line_number)

    return sorted(events, key=key)
