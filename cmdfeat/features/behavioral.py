"""User and host behavioural baselines (sections 20-21 of the spec).

**No future leakage.** Events are processed in timestamp order; every feature
for event *N* is computed from the state built by events *0..N-1*, and only
afterwards is the store updated with event *N*.  That ordering is what makes
these features usable for training an anomaly model without the model quietly
learning from its own answers.

Rarity is defined as ``1 - (prior occurrences / prior total)`` for that user, so
a value the user has never produced scores 1.0 and their most habitual value
tends toward 0.0.  ``*_history_size`` tells you how much evidence is behind a
rarity value -- a rarity of 1.0 after three events means very little.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

from ..schema import F, KIND_BEHAVIORAL

UNKNOWN = "<unknown>"
FIVE_MINUTES = 300.0
ONE_HOUR = 3600.0
#: Minimum history before "unusual hour" is allowed to fire at all.
UNUSUAL_HOUR_MIN_HISTORY = 50
UNUSUAL_HOUR_MAX_FREQUENCY = 0.02

FEATURES = [
    F("user_history_size", "int", "behavioral", KIND_BEHAVIORAL, "Events seen for this user before this one."),
    F("user_event_index", "int", "behavioral", KIND_BEHAVIORAL, "Zero-based position of this event within the user's history."),
    F("session_event_index", "int", "behavioral", KIND_BEHAVIORAL, "Zero-based position within this session, -1 without a session id.", -1),
    F("command_seen_before", "bool", "behavioral", KIND_BEHAVIORAL, "This user has run this normalized command before."),
    F("first_seen_by_user", "bool", "behavioral", KIND_BEHAVIORAL, "First time this user runs this normalized command."),
    F("executable_seen_before", "bool", "behavioral", KIND_BEHAVIORAL, "This user has run this executable before."),
    F("new_executable_for_user", "bool", "behavioral", KIND_BEHAVIORAL, "First time this user runs this executable."),
    F("domain_seen_before", "bool", "behavioral", KIND_BEHAVIORAL, "This user has contacted this domain before."),
    F("new_domain_for_user", "bool", "behavioral", KIND_BEHAVIORAL, "First time this user references this domain."),
    F("parent_seen_before", "bool", "behavioral", KIND_BEHAVIORAL, "This user has had this parent process before."),
    F("unusual_parent_for_user", "bool", "behavioral", KIND_BEHAVIORAL, "Parent process is new for this user (needs ancestry data)."),
    F("cwd_seen_before", "bool", "behavioral", KIND_BEHAVIORAL, "This user has worked in this directory before."),
    F("host_seen_before", "bool", "behavioral", KIND_BEHAVIORAL, "This user has used this host before."),
    F("first_seen_on_host", "bool", "behavioral", KIND_BEHAVIORAL, "First time this normalized command appears on this host."),
    F("command_count_for_user", "int", "behavioral", KIND_BEHAVIORAL, "Times this user ran this normalized command before."),
    F("executable_count_for_user", "int", "behavioral", KIND_BEHAVIORAL, "Times this user ran this executable before."),
    F("domain_count_for_user", "int", "behavioral", KIND_BEHAVIORAL, "Times this user referenced this domain before."),
    F("host_command_count", "int", "behavioral", KIND_BEHAVIORAL, "Times this normalized command was seen on this host before."),
    F("user_distinct_command_count", "int", "behavioral", KIND_BEHAVIORAL, "Distinct normalized commands in this user's history."),
    F("user_distinct_executable_count", "int", "behavioral", KIND_BEHAVIORAL, "Distinct executables in this user's history."),
    F("command_rarity", "float", "behavioral", KIND_BEHAVIORAL, "1 - frequency of this normalized command for this user.", 1.0),
    F("executable_rarity", "float", "behavioral", KIND_BEHAVIORAL, "1 - frequency of this executable for this user.", 1.0),
    F("domain_rarity", "float", "behavioral", KIND_BEHAVIORAL, "1 - frequency of this domain for this user.", 1.0),
    F("parent_rarity", "float", "behavioral", KIND_BEHAVIORAL, "1 - frequency of this parent process for this user.", 1.0),
    F("cwd_rarity", "float", "behavioral", KIND_BEHAVIORAL, "1 - frequency of this working directory for this user.", 1.0),
    F("host_rarity", "float", "behavioral", KIND_BEHAVIORAL, "1 - frequency of this host for this user.", 1.0),
    F("arg_pattern_rarity", "float", "behavioral", KIND_BEHAVIORAL, "1 - frequency of this executable+flag signature for this user.", 1.0),
    F("global_command_rarity", "float", "behavioral", KIND_BEHAVIORAL, "1 - frequency of this normalized command across all users.", 1.0),
    F("global_executable_rarity", "float", "behavioral", KIND_BEHAVIORAL, "1 - frequency of this executable across all users.", 1.0),
    F("user_host_pair_seen_before", "bool", "behavioral", KIND_BEHAVIORAL, "This user+host pair has occurred before."),
    F("user_host_pair_count", "int", "behavioral", KIND_BEHAVIORAL, "Prior events for this user+host pair."),
    F("user_executable_pair_count", "int", "behavioral", KIND_BEHAVIORAL, "Prior events for this user+executable pair."),
    F("time_since_previous_command", "float", "behavioral", KIND_BEHAVIORAL, "Seconds since this user's previous command, -1 when unknown.", -1.0),
    F("seconds_since_same_command", "float", "behavioral", KIND_BEHAVIORAL, "Seconds since this user last ran this normalized command, -1 when never.", -1.0),
    F("commands_in_previous_5_minutes", "int", "behavioral", KIND_BEHAVIORAL, "This user's commands in the preceding 5 minutes."),
    F("commands_in_previous_hour", "int", "behavioral", KIND_BEHAVIORAL, "This user's commands in the preceding hour."),
    F("user_hour_frequency", "float", "behavioral", KIND_BEHAVIORAL, "Share of this user's history that fell in this hour of day.", 0.0),
    F("user_day_frequency", "float", "behavioral", KIND_BEHAVIORAL, "Share of this user's history that fell on this weekday.", 0.0),
    F("usual_hour", "int", "behavioral", KIND_BEHAVIORAL, "This user's most frequent hour so far, -1 when unknown.", -1),
    F("hour_deviation", "int", "behavioral", KIND_BEHAVIORAL, "Circular distance in hours from the user's usual hour, -1 when unknown.", -1),
    F("unusual_hour", "bool", "behavioral", KIND_BEHAVIORAL, "Hour is rare for this user (needs >=50 prior events)."),
]


def _rarity(count: int, total: int) -> float:
    """1 - frequency, with an empty history treated as maximally rare."""
    if total <= 0:
        return 1.0
    return round(1.0 - (count / total), 6)


class BaselineStore:
    """Per-user / per-host frequency tables built incrementally.

    The store is intentionally simple (counters and deques) so that it can be
    checkpointed, or swapped for a database-backed implementation, without
    touching the extractors.
    """

    def __init__(self) -> None:
        self.user_total: Counter = Counter()
        self.user_command: Dict[str, Counter] = defaultdict(Counter)
        self.user_executable: Dict[str, Counter] = defaultdict(Counter)
        self.user_domain: Dict[str, Counter] = defaultdict(Counter)
        self.user_parent: Dict[str, Counter] = defaultdict(Counter)
        self.user_cwd: Dict[str, Counter] = defaultdict(Counter)
        self.user_host: Dict[str, Counter] = defaultdict(Counter)
        self.user_hour: Dict[str, Counter] = defaultdict(Counter)
        self.user_dow: Dict[str, Counter] = defaultdict(Counter)
        self.user_arg_pattern: Dict[str, Counter] = defaultdict(Counter)
        self.user_last_timestamp: Dict[str, float] = {}
        self.user_command_last_seen: Dict[Tuple[str, str], float] = {}
        self.user_recent: Dict[str, Deque[float]] = defaultdict(deque)
        self.host_total: Counter = Counter()
        self.host_command: Dict[str, Counter] = defaultdict(Counter)
        self.host_executable: Dict[str, Counter] = defaultdict(Counter)
        self.global_command: Counter = Counter()
        self.global_executable: Counter = Counter()
        self.global_total: int = 0
        self.session_counts: Counter = Counter()

    # -- feature computation ------------------------------------------------
    def features(
        self,
        user: str,
        host: str,
        normalized_command: str,
        executable: str,
        domain: str,
        parent: str,
        cwd: str,
        arg_pattern: str,
        session_id: str,
        timestamp: Optional[dt.datetime],
    ) -> Dict[str, object]:
        """Behavioural features for one event, using history *before* it."""
        user = user or UNKNOWN
        host = host or UNKNOWN
        total = self.user_total[user]

        command_count = self.user_command[user][normalized_command]
        executable_count = self.user_executable[user][executable] if executable else 0
        domain_count = self.user_domain[user][domain] if domain else 0
        parent_count = self.user_parent[user][parent] if parent else 0
        cwd_count = self.user_cwd[user][cwd] if cwd else 0
        host_count = self.user_host[user][host]
        pattern_count = self.user_arg_pattern[user][arg_pattern] if arg_pattern else 0

        epoch = timestamp.timestamp() if timestamp is not None else None
        since_previous = -1.0
        if epoch is not None and user in self.user_last_timestamp:
            since_previous = round(epoch - self.user_last_timestamp[user], 3)
        since_same = -1.0
        key = (user, normalized_command)
        if epoch is not None and key in self.user_command_last_seen:
            since_same = round(epoch - self.user_command_last_seen[key], 3)

        in_5m = in_1h = 0
        if epoch is not None:
            recent = self.user_recent[user]
            in_1h = sum(1 for t in recent if epoch - t <= ONE_HOUR)
            in_5m = sum(1 for t in recent if epoch - t <= FIVE_MINUTES)

        hour = timestamp.hour if timestamp is not None else -1
        dow = timestamp.weekday() if timestamp is not None else -1
        hour_counts = self.user_hour[user]
        hour_frequency = (hour_counts[hour] / total) if (total and hour >= 0) else 0.0
        day_frequency = (self.user_dow[user][dow] / total) if (total and dow >= 0) else 0.0
        usual_hour = hour_counts.most_common(1)[0][0] if hour_counts else -1
        deviation = -1
        if usual_hour >= 0 and hour >= 0:
            raw = abs(hour - usual_hour)
            deviation = min(raw, 24 - raw)
        unusual = int(
            total >= UNUSUAL_HOUR_MIN_HISTORY
            and hour >= 0
            and hour_frequency < UNUSUAL_HOUR_MAX_FREQUENCY
        )

        return {
            "user_history_size": total,
            "user_event_index": total,
            "session_event_index": self.session_counts[session_id] if session_id else -1,
            "command_seen_before": int(command_count > 0),
            "first_seen_by_user": int(command_count == 0),
            "executable_seen_before": int(executable_count > 0),
            "new_executable_for_user": int(bool(executable) and executable_count == 0),
            "domain_seen_before": int(domain_count > 0),
            "new_domain_for_user": int(bool(domain) and domain_count == 0),
            "parent_seen_before": int(parent_count > 0),
            "unusual_parent_for_user": int(bool(parent) and parent_count == 0),
            "cwd_seen_before": int(cwd_count > 0),
            "host_seen_before": int(host_count > 0),
            "first_seen_on_host": int(self.host_command[host][normalized_command] == 0),
            "command_count_for_user": command_count,
            "executable_count_for_user": executable_count,
            "domain_count_for_user": domain_count,
            "host_command_count": self.host_command[host][normalized_command],
            "user_distinct_command_count": len(self.user_command[user]),
            "user_distinct_executable_count": len(self.user_executable[user]),
            "command_rarity": _rarity(command_count, total),
            "executable_rarity": _rarity(executable_count, total),
            "domain_rarity": _rarity(domain_count, total) if domain else 1.0,
            "parent_rarity": _rarity(parent_count, total) if parent else 1.0,
            "cwd_rarity": _rarity(cwd_count, total) if cwd else 1.0,
            "host_rarity": _rarity(host_count, total),
            "arg_pattern_rarity": _rarity(pattern_count, total) if arg_pattern else 1.0,
            "global_command_rarity": _rarity(self.global_command[normalized_command], self.global_total),
            "global_executable_rarity": _rarity(self.global_executable[executable], self.global_total)
            if executable else 1.0,
            "user_host_pair_seen_before": int(host_count > 0),
            "user_host_pair_count": host_count,
            "user_executable_pair_count": executable_count,
            "time_since_previous_command": since_previous,
            "seconds_since_same_command": since_same,
            "commands_in_previous_5_minutes": in_5m,
            "commands_in_previous_hour": in_1h,
            "user_hour_frequency": round(hour_frequency, 6),
            "user_day_frequency": round(day_frequency, 6),
            "usual_hour": usual_hour,
            "hour_deviation": deviation,
            "unusual_hour": unusual,
        }

    # -- state update -------------------------------------------------------
    def update(
        self,
        user: str,
        host: str,
        normalized_command: str,
        executable: str,
        domain: str,
        parent: str,
        cwd: str,
        arg_pattern: str,
        session_id: str,
        timestamp: Optional[dt.datetime],
    ) -> None:
        """Fold one event into the baseline, after its features were computed."""
        user = user or UNKNOWN
        host = host or UNKNOWN
        self.user_total[user] += 1
        self.user_command[user][normalized_command] += 1
        self.user_host[user][host] += 1
        self.host_total[host] += 1
        self.host_command[host][normalized_command] += 1
        self.global_command[normalized_command] += 1
        self.global_total += 1
        if executable:
            self.user_executable[user][executable] += 1
            self.host_executable[host][executable] += 1
            self.global_executable[executable] += 1
        if domain:
            self.user_domain[user][domain] += 1
        if parent:
            self.user_parent[user][parent] += 1
        if cwd:
            self.user_cwd[user][cwd] += 1
        if arg_pattern:
            self.user_arg_pattern[user][arg_pattern] += 1
        if session_id:
            self.session_counts[session_id] += 1
        if timestamp is not None:
            self.user_hour[user][timestamp.hour] += 1
            self.user_dow[user][timestamp.weekday()] += 1
            epoch = timestamp.timestamp()
            self.user_last_timestamp[user] = epoch
            self.user_command_last_seen[(user, normalized_command)] = epoch
            recent = self.user_recent[user]
            recent.append(epoch)
            while recent and epoch - recent[0] > ONE_HOUR:
                recent.popleft()
