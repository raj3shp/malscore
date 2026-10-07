"""Pipeline orchestration: events in, feature records out.

The pipeline is deliberately thin.  It builds the analysis context once, calls
every declared extractor, then the behavioural extractor (which must see events
in order), and assembles a record whose key set is exactly the feature registry.

A module that raises does not abort the run: its features fall back to their
declared defaults and the module name is recorded in ``extraction_error``.
Telemetry is messy and one odd command line should never cost you the batch.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from . import features as feature_modules
from .context import CommandContext, build_context, is_flag
from .events import Event, sort_events
from .features import behavioral as behavioral_module
from .normalize import command_fingerprint, normalize_command
from .redaction import redact
from .schema import F, KIND_CONTEXT, KIND_TEXT, FeatureRegistry

META_FEATURES = [
    F("event_id", "int", "meta", KIND_CONTEXT, "Sequential id assigned at ingest; stable within a run."),
    F("line_number", "int", "meta", KIND_CONTEXT, "Source line (or array index) the event came from."),
    F("user", "str", "meta", KIND_CONTEXT, "Username from telemetry, '' when absent.", ""),
    F("host", "str", "meta", KIND_CONTEXT, "Hostname from telemetry, '' when absent.", ""),
    F("cwd", "str", "meta", KIND_CONTEXT, "Working directory, '' when absent.", ""),
    F("timestamp", "str", "meta", KIND_CONTEXT, "Normalized ISO 8601 timestamp, '' when absent.", ""),
    F("command", "str", "meta", KIND_TEXT, "Raw command line (redacted or dropped on request).", ""),
    F("normalized_command", "str", "meta", KIND_TEXT, "Command template with values replaced by placeholders.", ""),
    F("command_fingerprint", "str", "meta", KIND_TEXT, "Short hash of the normalized command; a stable grouping key.", ""),
    F("token_string", "str", "meta", KIND_TEXT, "Space-joined token values, for word/char n-gram models.", ""),
    F("arg_pattern", "str", "meta", KIND_TEXT, "Executable plus its sorted flag signature.", ""),
    F("parse_warning", "str", "meta", KIND_CONTEXT, "Ingest warnings for this event (missing command, bad timestamp).", ""),
    F("extraction_error", "str", "meta", KIND_CONTEXT, "Extractor modules that failed for this event.", ""),
]


def build_registry(include_behavioral: bool = True) -> FeatureRegistry:
    """Assemble the full feature registry from every extractor module."""
    registry = FeatureRegistry()
    registry.add_many(META_FEATURES)
    for module in feature_modules.STATELESS_MODULES:
        registry.add_many(module.FEATURES)
    if include_behavioral:
        registry.add_many(behavioral_module.FEATURES)
    return registry


@dataclass
class ExtractorConfig:
    """Runtime options for :class:`FeatureExtractor`."""

    keep_raw_command: bool = True
    redact_secrets: bool = False
    include_behavioral: bool = True
    sort_by_time: bool = True
    max_command_length: int = 8192


class FeatureExtractor:
    """Convert :class:`~cmdfeat.events.Event` objects into feature records."""

    def __init__(self, config: Optional[ExtractorConfig] = None) -> None:
        self.config = config or ExtractorConfig()
        self.registry = build_registry(self.config.include_behavioral)
        self.store = behavioral_module.BaselineStore()
        self._defaults = self.registry.defaults()

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _arg_pattern(ctx: CommandContext) -> str:
        """Executable plus sorted flag signature, e.g. ``rsync|-a|-v|--delete``."""
        if not ctx.executions:
            return ""
        execution = ctx.executions[0]
        flags = sorted({a.split("=", 1)[0] for a in execution.args if is_flag(a)})
        return "|".join([execution.basename] + flags)

    def _primary_domain(self, ctx: CommandContext) -> str:
        if ctx.domains:
            return ctx.domains[0]
        if ctx.urls and ctx.urls[0].host:
            return ctx.urls[0].host.lower()
        return ""

    # -- extraction ---------------------------------------------------------
    def extract_event(self, event: Event) -> Dict[str, object]:
        """Extract one event.  Updates the behavioural baseline as a side effect."""
        if len(event.command) > self.config.max_command_length:
            event.command = event.command[: self.config.max_command_length]
            event.parse_warnings.append("command truncated")

        ctx = build_context(event)
        record: Dict[str, object] = dict(self._defaults)
        errors: List[str] = []

        for module in feature_modules.STATELESS_MODULES:
            try:
                record.update(module.extract(ctx))
            except Exception as exc:                       # pragma: no cover - defensive
                errors.append("%s:%s" % (module.__name__.rsplit(".", 1)[-1], type(exc).__name__))

        normalized = normalize_command(ctx)
        executable = str(record.get("executable_basename", "") or "")
        parent = str(record.get("parent_executable", "") or "")
        domain = self._primary_domain(ctx)
        arg_pattern = self._arg_pattern(ctx)

        raw_command = event.command
        if self.config.redact_secrets:
            raw_command = redact(raw_command)
            normalized = redact(normalized)

        record.update({
            "event_id": event.event_id,
            "line_number": event.line_number,
            "user": event.user,
            "host": event.host,
            "cwd": event.cwd,
            "timestamp": event.timestamp.isoformat() if event.timestamp else "",
            "command": raw_command if self.config.keep_raw_command else "",
            "normalized_command": normalized,
            "command_fingerprint": command_fingerprint(normalized),
            "token_string": " ".join(ctx.all_words),
            "arg_pattern": arg_pattern,
            "parse_warning": "; ".join(event.parse_warnings),
            "extraction_error": ",".join(errors),
        })

        if self.config.include_behavioral:
            keys = dict(
                user=event.user, host=event.host, normalized_command=normalized,
                executable=executable, domain=domain, parent=parent, cwd=event.cwd,
                arg_pattern=arg_pattern, session_id=event.session_id,
                timestamp=event.timestamp,
            )
            record.update(self.store.features(**keys))
            self.store.update(**keys)

        return record

    def extract_events(self, events: Sequence[Event]) -> List[Dict[str, object]]:
        """Extract a batch of events, chronologically ordered by default."""
        ordered = sort_events(list(events)) if self.config.sort_by_time else list(events)
        return [self.extract_event(event) for event in ordered]

    def iter_records(self, events: Iterable[Event]) -> Iterable[Dict[str, object]]:
        """Streaming variant for inputs that do not fit in memory.

        The caller is responsible for feeding events in chronological order --
        streaming cannot sort.
        """
        for event in events:
            yield self.extract_event(event)
