"""High-level API: text in, :class:`Assessment` out.

``assess_command`` scores one command line.  ``assess_script`` splits a script
into statements, scores each, and then looks for *cross-statement* patterns that
no single line reveals -- a file downloaded on line 3 and executed on line 40, a
``tar`` on line 10 whose archive is ``scp``-ed on line 12, credential access
followed later by an upload.  ``assess`` picks between them by shape.

The whole path is non-executing: it reuses the same lexer and feature extractor
the rest of the package is built on.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from ..context import SCRIPT_INTERPRETERS, SHELLS, build_context
from ..events import Event
from ..pipeline import ExtractorConfig, FeatureExtractor
from ..script import Statement, looks_like_script, split_script
from .engine import Assessment, Hit, _collect, _combine, _damped_weights, score_record, verdict_for
from .signals import SCRIPT_SIGNALS, Signal

Record = Dict[str, object]

#: Script-level combination caps the contribution of any single noisy statement,
#: so a 200-line script is not automatically "critical" because one line is.
STATEMENT_CONTRIBUTION = 0.9


class Analyzer:
    """Reusable scorer.  Holds one stateless feature extractor."""

    def __init__(self, redact: bool = False) -> None:
        self._extractor = FeatureExtractor(
            ExtractorConfig(include_behavioral=False, redact_secrets=redact, sort_by_time=False)
        )

    # -- single command --------------------------------------------------------
    def assess_command(self, command: str, line: int = 0) -> Assessment:
        record = self._extractor.extract_event(Event(0, line or 1, command=command, user=""))
        return score_record(record, command=command, line=line)

    # -- script ----------------------------------------------------------------
    def assess_script(self, text: str) -> Assessment:
        statements = split_script(text)
        per_statement: List[Assessment] = []
        records: List[Record] = []
        for statement in statements:
            command = statement.text
            record = self._extractor.extract_event(Event(0, statement.line, command=command, user=""))
            records.append(record)
            assessment = score_record(record, command=command, line=statement.line)
            self._fold_heredocs(statement, assessment, records)
            per_statement.append(assessment)

        cross = _cross_statement_hits(statements, records, per_statement)

        statement_weights = [
            _combine(_damped_weights(a.hits)) * STATEMENT_CONTRIBUTION for a in per_statement
        ]
        cross_weights = [hit.weight for hit in cross]
        combined = _combine(statement_weights + cross_weights)
        score = int(round(combined * 100))

        all_hits: List[Hit] = [hit for a in per_statement for hit in a.hits] + cross
        # de-duplicate for the tactic/technique roll-up, keep strongest first
        unique: Dict[str, Hit] = {}
        for hit in sorted(all_hits, key=lambda h: h.weight, reverse=True):
            unique.setdefault(hit.id, hit)
        ranked = list(unique.values())
        tactics, techniques = _collect(ranked)

        return Assessment(
            score=score,
            verdict=verdict_for(score),
            hits=ranked,
            command="",
            tactics=tactics,
            techniques=techniques,
            per_statement=per_statement,
            note="%d statements" % len(statements),
        )

    # -- dispatch --------------------------------------------------------------
    def assess(self, text: str) -> Assessment:
        return self.assess_script(text) if looks_like_script(text) else self.assess_command(text.strip())

    def _fold_heredocs(self, statement: Statement, assessment: Assessment,
                       records: List[Record]) -> None:
        """Score here-doc bodies fed to an interpreter as part of this statement.

        ``bash <<SH ... SH`` and ``python3 - <<PY ... PY`` carry their real
        payload in the body, not in ``statement.text``.  Each body is scored on
        its own and the strongest signals are merged into the statement, so the
        payload is not invisible to the scorer.  Bodies written to a file (``cat
        > unit <<EOF``) need no folding: the redirect target already trips the
        relevant path/persistence features.
        """
        record = records[-1]
        fed_to_interpreter = bool(
            record.get("stdin_script_execution")
            or (record.get("interpreter_used") and statement.text.rstrip().endswith(("-", "<<", "SH", "EOF", "PY")))
            or any(base in statement.text.split() for base in ("bash", "sh", "python", "python3", "perl", "ruby"))
        )
        merged: Dict[str, Hit] = {hit.id: hit for hit in assessment.hits}
        for heredoc in statement.heredocs:
            body = heredoc.body.strip()
            if not body or not fed_to_interpreter:
                continue
            sub = self.assess_script(body) if "\n" in body else self.assess_command(body)
            for hit in sub.hits:
                merged.setdefault(hit.id, hit)
        if len(merged) != len(assessment.hits):
            assessment.hits = sorted(merged.values(), key=lambda h: h.weight, reverse=True)
            combined = _combine(_damped_weights(assessment.hits))
            assessment.score = int(round(combined * 100))
            assessment.verdict = verdict_for(assessment.score)
            assessment.tactics, assessment.techniques = _collect(assessment.hits)


# --------------------------------------------------------------------------
# cross-statement analysis
# --------------------------------------------------------------------------
def _cross_statement_hits(statements: Sequence[Statement], records: Sequence[Record],
                          per_statement: Sequence[Assessment]) -> List[Hit]:
    """Find patterns that only appear across multiple statements."""
    hits: List[Hit] = []
    tactics_seen = set()
    for assessment in per_statement:
        tactics_seen.update(assessment.tactics)

    downloaded_paths: List[tuple] = []     # (index, path)
    archive_paths: List[tuple] = []
    executed_after_download = False
    archive_then_network = False
    cred_index: Optional[int] = None
    upload_after_cred = False
    has_download = has_persistence = False
    cleared_tracks_after = False
    activity_before_cleanup = False

    for index, record in enumerate(records):
        path = str(record.get("download_output_path", "") or "")
        if path:
            downloaded_paths.append((index, path.rstrip("/")))
        if record.get("archive_creation") and record.get("archive_path"):
            archive_paths.append((index, str(record.get("archive_path"))))
        if record.get("network_download") or record.get("embedded_download_exec"):
            has_download = True
        if on_any(record, "crontab_edit", "systemd_unit_write", "authorized_keys_write",
                  "shell_startup_write", "preload_persistence", "service_enable"):
            has_persistence = True

        # a later statement executes a path a former one downloaded
        command = str(record.get("command", ""))
        for prior_index, prior_path in downloaded_paths:
            if prior_index >= index:
                continue
            base = prior_path.rsplit("/", 1)[-1]
            if base and (base in command or prior_path in command):
                if on_any(record, "interpreter_used", "script_path_execution") or command.strip().startswith(("./", "/", "sh ", "bash ")):
                    executed_after_download = True

        # a later statement sends an archive a former one created
        if on_any(record, "upload_indicator", "network_upload", "remote_copy", "transfer_over_socket_tool"):
            for prior_index, prior_path in archive_paths:
                base = prior_path.rsplit("/", 1)[-1]
                if prior_index < index and base and base in command:
                    archive_then_network = True

        # credential access, then a later upload
        if cred_index is None and on_any(record, "touches_shadow", "private_key_file_access",
                                         "cloud_credential_reference", "credential_search",
                                         "credential_file_reference"):
            cred_index = index
        elif cred_index is not None and index > cred_index and on_any(
                record, "upload_indicator", "network_upload", "remote_copy",
                "transfer_over_socket_tool", "exfil_service_domain"):
            upload_after_cred = True

    # cover-tracks: history/log clearing after earlier substantive activity
    for index, record in enumerate(records):
        if on_any(record, "history_cleared", "log_tampering"):
            if any(per_statement[j].score >= 15 for j in range(index)):
                cleared_tracks_after = True

    if executed_after_download:
        hits.append(Hit(SCRIPT_SIGNALS["staged_download_execution"]))
    if archive_then_network:
        hits.append(Hit(SCRIPT_SIGNALS["collect_then_exfiltrate"]))
    if upload_after_cred:
        hits.append(Hit(SCRIPT_SIGNALS["credential_access_then_upload"]))
    if has_download and has_persistence:
        hits.append(Hit(SCRIPT_SIGNALS["download_and_persist"]))
    if cleared_tracks_after:
        hits.append(Hit(SCRIPT_SIGNALS["cover_tracks"]))
    if len({t for t in tactics_seen if t not in ("discovery",)}) >= 3:
        hits.append(Hit(SCRIPT_SIGNALS["multi_stage"]))
    return hits


def on_any(record: Record, *names: str) -> bool:
    return any(record.get(name) not in (None, 0, "", -1, 0.0, False) for name in names)
