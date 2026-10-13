"""Turn feature records into a maliciousness score with an explanation.

The score is a deterministic function of the signals that fired (see
:mod:`malscore.signals`).  It is **not** a probability and not a trained model:
it is a transparent, auditable weighting whose every point can be traced to a
named signal and a MITRE technique.

Aggregation uses a *noisy-OR* of the signal weights rather than a sum::

    combined = 1 - prod(1 - weight_i)

so that many weak signals accumulate but never overflow, one strong signal
dominates, and the result stays in ``[0, 1)`` before being scaled to 0-100.
Signals within the same tactic are damped (a command that trips three redundant
persistence checks should not score as if it did three independent things).

``Analyzer.assess_command`` scores one command line.  ``assess_session`` scores a
list of commands, then looks for *cross-command* patterns that no single command
reveals -- a file downloaded by one command and executed by a later one, a
``tar`` whose archive is ``scp``-ed afterwards, credential access followed later
by an upload.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

from .features import Record, extract_features
from .redaction import redact
from .signals import SESSION_SIGNALS, SIGNALS, Signal, on

#: Score bands for the verdict label.  Lower bound inclusive.
BANDS: Tuple[Tuple[int, str], ...] = (
    (80, "critical"),
    (60, "high"),
    (35, "medium"),
    (15, "low"),
    (0, "benign"),
)
VERDICTS = [label for _lower, label in reversed(BANDS)]
#: Within one tactic, the n-th strongest signal is multiplied by DAMPING**n.
TACTIC_DAMPING = 0.55
#: Session-level combination caps the contribution of any single noisy command,
#: so a 200-command session is not automatically "critical" because one command is.
COMMAND_CONTRIBUTION = 0.9


@dataclass
class Assessment:
    """The result of scoring one command or one session."""

    score: int
    verdict: str
    hits: List[Signal]
    command: str = ""
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    per_command: List["Assessment"] = field(default_factory=list)
    line: int = 0

    def as_dict(self, include_commands: bool = True) -> Dict[str, object]:
        data: Dict[str, object] = {
            "score": self.score,
            "verdict": self.verdict,
            "tactics": self.tactics,
            "techniques": self.techniques,
            "signals": [
                {
                    "id": hit.id,
                    "title": hit.title,
                    "weight": round(hit.weight, 2),
                    "tactic": hit.tactic,
                    "techniques": list(hit.techniques),
                }
                for hit in self.hits
            ],
        }
        if self.command:
            data["command"] = self.command
        if self.line:
            data["line"] = self.line
        if include_commands and self.per_command:
            data["commands"] = [c.as_dict(include_commands=False) for c in self.per_command]
        return data


def verdict_for(score: int) -> str:
    """Map a 0-100 score to a verdict band."""
    for lower, label in BANDS:
        if score >= lower:
            return label
    return "benign"


def _combine(weights: Sequence[float]) -> float:
    """Noisy-OR of a list of weights, each in [0, 1]."""
    product = 1.0
    for weight in weights:
        product *= (1.0 - max(0.0, min(1.0, weight)))
    return 1.0 - product


def _damped_weights(hits: Sequence[Signal]) -> List[float]:
    """Damp redundant signals that share a tactic before combining."""
    by_tactic: Dict[str, List[float]] = {}
    for hit in hits:
        by_tactic.setdefault(hit.tactic, []).append(hit.weight)
    weights: List[float] = []
    for tactic_weights in by_tactic.values():
        for rank, weight in enumerate(sorted(tactic_weights, reverse=True)):
            weights.append(weight * (TACTIC_DAMPING ** rank))
    return weights


def _score(hits: Sequence[Signal]) -> int:
    return int(round(_combine(_damped_weights(hits)) * 100))


def _collect(hits: Sequence[Signal]) -> Tuple[List[str], List[str]]:
    tactics: List[str] = []
    techniques: List[str] = []
    for hit in hits:
        if hit.tactic not in tactics:
            tactics.append(hit.tactic)
        for technique in hit.techniques:
            if technique not in techniques:
                techniques.append(technique)
    return tactics, techniques


def find_hits(record: Record) -> List[Signal]:
    """Every signal whose test passes on ``record``, strongest first."""
    hits: List[Signal] = []
    for signal in SIGNALS:
        try:
            if signal.test(record):
                hits.append(signal)
        except Exception:                          # pragma: no cover - defensive
            continue
    return sorted(hits, key=lambda h: h.weight, reverse=True)


def score_record(record: Record, command: str = "", line: int = 0) -> Assessment:
    """Score a single feature record."""
    hits = find_hits(record)
    score = _score(hits)
    tactics, techniques = _collect(hits)
    return Assessment(score=score, verdict=verdict_for(score), hits=hits, command=command,
                      tactics=tactics, techniques=techniques, line=line)


class Analyzer:
    """Scores single commands and sessions of commands.

    With ``redact=True``, credential-looking values are replaced in every
    command echoed back in an :class:`Assessment`; scoring always sees the
    original text.
    """

    def __init__(self, redact: bool = False) -> None:
        self.redact = redact

    def _echo(self, command: str) -> str:
        return redact(command) if self.redact else command

    def assess_command(self, command: str, line: int = 0) -> Assessment:
        """Score one command line."""
        return score_record(extract_features(command), command=self._echo(command), line=line)

    def assess_session(self, commands: Sequence[str]) -> Assessment:
        """Score a list of commands run in order, such as a shell history.

        Blank entries are skipped; each command's ``line`` is its 1-based
        position in ``commands``.
        """
        session = [(line, command.strip()) for line, command in enumerate(commands, start=1) if command.strip()]
        records: List[Record] = []
        per_command: List[Assessment] = []
        for line, command in session:
            record = extract_features(command)
            records.append(record)
            per_command.append(score_record(record, command=self._echo(command), line=line))

        cross = _session_hits([command for _line, command in session], records, per_command)
        command_weights = [_combine(_damped_weights(a.hits)) * COMMAND_CONTRIBUTION for a in per_command]
        score = int(round(_combine(command_weights + [hit.weight for hit in cross]) * 100))

        # de-duplicate for the tactic/technique roll-up, keep strongest first
        unique: Dict[str, Signal] = {}
        for hit in sorted([h for a in per_command for h in a.hits] + cross,
                          key=lambda h: h.weight, reverse=True):
            unique.setdefault(hit.id, hit)
        ranked = list(unique.values())
        tactics, techniques = _collect(ranked)

        return Assessment(score=score, verdict=verdict_for(score), hits=ranked,
                          tactics=tactics, techniques=techniques, per_command=per_command)


# --------------------------------------------------------------------------
# cross-command analysis
# --------------------------------------------------------------------------
def _session_hits(commands: Sequence[str], records: Sequence[Record],
                  per_command: Sequence[Assessment]) -> List[Signal]:
    """Find patterns that only appear across multiple commands."""
    downloaded_paths: List[Tuple[int, str]] = []
    archive_paths: List[Tuple[int, str]] = []
    executed_after_download = False
    archive_then_network = False
    cred_index = None
    upload_after_cred = False
    has_download = has_persistence = False

    for index, (command, record) in enumerate(zip(commands, records)):
        path = str(record.get("download_output_path", "") or "")
        if path:
            downloaded_paths.append((index, path.rstrip("/")))
        if record.get("archive_creation") and record.get("archive_path"):
            archive_paths.append((index, str(record["archive_path"])))
        if on(record, "network_download", "embedded_download_exec"):
            has_download = True
        if on(record, "crontab_edit", "systemd_unit_write", "authorized_keys_write",
              "shell_startup_write", "preload_persistence", "service_enable"):
            has_persistence = True

        # a later command executes a path an earlier one downloaded
        for prior_index, prior_path in downloaded_paths:
            base = prior_path.rsplit("/", 1)[-1]
            if prior_index < index and base and (base in command or prior_path in command):
                if on(record, "interpreter_used", "script_path_execution") \
                        or command.strip().startswith(("./", "/", "sh ", "bash ")):
                    executed_after_download = True

        # a later command sends an archive an earlier one created
        if on(record, "upload_indicator", "network_upload", "remote_copy", "transfer_over_socket_tool"):
            for prior_index, prior_path in archive_paths:
                base = prior_path.rsplit("/", 1)[-1]
                if prior_index < index and base and base in command:
                    archive_then_network = True

        # credential access, then a later upload
        if cred_index is None and on(record, "touches_shadow", "private_key_file_access",
                                     "cloud_credential_reference", "credential_search",
                                     "credential_file_reference"):
            cred_index = index
        elif cred_index is not None and index > cred_index and on(
                record, "upload_indicator", "network_upload", "remote_copy",
                "transfer_over_socket_tool", "exfil_service_domain"):
            upload_after_cred = True

    # cover-tracks: history/log clearing after earlier substantive activity
    cleared_tracks_after = any(
        on(record, "history_cleared", "log_tampering") and any(a.score >= 15 for a in per_command[:index])
        for index, record in enumerate(records))
    tactics_seen = {t for a in per_command for t in a.tactics if t != "discovery"}

    hits: List[Signal] = []
    if executed_after_download:
        hits.append(SESSION_SIGNALS["staged_download_execution"])
    if archive_then_network:
        hits.append(SESSION_SIGNALS["collect_then_exfiltrate"])
    if upload_after_cred:
        hits.append(SESSION_SIGNALS["credential_access_then_upload"])
    if has_download and has_persistence:
        hits.append(SESSION_SIGNALS["download_and_persist"])
    if cleared_tracks_after:
        hits.append(SESSION_SIGNALS["cover_tracks"])
    if len(tactics_seen) >= 3:
        hits.append(SESSION_SIGNALS["multi_stage"])
    return hits
