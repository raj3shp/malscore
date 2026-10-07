"""Download-and-execute chain features (section 7 of the spec).

Detection is *structural*: the command line is decomposed into simple commands,
and the analysis asks whether a retrieval stage is followed -- in the same
pipeline, or after ``&&``/``;`` -- by a shell, an interpreter, a ``chmod +x`` or
an execution of the file that was just written.

This is what separates ``curl -o /tmp/x URL`` (a download) from
``curl URL | bash`` (a download feeding an interpreter) without relying on the
literal string "| bash".
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..context import (
    SCRIPT_INTERPRETERS,
    SHELLS,
    CommandContext,
    Execution,
    resolve_execution,
)
from ..lexer import SimpleCommand, tokenize
from ..schema import F, KIND_INDICATOR

RETRIEVAL_TOOLS = frozenset({"curl", "wget", "aria2c", "axel", "fetch", "tftp",
                             "nc", "ncat", "netcat", "socat", "scp", "rsync", "sftp", "lftp"})
OUTPUT_FLAGS = frozenset({"-o", "--output", "-O", "--remote-name", "--output-dir"})
WGET_DIR_FLAGS = frozenset({"-P", "--directory-prefix"})

FEATURES = [
    F("download_then_execute", "bool", "chains", KIND_INDICATOR, "A retrieval stage is followed by execution of what it produced."),
    F("network_to_shell_pipeline", "bool", "chains", KIND_INDICATOR, "A retrieval command is piped into a shell."),
    F("network_to_interpreter_pipeline", "bool", "chains", KIND_INDICATOR, "A retrieval command is piped into a non-shell interpreter."),
    F("pipeline_ends_in_interpreter", "bool", "chains", KIND_INDICATOR, "The last stage of a pipeline is an interpreter."),
    F("download_to_tmp", "bool", "chains", KIND_INDICATOR, "Retrieved content is written under a temporary directory."),
    F("download_to_home", "bool", "chains", KIND_INDICATOR, "Retrieved content is written under a home directory."),
    F("download_to_current_directory", "bool", "chains", KIND_INDICATOR, "Retrieved content is written to the working directory."),
    F("download_output_path", "str", "chains", KIND_INDICATOR, "Output path the retrieval writes to.", ""),
    F("downloaded_file_executed", "bool", "chains", KIND_INDICATOR, "The retrieved file is executed later in the same command line."),
    F("chmod_following_download", "bool", "chains", KIND_INDICATOR, "A chmod follows a retrieval in the same command line."),
    F("interpreter_following_download", "bool", "chains", KIND_INDICATOR, "An interpreter runs after a retrieval in the same command line."),
    F("retrieval_stage_count", "int", "chains", KIND_INDICATOR, "Retrieval commands in the command line."),
    F("chain_length", "int", "chains", KIND_INDICATOR, "Simple commands joined by pipes or logical operators.", 1),
]


def _is_retrieval(execution: Execution) -> bool:
    """True when this stage pulls remote content onto this host."""
    if execution.basename not in RETRIEVAL_TOOLS:
        return False
    if execution.basename in ("scp", "rsync", "sftp", "lftp"):
        positionals = execution.positionals
        return bool(positionals) and (":" in positionals[0] or "@" in positionals[0])
    return True


def _output_path(execution: Execution) -> Optional[str]:
    """Where a retrieval tool writes its result, if it can be determined."""
    args = execution.args
    base = execution.basename
    for index, token in enumerate(args):
        if token in OUTPUT_FLAGS and token not in ("-O", "--remote-name"):
            if index + 1 < len(args):
                return args[index + 1]
        if token.startswith("--output="):
            return token.split("=", 1)[1]
        if base == "wget" and token == "-O" and index + 1 < len(args):
            return args[index + 1]
        if base == "wget" and token in WGET_DIR_FLAGS and index + 1 < len(args):
            return args[index + 1].rstrip("/") + "/"
    if execution.command is not None:
        for op, target in execution.command.redirects:
            if op.endswith(">") or op.endswith(">>"):
                return target
    if base == "curl" and any(t in ("-O", "--remote-name") for t in args):
        return "./"
    if base in ("scp", "rsync", "sftp") and len(execution.positionals) >= 2:
        # only a remote -> local copy retrieves anything; an upload's last
        # positional is the destination, not something fetched to this host
        source = execution.positionals[0]
        if ":" in source or "@" in source:
            return execution.positionals[-1]
    return None


def _executions_for(commands: Sequence[SimpleCommand]) -> List[Tuple[int, SimpleCommand, Optional[Execution]]]:
    return [(index, command, resolve_execution(command))
            for index, command in enumerate(commands)]


def _analyse_group(commands: Sequence[SimpleCommand]) -> Dict[str, object]:
    """Chain analysis for one ordered group of simple commands."""
    result = {
        "download_then_execute": 0, "network_to_shell_pipeline": 0,
        "network_to_interpreter_pipeline": 0, "pipeline_ends_in_interpreter": 0,
        "download_to_tmp": 0, "download_to_home": 0, "download_to_current_directory": 0,
        "download_output_path": "", "downloaded_file_executed": 0,
        "chmod_following_download": 0, "interpreter_following_download": 0,
        "retrieval_stage_count": 0, "chain_length": len(commands) or 1,
    }
    resolved = _executions_for(commands)
    retrievals = [(i, c, e) for i, c, e in resolved if e is not None and _is_retrieval(e)]
    result["retrieval_stage_count"] = len(retrievals)

    # pipeline stage ending in an interpreter (independent of downloads)
    for index, command, execution in resolved:
        if execution is None:
            continue
        if command.pipeline_length > 1 and command.pipeline_index == command.pipeline_length - 1:
            if execution.basename in SHELLS or execution.basename in SCRIPT_INTERPRETERS:
                result["pipeline_ends_in_interpreter"] = 1

    for index, command, execution in retrievals:
        output = _output_path(execution) if execution else None
        if output:
            if not result["download_output_path"]:
                result["download_output_path"] = output
            lowered = output.lower()
            if lowered.startswith(("/tmp", "/var/tmp", "/dev/shm")):
                result["download_to_tmp"] = 1
            if lowered.startswith(("~", "$home", "${home}", "/home/", "/root/")):
                result["download_to_home"] = 1
            if lowered.startswith("./") or "/" not in lowered.rstrip("/") or lowered == "./":
                result["download_to_current_directory"] = 1

        downstream = [(i, c, e) for i, c, e in resolved if i > index]
        for later_index, later_command, later_execution in downstream:
            if later_execution is None:
                continue
            base = later_execution.basename
            same_pipeline = (later_command.pipeline_id == command.pipeline_id
                             and later_command.pipeline_index > command.pipeline_index)
            if base in SHELLS and same_pipeline:
                result["network_to_shell_pipeline"] = 1
                result["download_then_execute"] = 1
            elif base in SCRIPT_INTERPRETERS and same_pipeline:
                result["network_to_interpreter_pipeline"] = 1
                result["download_then_execute"] = 1
            if base in SHELLS or base in SCRIPT_INTERPRETERS:
                result["interpreter_following_download"] = 1
            if base == "chmod":
                result["chmod_following_download"] = 1
                if output and any(output.rstrip("/") in arg for arg in later_execution.args):
                    result["download_then_execute"] = 1
            if output:
                target = output.rstrip("/")
                names = {target, target.lstrip("./"), "./" + target.lstrip("./")}
                if later_execution.name in names or any(a in names for a in later_execution.args):
                    if later_execution.name in names:
                        result["downloaded_file_executed"] = 1
                        result["download_then_execute"] = 1
                    elif base in SHELLS or base in SCRIPT_INTERPRETERS:
                        result["downloaded_file_executed"] = 1
                        result["download_then_execute"] = 1
    return result


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute download/execute chain features for one event."""
    groups: List[Sequence[SimpleCommand]] = [ctx.parsed.commands]
    for payload in ctx.shell_payloads + ctx.remote_payloads:
        if payload.strip():
            groups.append(tokenize(payload).commands)

    merged = _analyse_group(groups[0])
    for group in groups[1:]:
        other = _analyse_group(group)
        for key, value in other.items():
            if key == "download_output_path":
                if not merged[key]:
                    merged[key] = value
            elif key in ("retrieval_stage_count", "chain_length"):
                merged[key] = max(merged[key], value)  # type: ignore[arg-type]
            else:
                merged[key] = max(merged[key], value)  # type: ignore[arg-type]
    return merged
