"""Interpreter and executable features (section 5 of the spec).

Interpreter use is detected from the resolved execution list, so it survives
wrappers (``sudo env python3 -c ...``), pipelines (``... | bash``) and one level
of nesting (``bash -c 'python3 -c ...'``).
"""

from __future__ import annotations

from typing import Dict, List

from ..context import (
    INLINE_SCRIPT_FLAGS,
    SCRIPT_INTERPRETERS,
    SHELLS,
    CommandContext,
    Execution,
    inline_payload,
)
from ..schema import F, KIND_STRUCTURAL

SCRIPT_EXTENSIONS = frozenset({"sh", "bash", "zsh", "ksh", "py", "py3", "pl", "rb",
                               "php", "js", "mjs", "lua", "awk", "sed", "exp", "ps1", "r"})
#: Interpreter families we report individually.
INTERPRETER_FLAGS = {
    "uses_bash": ("bash", "rbash"),
    "uses_sh": ("sh",),
    "uses_dash": ("dash",),
    "uses_zsh": ("zsh",),
    "uses_fish": ("fish",),
    "uses_ksh": ("ksh", "mksh", "pdksh"),
    "uses_csh": ("csh",),
    "uses_tcsh": ("tcsh",),
    "uses_ash": ("ash",),
    "uses_busybox": ("busybox",),
    "uses_python": ("python", "python2", "python3"),
    "uses_perl": ("perl",),
    "uses_ruby": ("ruby",),
    "uses_php": ("php",),
    "uses_node": ("node", "nodejs", "deno", "bun"),
    "uses_awk": ("awk", "gawk", "mawk", "nawk"),
    "uses_sed": ("sed",),
    "uses_expect": ("expect",),
    "uses_powershell": ("powershell", "pwsh"),
}

FEATURES = [
    F("execution_count", "int", "executable", KIND_STRUCTURAL, "Resolved program executions, including nested ones."),
    F("distinct_executable_count", "int", "executable", KIND_STRUCTURAL, "Distinct executable basenames."),
    F("nested_execution_count", "int", "executable", KIND_STRUCTURAL, "Executions found inside substitutions, -c payloads or remote commands."),
    F("wrapper_count", "int", "executable", KIND_STRUCTURAL, "Wrapper programs skipped during resolution (sudo, env, xargs, ...)."),
    F("uses_wrapper", "bool", "executable", KIND_STRUCTURAL, "At least one wrapper program was used."),
    F("wrapper_names", "str", "executable", KIND_STRUCTURAL, "Pipe-separated wrapper names.", ""),
    F("executable_list", "str", "executable", KIND_STRUCTURAL, "Pipe-separated executable basenames in execution order.", ""),
    F("interpreter_used", "bool", "executable", KIND_STRUCTURAL, "A shell or scripting interpreter is executed."),
    F("interpreter_name", "str", "executable", KIND_STRUCTURAL, "First interpreter basename.", ""),
    F("interpreter_count", "int", "executable", KIND_STRUCTURAL, "Number of interpreter executions."),
    F("interpreter_family", "str", "executable", KIND_STRUCTURAL, "'shell', 'script' or '' when no interpreter is used.", ""),
    F("interpreter_execution", "bool", "executable", KIND_STRUCTURAL, "An interpreter runs code (inline payload or script file)."),
    F("inline_script_execution", "bool", "executable", KIND_STRUCTURAL, "Interpreter given inline code via -c/-e/--eval."),
    F("has_dash_c", "bool", "executable", KIND_STRUCTURAL, "A '-c' style inline-code flag is present."),
    F("inline_payload_length", "int", "executable", KIND_STRUCTURAL, "Characters of inline interpreter payload."),
    F("script_file_execution", "bool", "executable", KIND_STRUCTURAL, "Interpreter invoked with a script file argument."),
    F("script_path_execution", "bool", "executable", KIND_STRUCTURAL, "A script-looking file is executed directly (./x.sh)."),
    F("nested_interpreter", "bool", "executable", KIND_STRUCTURAL, "Two or more interpreters in one command line."),
    F("shell_from_shell", "bool", "executable", KIND_STRUCTURAL, "A shell is spawned by another shell (payload, pipeline or nesting)."),
    F("uses_shell", "bool", "executable", KIND_STRUCTURAL, "A shell interpreter is executed."),
    F("shell_name", "str", "executable", KIND_STRUCTURAL, "First shell basename.", ""),
    F("shell_count", "int", "executable", KIND_STRUCTURAL, "Shell executions."),
    F("remote_command_execution", "bool", "executable", KIND_STRUCTURAL, "A command is handed to ssh/docker/kubectl to run elsewhere."),
    F("remote_command_count", "int", "executable", KIND_STRUCTURAL, "Remote/container command payloads found."),
    F("login_shell_flag", "bool", "executable", KIND_STRUCTURAL, "Interactive/login shell flags (-i, -l, --login)."),
    F("stdin_script_execution", "bool", "executable", KIND_STRUCTURAL, "An interpreter reads its program from stdin or a here-doc."),
] + [
    F(name, "bool", "executable", KIND_STRUCTURAL, "Executes %s." % " / ".join(values))
    for name, values in INTERPRETER_FLAGS.items()
]


def _is_script_file(token: str) -> bool:
    base = token.rsplit("/", 1)[-1]
    return "." in base and base.rsplit(".", 1)[-1].lower() in SCRIPT_EXTENSIONS


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute interpreter/executable features for one event."""
    executions: List[Execution] = ctx.executions
    interpreters = [e for e in executions if e.basename in SHELLS or e.basename in SCRIPT_INTERPRETERS]
    shells = [e for e in executions if e.basename in SHELLS]
    wrappers = [w for e in executions for w in e.wrappers]

    payloads = [inline_payload(e) or "" for e in interpreters]
    payloads = [p for p in payloads if p]
    script_file = any(
        any(_is_script_file(arg) for arg in e.positionals) for e in interpreters
    )
    direct_script = any(
        _is_script_file(e.name) and ("/" in e.name or e.name.startswith("."))
        for e in executions
    )
    has_dash_c = any(flag in INLINE_SCRIPT_FLAGS for e in interpreters for flag in e.args)

    # a shell spawned by a shell: shell inside a shell payload, a pipeline whose
    # downstream stage is a shell, or a shell executed by a shell wrapper
    shell_from_shell = False
    if len(shells) >= 2:
        shell_from_shell = True
    for execution in shells:
        if execution.nested:
            shell_from_shell = True
        command = execution.command
        if command is not None and command.preceding_op in ("|", "|&") and command.pipeline_index > 0:
            shell_from_shell = True

    family = ""
    if interpreters:
        family = "shell" if interpreters[0].basename in SHELLS else "script"

    features: Dict[str, object] = {
        "execution_count": len(executions),
        "distinct_executable_count": len({e.basename for e in executions}),
        "nested_execution_count": sum(1 for e in executions if e.nested),
        "wrapper_count": len(wrappers),
        "uses_wrapper": int(bool(wrappers)),
        "wrapper_names": "|".join(sorted(set(wrappers))),
        "executable_list": "|".join(e.basename for e in executions),
        "interpreter_used": int(bool(interpreters)),
        "interpreter_name": interpreters[0].basename if interpreters else "",
        "interpreter_count": len(interpreters),
        "interpreter_family": family,
        "interpreter_execution": int(bool(payloads) or script_file),
        "inline_script_execution": int(bool(payloads)),
        "has_dash_c": int(has_dash_c),
        "inline_payload_length": max((len(p) for p in payloads), default=0),
        "script_file_execution": int(script_file),
        "script_path_execution": int(direct_script),
        "nested_interpreter": int(len(interpreters) >= 2),
        "shell_from_shell": int(shell_from_shell),
        "uses_shell": int(bool(shells)),
        "shell_name": shells[0].basename if shells else "",
        "shell_count": len(shells),
        "remote_command_execution": int(bool(ctx.remote_payloads)),
        "remote_command_count": len(ctx.remote_payloads),
        "login_shell_flag": int(any(flag in ("-i", "-l", "--login", "--interactive")
                                    for e in interpreters for flag in e.args)),
        "stdin_script_execution": int(
            bool(interpreters) and any(
                op.endswith("<") or op.endswith("<<") or op.endswith("<<<")
                for e in interpreters if e.command is not None
                for op, _target in e.command.redirects
            )
        ),
    }
    for name, values in INTERPRETER_FLAGS.items():
        features[name] = int(ctx.uses(*values))
    return features
