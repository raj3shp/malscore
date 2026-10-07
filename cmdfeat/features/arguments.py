"""Argument-shape features.

How a program is *invoked* carries user-specific signal: some people always use
long options, recursive/force flags cluster around bulk operations, and unusual
option mixes for a familiar binary are worth a feature even when the binary is
completely normal for that user.
"""

from __future__ import annotations

from typing import Dict, List

from ..context import CommandContext, flag_letters, is_assignment, is_flag
from ..schema import F, KIND_STRUCTURAL

RECURSIVE_FLAGS = frozenset({"-r", "-R", "--recursive", "-rf", "-fr", "-rvf"})
FORCE_FLAGS = frozenset({"-f", "--force", "-rf", "-fr", "-y", "--yes", "--assume-yes"})
QUIET_FLAGS = frozenset({"-q", "--quiet", "-s", "--silent", "--no-progress-meter"})
VERBOSE_FLAGS = frozenset({"-v", "-vv", "-vvv", "--verbose", "--debug"})

FEATURES = [
    F("flag_count", "int", "arguments", KIND_STRUCTURAL, "Option tokens across all commands."),
    F("short_flag_count", "int", "arguments", KIND_STRUCTURAL, "Short options ('-x')."),
    F("long_flag_count", "int", "arguments", KIND_STRUCTURAL, "Long options ('--xyz')."),
    F("has_double_dash_separator", "bool", "arguments", KIND_STRUCTURAL, "'--' end-of-options separator present."),
    F("key_value_arg_count", "int", "arguments", KIND_STRUCTURAL, "Arguments of the form key=value."),
    F("env_assignment_count", "int", "arguments", KIND_STRUCTURAL, "Inline environment assignments before the program."),
    F("numeric_arg_count", "int", "arguments", KIND_STRUCTURAL, "Purely numeric arguments."),
    F("positional_arg_count", "int", "arguments", KIND_STRUCTURAL, "Non-option arguments."),
    F("distinct_arg_ratio", "float", "arguments", KIND_STRUCTURAL, "Distinct arguments divided by argument count.", 0.0),
    F("has_recursive_flag", "bool", "arguments", KIND_STRUCTURAL, "A recursive flag (-r/-R/--recursive) is used."),
    F("has_force_flag", "bool", "arguments", KIND_STRUCTURAL, "A force/assume-yes flag is used."),
    F("has_quiet_flag", "bool", "arguments", KIND_STRUCTURAL, "A quiet/silent flag is used."),
    F("has_verbose_flag", "bool", "arguments", KIND_STRUCTURAL, "A verbose/debug flag is used."),
    F("longest_arg_length", "int", "arguments", KIND_STRUCTURAL, "Length of the longest argument."),
    F("arg_with_space_count", "int", "arguments", KIND_STRUCTURAL, "Arguments containing whitespace (quoted payloads)."),
    F("argument_string", "str", "arguments", KIND_STRUCTURAL, "Arguments of the first command joined by spaces.", ""),
]


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute argument-shape features for one event."""
    args: List[str] = ctx.args
    flags = [a for a in args if is_flag(a)]
    short_flags = [a for a in flags if not a.startswith("--")]
    long_flags = [a for a in flags if a.startswith("--")]
    positionals = [a for a in args if not is_flag(a)]
    # clustered short options (-rvf) count as their individual letters
    lowered = {a.lower() for a in flags} | {f.lower() for f in flag_letters(flags)}

    first = ctx.executions[0] if ctx.executions else None
    return {
        "flag_count": len(flags),
        "short_flag_count": len(short_flags),
        "long_flag_count": len(long_flags),
        "has_double_dash_separator": int("--" in args),
        "key_value_arg_count": sum(1 for a in args if "=" in a and not a.startswith("-")),
        "env_assignment_count": sum(len(e.assignments) for e in ctx.executions),
        "numeric_arg_count": sum(1 for a in args if a.lstrip("+-").isdigit()),
        "positional_arg_count": len(positionals),
        "distinct_arg_ratio": round(len(set(args)) / len(args), 3) if args else 0.0,
        "has_recursive_flag": int(bool(lowered & {f.lower() for f in RECURSIVE_FLAGS})),
        "has_force_flag": int(bool(lowered & {f.lower() for f in FORCE_FLAGS})),
        "has_quiet_flag": int(bool(lowered & {f.lower() for f in QUIET_FLAGS})),
        "has_verbose_flag": int(bool(lowered & {f.lower() for f in VERBOSE_FLAGS})),
        "longest_arg_length": max((len(a) for a in args), default=0),
        "arg_with_space_count": sum(1 for a in args if any(ch.isspace() for ch in a)),
        "argument_string": " ".join(first.args) if first else "",
    }
