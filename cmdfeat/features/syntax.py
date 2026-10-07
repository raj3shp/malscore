"""Shell syntax and structural features (section 4 of the spec).

These are deterministic properties of the command *text*: lengths, counts of
metacharacters, redirections, pipelines and control characters.  Nothing here
judges intent.
"""

from __future__ import annotations

from statistics import mean
from typing import Dict, List

from ..context import CommandContext
from ..schema import F, KIND_STRUCTURAL

METACHARS = set("|&;<>()$`\\\"'*?[]{}~!#")

FEATURES = [
    F("command_length", "int", "syntax", KIND_STRUCTURAL, "Characters in the raw command line."),
    F("token_count", "int", "syntax", KIND_STRUCTURAL, "Lexical tokens (words plus operators)."),
    F("word_count", "int", "syntax", KIND_STRUCTURAL, "Word tokens only."),
    F("arg_count", "int", "syntax", KIND_STRUCTURAL, "Arguments across all simple commands (words minus each command head)."),
    F("segment_count", "int", "syntax", KIND_STRUCTURAL, "Simple commands the line decomposes into."),
    F("operator_count", "int", "syntax", KIND_STRUCTURAL, "Shell operator tokens (|, &&, >, ...)."),
    F("first_token", "str", "syntax", KIND_STRUCTURAL, "First word of the command line, as written.", ""),
    F("executable_path", "str", "syntax", KIND_STRUCTURAL, "Effective executable of the first command, as written.", ""),
    F("executable_basename", "str", "syntax", KIND_STRUCTURAL, "Basename of the effective executable.", ""),
    F("executable_path_components", "int", "syntax", KIND_STRUCTURAL, "Path components in the executable reference."),
    F("executable_is_absolute", "bool", "syntax", KIND_STRUCTURAL, "Executable was invoked by absolute path."),
    F("arg_length_total", "int", "syntax", KIND_STRUCTURAL, "Sum of argument lengths."),
    F("arg_length_min", "int", "syntax", KIND_STRUCTURAL, "Shortest argument length."),
    F("arg_length_max", "int", "syntax", KIND_STRUCTURAL, "Longest argument length."),
    F("arg_length_mean", "float", "syntax", KIND_STRUCTURAL, "Mean argument length.", 0.0),
    F("quoted_string_count", "int", "syntax", KIND_STRUCTURAL, "Quoted strings (single plus double)."),
    F("has_single_quote", "bool", "syntax", KIND_STRUCTURAL, "A single-quoted string is present."),
    F("has_double_quote", "bool", "syntax", KIND_STRUCTURAL, "A double-quoted string is present."),
    F("single_quote_count", "int", "syntax", KIND_STRUCTURAL, "Single-quoted strings."),
    F("double_quote_count", "int", "syntax", KIND_STRUCTURAL, "Double-quoted strings."),
    F("has_backslash", "bool", "syntax", KIND_STRUCTURAL, "A backslash is present."),
    F("backslash_count", "int", "syntax", KIND_STRUCTURAL, "Backslash characters."),
    F("escaped_char_count", "int", "syntax", KIND_STRUCTURAL, "Backslash escape sequences consumed by the lexer."),
    F("shell_metachar_count", "int", "syntax", KIND_STRUCTURAL, "Shell metacharacters in the raw text."),
    F("has_shell_metachar", "bool", "syntax", KIND_STRUCTURAL, "At least one shell metacharacter."),
    F("has_semicolon", "bool", "syntax", KIND_STRUCTURAL, "Command separator ';' used."),
    F("semicolon_count", "int", "syntax", KIND_STRUCTURAL, "Unquoted ';' separators."),
    F("has_pipe", "bool", "syntax", KIND_STRUCTURAL, "A pipeline is present."),
    F("pipe_count", "int", "syntax", KIND_STRUCTURAL, "Pipe operators."),
    F("pipeline_length", "int", "syntax", KIND_STRUCTURAL, "Stages in the longest pipeline.", 1),
    F("has_logical_and", "bool", "syntax", KIND_STRUCTURAL, "'&&' used."),
    F("has_logical_or", "bool", "syntax", KIND_STRUCTURAL, "'||' used."),
    F("logical_operator_count", "int", "syntax", KIND_STRUCTURAL, "Count of '&&' and '||'."),
    F("has_command_substitution", "bool", "syntax", KIND_STRUCTURAL, "'$( )' substitution present."),
    F("command_substitution_count", "int", "syntax", KIND_STRUCTURAL, "'$( )' substitutions."),
    F("has_backtick_substitution", "bool", "syntax", KIND_STRUCTURAL, "Backtick substitution present."),
    F("backtick_count", "int", "syntax", KIND_STRUCTURAL, "Backtick substitutions."),
    F("has_variable_expansion", "bool", "syntax", KIND_STRUCTURAL, "'$VAR' or '${VAR}' present."),
    F("variable_expansion_count", "int", "syntax", KIND_STRUCTURAL, "Variable expansions."),
    F("has_glob_star", "bool", "syntax", KIND_STRUCTURAL, "'*' glob present."),
    F("has_glob_question", "bool", "syntax", KIND_STRUCTURAL, "'?' glob present."),
    F("has_glob_bracket", "bool", "syntax", KIND_STRUCTURAL, "'[...]' glob present."),
    F("glob_char_count", "int", "syntax", KIND_STRUCTURAL, "Glob metacharacters."),
    F("has_input_redirect", "bool", "syntax", KIND_STRUCTURAL, "'<' input redirection."),
    F("has_output_redirect", "bool", "syntax", KIND_STRUCTURAL, "'>' output redirection."),
    F("has_append_redirect", "bool", "syntax", KIND_STRUCTURAL, "'>>' append redirection."),
    F("has_stderr_redirect", "bool", "syntax", KIND_STRUCTURAL, "'2>' stderr redirection."),
    F("has_combined_redirect", "bool", "syntax", KIND_STRUCTURAL, "'2>&1' or '&>' combined redirection."),
    F("redirect_count", "int", "syntax", KIND_STRUCTURAL, "Redirections of any kind."),
    F("has_heredoc", "bool", "syntax", KIND_STRUCTURAL, "'<<' here-document."),
    F("has_herestring", "bool", "syntax", KIND_STRUCTURAL, "'<<<' here-string."),
    F("has_background", "bool", "syntax", KIND_STRUCTURAL, "Trailing '&' background execution."),
    F("has_subshell", "bool", "syntax", KIND_STRUCTURAL, "Explicit '( ... )' subshell."),
    F("subshell_depth", "int", "syntax", KIND_STRUCTURAL, "Maximum subshell nesting depth."),
    F("has_parentheses", "bool", "syntax", KIND_STRUCTURAL, "Parentheses anywhere in the text."),
    F("has_braces", "bool", "syntax", KIND_STRUCTURAL, "Curly braces anywhere in the text."),
    F("has_brace_group", "bool", "syntax", KIND_STRUCTURAL, "Looks like a '{ ...; }' brace group."),
    F("newline_count", "int", "syntax", KIND_STRUCTURAL, "Embedded newline characters."),
    F("carriage_return_count", "int", "syntax", KIND_STRUCTURAL, "Embedded carriage returns."),
    F("has_null_byte", "bool", "syntax", KIND_STRUCTURAL, "NUL byte present in the command string."),
    F("control_char_count", "int", "syntax", KIND_STRUCTURAL, "ASCII control characters (excluding tab/newline/CR)."),
    F("nonprintable_char_count", "int", "syntax", KIND_STRUCTURAL, "Non-printable characters."),
    F("has_ansi_c_quoting", "bool", "syntax", KIND_STRUCTURAL, "$'...' ANSI-C quoting present."),
    F("unbalanced_quotes", "bool", "syntax", KIND_STRUCTURAL, "Lexer reached end of input inside a quote."),
    F("is_empty_command", "bool", "syntax", KIND_STRUCTURAL, "Command line is empty or whitespace only."),
]


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute structural syntax features for one event."""
    raw = ctx.raw
    parsed = ctx.parsed
    words = parsed.words
    arg_lengths: List[int] = []
    for command in parsed.commands:
        for value in command.argv[1:]:
            arg_lengths.append(len(value))

    first_execution = ctx.executions[0] if ctx.executions else None
    exe_written = first_execution.name if first_execution else ""
    ops = parsed.operators

    return {
        "command_length": len(raw),
        "token_count": len(parsed.tokens),
        "word_count": len(words),
        "arg_count": len(arg_lengths),
        "segment_count": len(parsed.commands),
        "operator_count": len(ops),
        "first_token": words[0].text if words else "",
        "executable_path": exe_written,
        "executable_basename": first_execution.basename if first_execution else "",
        "executable_path_components": len([p for p in exe_written.split("/") if p]) if exe_written else 0,
        "executable_is_absolute": int(exe_written.startswith("/")),
        "arg_length_total": sum(arg_lengths),
        "arg_length_min": min(arg_lengths) if arg_lengths else 0,
        "arg_length_max": max(arg_lengths) if arg_lengths else 0,
        "arg_length_mean": round(mean(arg_lengths), 3) if arg_lengths else 0.0,
        "quoted_string_count": parsed.single_quote_count + parsed.double_quote_count,
        "has_single_quote": int(parsed.single_quote_count > 0),
        "has_double_quote": int(parsed.double_quote_count > 0),
        "single_quote_count": parsed.single_quote_count,
        "double_quote_count": parsed.double_quote_count,
        "has_backslash": int("\\" in raw),
        "backslash_count": raw.count("\\"),
        "escaped_char_count": parsed.escape_count,
        "shell_metachar_count": sum(1 for ch in raw if ch in METACHARS),
        "has_shell_metachar": int(any(ch in METACHARS for ch in raw)),
        "has_semicolon": int(";" in ops),
        "semicolon_count": ops.count(";"),
        "has_pipe": int("|" in ops or "|&" in ops),
        "pipe_count": ops.count("|") + ops.count("|&"),
        "pipeline_length": parsed.max_pipeline_length,
        "has_logical_and": int("&&" in ops),
        "has_logical_or": int("||" in ops),
        "logical_operator_count": ops.count("&&") + ops.count("||"),
        "has_command_substitution": int(parsed.dollar_paren_count > 0),
        "command_substitution_count": parsed.dollar_paren_count,
        "has_backtick_substitution": int(parsed.backtick_count > 0),
        "backtick_count": parsed.backtick_count,
        "has_variable_expansion": int(parsed.expansion_count > 0),
        "variable_expansion_count": parsed.expansion_count,
        "has_glob_star": int("*" in raw),
        "has_glob_question": int("?" in raw),
        "has_glob_bracket": int("[" in raw and "]" in raw),
        "glob_char_count": sum(raw.count(ch) for ch in "*?["),
        "has_input_redirect": int("<" in ops),
        "has_output_redirect": int(">" in ops),
        "has_append_redirect": int(">>" in ops or "&>>" in ops or "2>>" in ops),
        "has_stderr_redirect": int("2>" in ops or "2>>" in ops or "2>&1" in ops),
        "has_combined_redirect": int("2>&1" in ops or "&>" in ops or "&>>" in ops or "1>&2" in ops),
        "redirect_count": sum(len(c.redirects) for c in parsed.commands),
        "has_heredoc": int(parsed.has_heredoc),
        "has_herestring": int("<<<" in ops),
        "has_background": int("&" in ops),
        "has_subshell": int("(" in ops),
        "subshell_depth": parsed.max_subshell_depth,
        "has_parentheses": int("(" in raw or ")" in raw),
        "has_braces": int("{" in raw or "}" in raw),
        "has_brace_group": int("{ " in raw and ("; }" in raw or ";}" in raw)),
        "newline_count": raw.count("\n"),
        "carriage_return_count": raw.count("\r"),
        "has_null_byte": int("\x00" in raw),
        "control_char_count": sum(1 for ch in raw if ord(ch) < 32 and ch not in "\t\n\r"),
        "nonprintable_char_count": sum(1 for ch in raw if not ch.isprintable() and ch not in "\t\n\r"),
        "has_ansi_c_quoting": int(parsed.ansi_c_quote_count > 0),
        "unbalanced_quotes": int(parsed.unbalanced_quotes),
        "is_empty_command": int(not raw.strip()),
    }
