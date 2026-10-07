"""Encoding and obfuscation *characteristics* (section 8 of the spec).

Nothing here claims obfuscation is malicious.  Minified one-liners, base64 in
CI scripts and long hashes in container digests are all normal.  The features
describe measurable properties -- entropy, escape density, encode/decode tools,
dynamic command construction -- and leave interpretation to the model.
"""

from __future__ import annotations

from typing import Dict, List

from ..context import SCRIPT_INTERPRETERS, SHELLS, CommandContext
from ..schema import F, KIND_INDICATOR, KIND_STRUCTURAL
from ..textutil import (
    BASE64_RE,
    HEX_ESCAPE_RE,
    HEX_STRING_RE,
    OCTAL_ESCAPE_RE,
    URL_ENCODING_RE,
    char_ratios,
    shannon_entropy,
)

DECODE_TOOLS = ("base64", "base32", "uudecode", "xxd", "openssl", "basenc")
DECODE_FLAGS = frozenset({"-d", "--decode", "-D", "-di", "--decode=1", "-r", "-p"})
LONG_TOKEN_THRESHOLD = 40
HIGH_ENTROPY_THRESHOLD = 4.0

FEATURES = [
    F("has_base64_keyword", "bool", "encoding", KIND_STRUCTURAL, "The word 'base64' (or basenc/base32) appears."),
    F("base64_decode", "bool", "encoding", KIND_INDICATOR, "A base64 decode operation is requested."),
    F("base64_encode", "bool", "encoding", KIND_INDICATOR, "A base64 encode operation is requested."),
    F("base64_to_interpreter", "bool", "encoding", KIND_INDICATOR, "Decoded output is piped into an interpreter."),
    F("echo_to_interpreter", "bool", "encoding", KIND_INDICATOR, "echo/printf output is piped into an interpreter."),
    F("has_hex_string", "bool", "encoding", KIND_STRUCTURAL, "A long hexadecimal string is present."),
    F("hex_string_count", "int", "encoding", KIND_STRUCTURAL, "Long hexadecimal strings (16+ chars)."),
    F("has_hex_escape", "bool", "encoding", KIND_STRUCTURAL, "'\\xNN' escape sequences are present."),
    F("hex_escape_count", "int", "encoding", KIND_STRUCTURAL, "'\\xNN' escape sequences."),
    F("has_octal_escape", "bool", "encoding", KIND_STRUCTURAL, "'\\NNN' octal escapes are present."),
    F("has_url_encoding", "bool", "encoding", KIND_STRUCTURAL, "Percent-encoded characters are present."),
    F("url_encoded_char_count", "int", "encoding", KIND_STRUCTURAL, "Percent-encoded characters."),
    F("base64_like_token_count", "int", "encoding", KIND_STRUCTURAL, "Tokens that look like base64 blobs (20+ chars)."),
    F("long_token_count", "int", "encoding", KIND_STRUCTURAL, "Tokens longer than 40 characters."),
    F("longest_token", "str", "encoding", KIND_STRUCTURAL, "The longest whitespace-delimited token.", ""),
    F("longest_token_length", "int", "encoding", KIND_STRUCTURAL, "Length of the longest token."),
    F("longest_token_entropy", "float", "encoding", KIND_STRUCTURAL, "Shannon entropy of the longest token.", 0.0),
    F("command_entropy", "float", "encoding", KIND_STRUCTURAL, "Shannon entropy of the whole command line.", 0.0),
    F("high_entropy_token_count", "int", "encoding", KIND_STRUCTURAL, "Long tokens with entropy >= 4.0 bits/char."),
    F("alnum_ratio", "float", "encoding", KIND_STRUCTURAL, "Proportion of alphanumeric characters.", 0.0),
    F("punctuation_ratio", "float", "encoding", KIND_STRUCTURAL, "Proportion of punctuation characters.", 0.0),
    F("digit_ratio", "float", "encoding", KIND_STRUCTURAL, "Proportion of digits.", 0.0),
    F("uppercase_ratio", "float", "encoding", KIND_STRUCTURAL, "Proportion of upper-case characters.", 0.0),
    F("whitespace_ratio", "float", "encoding", KIND_STRUCTURAL, "Proportion of whitespace.", 0.0),
    F("escape_char_ratio", "float", "encoding", KIND_STRUCTURAL, "Proportion of backslashes.", 0.0),
    F("base64_char_ratio", "float", "encoding", KIND_STRUCTURAL, "Proportion of base64-alphabet characters.", 0.0),
    F("nonprintable_ratio", "float", "encoding", KIND_STRUCTURAL, "Proportion of non-printable characters.", 0.0),
    F("uses_eval", "bool", "encoding", KIND_INDICATOR, "The shell 'eval' builtin is invoked."),
    F("uses_exec_builtin", "bool", "encoding", KIND_INDICATOR, "The shell 'exec' builtin is invoked."),
    F("uses_printf_construction", "bool", "encoding", KIND_INDICATOR, "printf is used to build a string with escapes."),
    F("xargs_execution", "bool", "encoding", KIND_INDICATOR, "xargs is used to execute a command per input line."),
    F("dynamic_command_construction", "bool", "encoding", KIND_INDICATOR, "The program name comes from a variable or substitution."),
    F("char_construction", "bool", "encoding", KIND_INDICATOR, "Characters are assembled from escapes or chr()-style calls."),
    F("variable_indirection", "bool", "encoding", KIND_INDICATOR, "Indirect variable expansion ('${!var}') is used."),
    F("excessive_backslash", "bool", "encoding", KIND_INDICATOR, "Unusually dense backslash escaping."),
    F("repeated_escape_sequences", "bool", "encoding", KIND_INDICATOR, "Doubled backslash escape sequences repeat."),
    F("obfuscation_characteristic_count", "int", "encoding", KIND_INDICATOR, "How many obfuscation-adjacent characteristics are present (0-10)."),
]

OBFUSCATION_KEYS = (
    "base64_decode", "has_hex_escape", "has_octal_escape", "char_construction",
    "variable_indirection", "excessive_backslash", "repeated_escape_sequences",
    "dynamic_command_construction", "uses_eval", "echo_to_interpreter",
)


def _pipes_into_interpreter(ctx: CommandContext, sources: List[str]) -> bool:
    """True when a stage running one of ``sources`` pipes into an interpreter."""
    for execution in ctx.executions:
        if execution.basename not in sources or execution.command is None:
            continue
        command = execution.command
        if command.pipeline_length <= 1:
            continue
        for other in ctx.executions:
            if other.command is None or other is execution:
                continue
            if (other.command.pipeline_id == command.pipeline_id
                    and other.command.pipeline_index > command.pipeline_index
                    and (other.basename in SHELLS or other.basename in SCRIPT_INTERPRETERS)):
                return True
    return False


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute encoding/obfuscation characteristics for one event."""
    text = ctx.scan_text
    tokens = text.split()
    longest = max(tokens, key=len) if tokens else ""
    ratios = char_ratios(text)

    decode_executions = ctx.executions_of(*DECODE_TOOLS)
    decode = any(
        flag in DECODE_FLAGS for e in decode_executions for flag in e.args
    ) or "b64decode" in ctx.lower or "base64 -d" in ctx.lower
    encode = bool(decode_executions) and not decode or "b64encode" in ctx.lower

    head_dynamic = any(
        e.name.startswith("$") or e.name.startswith("`") or "$(" in e.name
        for e in ctx.executions
    )
    features: Dict[str, object] = {
        "has_base64_keyword": int(any(word in ctx.lower for word in ("base64", "base32", "basenc"))),
        "base64_decode": int(bool(decode)),
        "base64_encode": int(bool(encode)),
        "base64_to_interpreter": int(_pipes_into_interpreter(ctx, list(DECODE_TOOLS))),
        "echo_to_interpreter": int(_pipes_into_interpreter(ctx, ["echo", "printf", "cat"])),
        "has_hex_string": int(bool(HEX_STRING_RE.search(text))),
        "hex_string_count": len(HEX_STRING_RE.findall(text)),
        "has_hex_escape": int(bool(HEX_ESCAPE_RE.search(text))),
        "hex_escape_count": len(HEX_ESCAPE_RE.findall(text)),
        "has_octal_escape": int(bool(OCTAL_ESCAPE_RE.search(text))),
        "has_url_encoding": int(bool(URL_ENCODING_RE.search(text))),
        "url_encoded_char_count": len(URL_ENCODING_RE.findall(text)),
        "base64_like_token_count": len(BASE64_RE.findall(text)),
        "long_token_count": sum(1 for t in tokens if len(t) > LONG_TOKEN_THRESHOLD),
        "longest_token": longest[:120],
        "longest_token_length": len(longest),
        "longest_token_entropy": round(shannon_entropy(longest), 3),
        "command_entropy": round(shannon_entropy(text), 3),
        "high_entropy_token_count": sum(
            1 for t in tokens if len(t) >= 20 and shannon_entropy(t) >= HIGH_ENTROPY_THRESHOLD
        ),
        "alnum_ratio": round(ratios["alnum"], 3),
        "punctuation_ratio": round(ratios["punct"], 3),
        "digit_ratio": round(ratios["digit"], 3),
        "uppercase_ratio": round(ratios["upper"], 3),
        "whitespace_ratio": round(ratios["space"], 3),
        "escape_char_ratio": round(ratios["escape"], 3),
        "base64_char_ratio": round(ratios["base64"], 3),
        "nonprintable_ratio": round(ratios["nonprintable"], 3),
        "uses_eval": int(ctx.uses("eval") or " eval " in " %s " % ctx.lower),
        "uses_exec_builtin": int(ctx.uses("exec")),
        "uses_printf_construction": int(
            ctx.uses("printf") and bool(HEX_ESCAPE_RE.search(text) or OCTAL_ESCAPE_RE.search(text))
        ),
        "xargs_execution": int(ctx.any_wrapper("xargs") or ctx.uses("xargs")),
        "dynamic_command_construction": int(head_dynamic or ctx.uses("eval")),
        "char_construction": int(
            bool(HEX_ESCAPE_RE.search(text)) or "chr(" in ctx.lower
            or ctx.parsed.ansi_c_quote_count > 0
        ),
        "variable_indirection": int("${!" in text),
        "excessive_backslash": int(text.count("\\") >= 8 or ratios["escape"] > 0.05),
        "repeated_escape_sequences": int(text.count("\\\\") >= 2),
    }
    features["obfuscation_characteristic_count"] = sum(
        int(bool(features[key])) for key in OBFUSCATION_KEYS
    )
    return features
