"""File modification features (section 17 of the spec)."""

from __future__ import annotations

from typing import Dict

from ..context import CommandContext, flag_letters
from ..schema import F, KIND_INDICATOR

WRITE_TOOLS = ("touch", "tee", "install", "truncate", "dd", "ln", "mkdir", "mktemp", "split")
EDIT_TOOLS = ("sed", "perl", "awk", "ed", "patch", "vi", "vim", "nvim", "nano", "emacs")
DELETE_TOOLS = ("rm", "unlink", "shred", "rmdir", "wipe", "srm")
MOVE_TOOLS = ("mv", "rename")
COPY_TOOLS = ("cp", "rsync", "install", "dd", "cpio")
#: Redirect targets that discard or pass through output rather than write a file.
DISCARD_TARGETS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"})

FEATURES = [
    F("file_write_indicator", "bool", "file_ops", KIND_INDICATOR, "The command writes to a file (tool or redirection)."),
    F("file_create_indicator", "bool", "file_ops", KIND_INDICATOR, "A file or directory is created."),
    F("file_delete_indicator", "bool", "file_ops", KIND_INDICATOR, "A file is deleted."),
    F("file_move_indicator", "bool", "file_ops", KIND_INDICATOR, "A file is moved or renamed."),
    F("file_copy_indicator", "bool", "file_ops", KIND_INDICATOR, "A file is copied."),
    F("file_edit_indicator", "bool", "file_ops", KIND_INDICATOR, "An editor or in-place edit tool is used."),
    F("inplace_edit", "bool", "file_ops", KIND_INDICATOR, "In-place editing ('sed -i', 'perl -i') is used."),
    F("overwrite_indicator", "bool", "file_ops", KIND_INDICATOR, "Output truncates an existing file ('>' redirection or dd of=)."),
    F("append_indicator", "bool", "file_ops", KIND_INDICATOR, "Output is appended ('>>' redirection or tee -a)."),
    F("permission_change_indicator", "bool", "file_ops", KIND_INDICATOR, "File permissions are changed."),
    F("ownership_change_indicator", "bool", "file_ops", KIND_INDICATOR, "File ownership is changed."),
    F("recursive_delete", "bool", "file_ops", KIND_INDICATOR, "A recursive delete is requested."),
    F("force_delete", "bool", "file_ops", KIND_INDICATOR, "A forced delete is requested."),
    F("wildcard_delete", "bool", "file_ops", KIND_INDICATOR, "A delete targets a glob pattern."),
    F("secure_delete", "bool", "file_ops", KIND_INDICATOR, "shred/wipe-style secure deletion is used."),
    F("truncate_indicator", "bool", "file_ops", KIND_INDICATOR, "A file is truncated (truncate, ': >', dd)."),
    F("dd_usage", "bool", "file_ops", KIND_INDICATOR, "dd is used."),
    F("tee_usage", "bool", "file_ops", KIND_INDICATOR, "tee is used (often to write with sudo)."),
    F("symlink_creation", "bool", "file_ops", KIND_INDICATOR, "A symbolic link is created."),
    F("timestamp_modification", "bool", "file_ops", KIND_INDICATOR, "File timestamps are set explicitly (touch -t/-d/-r)."),
    F("file_write_target_count", "int", "file_ops", KIND_INDICATOR, "Distinct write targets identified."),
]


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute file-modification features for one event."""
    redirects = [(op, target) for command in ctx.parsed.commands for op, target in command.redirects
                 if target not in DISCARD_TARGETS]
    truncating = [t for op, t in redirects if op.endswith(">") and not op.endswith(">>")]
    appending = [t for op, t in redirects if op.endswith(">>")]

    rm_args = [a for e in ctx.executions_of(*DELETE_TOOLS) for a in e.args]
    rm_flags = set(rm_args) | flag_letters(rm_args)
    touch_args = [a for e in ctx.executions_of("touch") for a in e.args]
    tee_args = [a for e in ctx.executions_of("tee") for a in e.args]
    dd_args = [a for e in ctx.executions_of("dd") for a in e.args]
    inplace = any(
        a == "-i" or a.startswith("-i.") or a in ("--in-place",) or a.startswith("--in-place=")
        for e in ctx.executions_of("sed", "perl", "ruby") for a in e.args
    )
    write_targets = set(truncating) | set(appending) | {
        a.split("=", 1)[1] for a in dd_args if a.startswith("of=")
    }

    return {
        "file_write_indicator": int(bool(redirects and (truncating or appending))
                                    or ctx.uses(*WRITE_TOOLS) or inplace),
        "file_create_indicator": int(ctx.uses("touch", "mkdir", "mktemp") or bool(truncating)),
        "file_delete_indicator": int(ctx.uses(*DELETE_TOOLS)),
        "file_move_indicator": int(ctx.uses(*MOVE_TOOLS)),
        "file_copy_indicator": int(ctx.uses(*COPY_TOOLS)),
        "file_edit_indicator": int(ctx.uses(*EDIT_TOOLS)),
        "inplace_edit": int(inplace),
        "overwrite_indicator": int(bool(truncating) or any(a.startswith("of=") for a in dd_args)),
        "append_indicator": int(bool(appending) or "-a" in tee_args or "--append" in tee_args),
        "permission_change_indicator": int(ctx.uses("chmod", "setfacl", "chattr")),
        "ownership_change_indicator": int(ctx.uses("chown", "chgrp")),
        "recursive_delete": int(bool(rm_flags & {"-r", "-R", "--recursive"})),
        "force_delete": int(bool(rm_flags & {"-f", "--force"})),
        "wildcard_delete": int(bool(ctx.uses(*DELETE_TOOLS)) and any("*" in a or "?" in a for a in rm_args)),
        "secure_delete": int(ctx.uses("shred", "wipe", "srm")),
        "truncate_indicator": int(ctx.uses("truncate") or any(t and not t.startswith("/dev") for t in truncating)),
        "dd_usage": int(ctx.uses("dd")),
        "tee_usage": int(ctx.uses("tee")),
        "symlink_creation": int(ctx.uses("ln") and any(a in ("-s", "-sf", "--symbolic")
                                                       for e in ctx.executions_of("ln") for a in e.args)),
        "timestamp_modification": int(any(a in ("-t", "-d", "-r", "--date", "--reference")
                                          for a in touch_args)),
        "file_write_target_count": len({t for t in write_targets if t}),
    }
