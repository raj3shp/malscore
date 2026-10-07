"""Privilege and account-management features (section 11 of the spec)."""

from __future__ import annotations

from typing import Dict

from ..context import SHELLS, CommandContext, flag_letters
from ..schema import F, KIND_CONTEXT, KIND_INDICATOR, KIND_STRUCTURAL

ESCALATION_TOOLS = ("sudo", "su", "doas", "pkexec", "runuser", "sudoedit", "gosu", "setpriv")
USER_TOOLS = ("useradd", "adduser", "usermod", "userdel", "deluser", "chage", "passwd", "newusers")
GROUP_TOOLS = ("groupadd", "groupmod", "groupdel", "gpasswd", "addgroup", "delgroup", "newgrp")
PERMISSION_TOOLS = ("chmod", "setfacl", "umask", "chattr")
OWNERSHIP_TOOLS = ("chown", "chgrp")
CAPABILITY_TOOLS = ("setcap", "getcap", "capsh", "filecap")

FEATURES = [
    F("privilege_tool_used", "bool", "privilege", KIND_INDICATOR, "A privilege-escalation tool is used."),
    F("uses_sudo", "bool", "privilege", KIND_INDICATOR, "sudo is used (as wrapper or as the command)."),
    F("sudo_count", "int", "privilege", KIND_INDICATOR, "sudo invocations in the command line."),
    F("sudo_target_user", "str", "privilege", KIND_INDICATOR, "Value of sudo's -u option.", ""),
    F("sudo_to_other_user", "bool", "privilege", KIND_INDICATOR, "sudo runs as a named non-root account."),
    F("sudo_shell", "bool", "privilege", KIND_INDICATOR, "sudo/su is used to obtain an interactive shell."),
    F("sudo_list_permissions", "bool", "privilege", KIND_INDICATOR, "'sudo -l' enumerates sudo rights."),
    F("sudo_preserve_env", "bool", "privilege", KIND_INDICATOR, "sudo -E / --preserve-env is used."),
    F("sudo_non_interactive", "bool", "privilege", KIND_INDICATOR, "sudo -n (no password prompt) is used."),
    F("uses_su", "bool", "privilege", KIND_INDICATOR, "su is used."),
    F("uses_doas", "bool", "privilege", KIND_INDICATOR, "doas is used."),
    F("uses_pkexec", "bool", "privilege", KIND_INDICATOR, "pkexec is used."),
    F("privilege_change_indicator", "bool", "privilege", KIND_INDICATOR, "The command changes the effective account or its rights."),
    F("user_management", "bool", "privilege", KIND_INDICATOR, "A user account tool is used."),
    F("group_management", "bool", "privilege", KIND_INDICATOR, "A group management tool is used."),
    F("password_change_tool", "bool", "privilege", KIND_INDICATOR, "passwd/chage-style credential tool is used."),
    F("permission_change", "bool", "privilege", KIND_INDICATOR, "File permissions are changed."),
    F("ownership_change", "bool", "privilege", KIND_INDICATOR, "File ownership is changed."),
    F("capability_change", "bool", "privilege", KIND_INDICATOR, "Linux capabilities are read or set."),
    F("setuid_related", "bool", "privilege", KIND_INDICATOR, "A setuid/setgid bit is referenced (chmod u+s, 4755, find -perm)."),
    F("chmod_world_writable", "bool", "privilege", KIND_INDICATOR, "chmod grants world-write (777/666/o+w)."),
    F("chmod_executable_bit", "bool", "privilege", KIND_INDICATOR, "chmod grants an execute bit."),
    F("chmod_recursive", "bool", "privilege", KIND_INDICATOR, "chmod/chown applied recursively."),
    F("uid", "int", "privilege", KIND_CONTEXT, "Real uid from telemetry, -1 when absent.", -1),
    F("euid", "int", "privilege", KIND_CONTEXT, "Effective uid, -1 when absent.", -1),
    F("gid", "int", "privilege", KIND_CONTEXT, "Real gid, -1 when absent.", -1),
    F("egid", "int", "privilege", KIND_CONTEXT, "Effective gid, -1 when absent.", -1),
    F("uid_euid_mismatch", "bool", "privilege", KIND_INDICATOR, "uid and euid differ (setuid execution)."),
    F("gid_egid_mismatch", "bool", "privilege", KIND_INDICATOR, "gid and egid differ."),
    F("runs_as_root", "bool", "privilege", KIND_CONTEXT, "Effective uid is 0."),
    F("identity_fields_available", "bool", "privilege", KIND_CONTEXT, "The event carried uid/euid information."),
]

SETUID_TOKENS = ("u+s", "g+s", "+s", "4755", "4777", "2755", "6755", "-perm -4000", "-perm -u=s")
WORLD_WRITABLE_TOKENS = ("777", "666", "o+w", "a+w", "a=rwx")


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute privilege features for one event."""
    event = ctx.event
    lower = ctx.lower
    sudo_executions = [e for e in ctx.executions if e.basename == "sudo"]
    sudo_wrappers = sum(e.wrappers.count("sudo") for e in ctx.executions)
    sudo_count = len(sudo_executions) + sudo_wrappers

    sudo_target = ""
    for execution in ctx.executions:
        if execution.basename == "sudo":
            args = execution.argv
        elif "sudo" in execution.wrappers and execution.command is not None:
            # only the wrapper prefix: 'sudo -u svc useradd -u 0' targets svc, not 0
            args = execution.command.argv[:len(execution.command.argv) - len(execution.argv)]
        else:
            continue
        for index, token in enumerate(args):
            if token in ("-u", "--user") and index + 1 < len(args):
                sudo_target = args[index + 1]
            elif token.startswith("--user="):
                sudo_target = token.split("=", 1)[1]

    chmod_args = " ".join(a for e in ctx.executions_of("chmod", "find", "install") for a in e.args)
    chown_args = [a for e in ctx.executions_of("chmod", "chown", "chgrp") for a in e.args]
    chown_recursive = bool((set(chown_args) | flag_letters(chown_args)) & {"-R", "--recursive"})
    shell_via_escalation = False
    for execution in ctx.executions:
        if execution.basename in SHELLS and ({"sudo", "doas"} & set(execution.wrappers)):
            shell_via_escalation = True
        if execution.basename == "su" and not execution.args:
            shell_via_escalation = True
        if execution.basename == "su" and all(a.startswith("-") or a.isalnum() for a in execution.args):
            shell_via_escalation = True
    if ctx.uses("sudo") and any(e.basename in SHELLS for e in ctx.executions if e.wrappers):
        shell_via_escalation = True

    uid, euid = event.uid, event.euid
    gid, egid = event.gid, event.egid

    return {
        "privilege_tool_used": int(ctx.uses(*ESCALATION_TOOLS) or ctx.any_wrapper("sudo", "doas")),
        "uses_sudo": int(sudo_count > 0),
        "sudo_count": sudo_count,
        "sudo_target_user": sudo_target,
        "sudo_to_other_user": int(bool(sudo_target) and sudo_target != "root"),
        "sudo_shell": int(shell_via_escalation),
        "sudo_list_permissions": int(any("-l" in e.args or "--list" in e.args for e in sudo_executions)),
        "sudo_preserve_env": int(any(a in ("-E", "--preserve-env") or a.startswith("--preserve-env=")
                                     for e in ctx.executions for a in e.argv)),
        "sudo_non_interactive": int(any(a in ("-n", "--non-interactive")
                                        for e in sudo_executions for a in e.argv)),
        "uses_su": int(ctx.uses("su", "runuser")),
        "uses_doas": int(ctx.uses("doas")),
        "uses_pkexec": int(ctx.uses("pkexec")),
        "privilege_change_indicator": int(
            ctx.uses(*ESCALATION_TOOLS) or ctx.uses(*PERMISSION_TOOLS) or ctx.uses(*OWNERSHIP_TOOLS)
            or ctx.uses(*CAPABILITY_TOOLS) or ctx.uses(*USER_TOOLS) or ctx.uses(*GROUP_TOOLS)
            or ctx.any_wrapper("sudo", "doas")
        ),
        "user_management": int(ctx.uses(*USER_TOOLS)),
        "group_management": int(ctx.uses(*GROUP_TOOLS)),
        "password_change_tool": int(ctx.uses("passwd", "chage", "gpasswd", "chpasswd")),
        "permission_change": int(ctx.uses(*PERMISSION_TOOLS)),
        "ownership_change": int(ctx.uses(*OWNERSHIP_TOOLS)),
        "capability_change": int(ctx.uses(*CAPABILITY_TOOLS)),
        "setuid_related": int(any(token in chmod_args or token in lower for token in SETUID_TOKENS)),
        "chmod_world_writable": int(
            ctx.uses("chmod") and any(token in chmod_args for token in WORLD_WRITABLE_TOKENS)
        ),
        "chmod_executable_bit": int(ctx.uses("chmod") and ("+x" in chmod_args or "755" in chmod_args
                                                           or "775" in chmod_args or "777" in chmod_args)),
        "chmod_recursive": int(chown_recursive),
        "uid": uid if uid is not None else -1,
        "euid": euid if euid is not None else -1,
        "gid": gid if gid is not None else -1,
        "egid": egid if egid is not None else -1,
        "uid_euid_mismatch": int(uid is not None and euid is not None and uid != euid),
        "gid_egid_mismatch": int(gid is not None and egid is not None and gid != egid),
        "runs_as_root": int((euid if euid is not None else uid) == 0),
        "identity_fields_available": int(uid is not None or euid is not None),
    }
