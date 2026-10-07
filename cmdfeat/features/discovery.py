"""Discovery / situational-awareness features (section 15 of the spec).

Every one of these commands is something an ordinary user runs daily.  The
value is in the *category mix*: a burst of identity + host + network discovery
from an account that normally only runs ``git`` is interesting; the same
commands from an administrator are their job.
"""

from __future__ import annotations

from typing import Dict, Tuple

from ..context import CommandContext
from ..schema import F, KIND_INDICATOR, KIND_STRUCTURAL

CATEGORIES: Dict[str, Tuple[str, ...]] = {
    "identity_discovery": ("whoami", "id", "groups", "logname", "who", "w", "users", "last", "lastlog"),
    "host_discovery": ("uname", "hostname", "hostnamectl", "uptime", "lsb_release", "dmidecode",
                       "timedatectl", "localectl", "arch"),
    "process_discovery": ("ps", "top", "htop", "pgrep", "pstree", "pidof", "lsof", "fuser"),
    "network_discovery": ("ip", "ifconfig", "ss", "netstat", "route", "arp", "resolvectl",
                          "iptables", "nft", "firewall-cmd", "traceroute", "ping", "dig",
                          "nslookup", "host", "nmap"),
    "filesystem_discovery": ("ls", "find", "locate", "tree", "du", "df", "stat", "file",
                             "readlink", "realpath", "mount", "lsblk", "blkid"),
    "hardware_discovery": ("lscpu", "lsusb", "lspci", "lsblk", "lshw", "free", "nproc",
                           "sensors", "nvidia-smi", "dmidecode"),
    "service_discovery": ("systemctl", "service", "journalctl", "chkconfig", "initctl",
                          "supervisorctl", "rc-status"),
    "environment_discovery": ("env", "printenv", "set", "export", "history", "pwd", "which",
                              "whereis", "type", "command", "alias", "ulimit", "locale"),
    "credential_discovery": ("getent", "passwd", "vault", "aws", "gcloud", "az", "kubectl", "keyctl"),
}
#: getent/passwd only count as credential discovery with these arguments.
CREDENTIAL_ARG_HINTS = ("passwd", "shadow", "secret", "credential", "token", "key", "login")

FEATURES = [
    F(name, "bool", "discovery", KIND_INDICATOR, "Uses a %s tool." % name.replace("_", " "))
    for name in CATEGORIES
] + [
    F("discovery_category_count", "int", "discovery", KIND_INDICATOR, "Distinct discovery categories in one command line."),
    F("discovery_tool_count", "int", "discovery", KIND_STRUCTURAL, "Discovery tool executions."),
    F("is_pure_discovery", "bool", "discovery", KIND_INDICATOR, "Every execution in the line is a discovery tool."),
    F("history_inspection", "bool", "discovery", KIND_INDICATOR, "Shell history is read or manipulated."),
    F("history_cleared", "bool", "discovery", KIND_INDICATOR, "'history -c' or HISTFILE tampering is present."),
]


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute discovery-category features for one event."""
    features: Dict[str, object] = {}
    hit_categories = 0
    tool_hits = 0
    for name, tools in CATEGORIES.items():
        hit = ctx.uses(*tools)
        if name == "credential_discovery" and hit:
            hit = any(
                any(hint in a.lower() for hint in CREDENTIAL_ARG_HINTS)
                for e in ctx.executions_of(*tools) for a in e.args
            )
        features[name] = int(hit)
        hit_categories += int(bool(hit))
        tool_hits += ctx.count_uses(*tools)

    all_discovery_tools = {tool for tools in CATEGORIES.values() for tool in tools}
    executions = ctx.executions
    history_text = ctx.lower
    return dict(
        features,
        discovery_category_count=hit_categories,
        discovery_tool_count=tool_hits,
        is_pure_discovery=int(bool(executions) and all(e.basename in all_discovery_tools for e in executions)),
        history_inspection=int(ctx.uses("history") or "histfile" in history_text
                               or any(p.basename in (".bash_history", ".zsh_history") for p in ctx.paths)),
        history_cleared=int(
            "history -c" in history_text or "unset histfile" in history_text
            or "histfile=/dev/null" in history_text.replace(" ", "")
            or any(p.basename in (".bash_history", ".zsh_history") and p.from_redirect for p in ctx.paths)
            or (ctx.uses("rm", "shred", "truncate")
                and any(p.basename in (".bash_history", ".zsh_history") for p in ctx.paths))
        ),
    )
