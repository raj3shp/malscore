"""Process ancestry features (section 22 of the spec).

These depend entirely on what the telemetry source provides.  Shell history
exports have none of it; auditd and eBPF sensors have all of it.  When the
fields are missing every feature falls back to its default and
``ancestry_available`` is 0, so a model can learn to ignore them.
"""

from __future__ import annotations

from typing import Dict

from ..context import SCRIPT_INTERPRETERS, SHELLS, CommandContext
from ..schema import F, KIND_CONTEXT, KIND_INDICATOR

SSHD_PARENTS = ("sshd",)
CRON_PARENTS = ("cron", "crond", "anacron", "atd", "systemd-cron")
SYSTEMD_PARENTS = ("systemd", "init", "systemd-logind", "systemd-journald")
WEB_SERVER_PARENTS = ("nginx", "httpd", "apache2", "lighttpd", "caddy", "haproxy",
                      "php-fpm", "gunicorn", "uwsgi", "tomcat", "node")
CONTAINER_PARENTS = ("containerd-shim", "dockerd", "runc", "crio", "podman", "conmon")

FEATURES = [
    F("ancestry_available", "bool", "ancestry", KIND_CONTEXT, "The event carried parent process information."),
    F("parent_executable", "str", "ancestry", KIND_CONTEXT, "Parent process executable basename.", ""),
    F("grandparent_executable", "str", "ancestry", KIND_CONTEXT, "Grandparent process executable basename.", ""),
    F("parent_command", "str", "ancestry", KIND_CONTEXT, "Parent command line, when provided.", ""),
    F("grandparent_command", "str", "ancestry", KIND_CONTEXT, "Grandparent command line, when provided.", ""),
    F("process_depth", "int", "ancestry", KIND_CONTEXT, "Depth in the process tree, -1 when unknown.", -1),
    F("pid", "int", "ancestry", KIND_CONTEXT, "Process id, -1 when unknown.", -1),
    F("parent_pid", "int", "ancestry", KIND_CONTEXT, "Parent process id, -1 when unknown.", -1),
    F("from_shell", "bool", "ancestry", KIND_INDICATOR, "Parent process is a shell."),
    F("shell_parent", "bool", "ancestry", KIND_INDICATOR, "Alias of from_shell, kept for readability in rules."),
    F("from_sshd", "bool", "ancestry", KIND_INDICATOR, "Parent process is sshd (interactive remote session)."),
    F("from_cron", "bool", "ancestry", KIND_INDICATOR, "Parent process is a cron/at daemon."),
    F("from_systemd", "bool", "ancestry", KIND_INDICATOR, "Parent process is systemd/init."),
    F("from_web_server", "bool", "ancestry", KIND_INDICATOR, "Parent process is a web/application server."),
    F("from_container_runtime", "bool", "ancestry", KIND_INDICATOR, "Parent process belongs to a container runtime."),
    F("from_interpreter", "bool", "ancestry", KIND_INDICATOR, "Parent process is a scripting interpreter."),
    F("parent_user_mismatch", "bool", "ancestry", KIND_INDICATOR, "Parent process runs as a different user than the event."),
    F("interactive_session", "bool", "ancestry", KIND_CONTEXT, "A tty is attached to the session."),
    F("session_id", "str", "ancestry", KIND_CONTEXT, "Session identifier from telemetry.", ""),
]


def _basename(value: str) -> str:
    return value.rsplit("/", 1)[-1].lower() if value else ""


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute process-ancestry features for one event."""
    event = ctx.event
    parent = _basename(event.parent_exe)
    grandparent = _basename(event.grandparent_exe)
    available = bool(parent or grandparent or event.ppid is not None)
    tty = event.tty.lower()

    return {
        "ancestry_available": int(available),
        "parent_executable": parent,
        "grandparent_executable": grandparent,
        "parent_command": event.parent_cmdline,
        "grandparent_command": event.grandparent_cmdline,
        "process_depth": event.process_depth if event.process_depth is not None else -1,
        "pid": event.pid if event.pid is not None else -1,
        "parent_pid": event.ppid if event.ppid is not None else -1,
        "from_shell": int(parent in SHELLS),
        "shell_parent": int(parent in SHELLS),
        "from_sshd": int(parent in SSHD_PARENTS or grandparent in SSHD_PARENTS),
        "from_cron": int(parent in CRON_PARENTS or grandparent in CRON_PARENTS),
        "from_systemd": int(parent in SYSTEMD_PARENTS),
        "from_web_server": int(parent in WEB_SERVER_PARENTS or grandparent in WEB_SERVER_PARENTS),
        "from_container_runtime": int(parent in CONTAINER_PARENTS or grandparent in CONTAINER_PARENTS),
        "from_interpreter": int(parent in SCRIPT_INTERPRETERS),
        "parent_user_mismatch": int(bool(event.parent_user) and bool(event.user)
                                    and event.parent_user != event.user),
        "interactive_session": int(bool(tty) and tty not in ("none", "(none)", "?", "cron")),
        "session_id": event.session_id,
    }
