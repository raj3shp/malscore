"""Persistence-mechanism features (section 10 of the spec).

Interacting with cron, systemd, shell startup files or authorized_keys is
completely routine for administrators.  These features record *which*
persistence surface a command touches and whether it looks like a read or a
write, so that later stages can ask "is this normal for this user?".
"""

from __future__ import annotations

from typing import Dict, Sequence, Tuple

from ..context import CommandContext
from ..schema import F, KIND_INDICATOR

CRON_PATHS = ("/etc/cron", "/etc/crontab", "/var/spool/cron", "/etc/cron.d",
              "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly")
SYSTEMD_PATHS = ("/etc/systemd", "/lib/systemd", "/usr/lib/systemd", "~/.config/systemd",
                 "/run/systemd/system")
SSH_PERSIST_BASENAMES = ("authorized_keys", "authorized_keys2", "known_hosts")
SHELL_STARTUP_BASENAMES = (".bashrc", ".bash_profile", ".bash_login", ".profile",
                           ".zshrc", ".zprofile", ".kshrc", ".cshrc", ".bash_logout")
SHELL_STARTUP_PATHS = ("/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/zsh")
INIT_PATHS = ("/etc/rc.local", "/etc/init.d", "/etc/rc.d", "/etc/inittab")
PRELOAD_PATHS = ("/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d")
UDEV_PATHS = ("/etc/udev", "/lib/udev", "/usr/lib/udev")
PAM_PATHS = ("/etc/pam.d", "/etc/pam.conf", "/etc/security")
SUDO_PATHS = ("/etc/sudoers", "/etc/sudoers.d")
MODULE_PATHS = ("/etc/modules", "/etc/modules-load.d", "/etc/modprobe.d")
AUTOSTART_PATHS = ("~/.config/autostart", "/etc/xdg/autostart")

WRITE_TOOLS = ("tee", "cp", "mv", "install", "touch", "truncate", "dd", "sed", "vi", "vim",
               "nano", "emacs", "ed", "patch", "ln")

FEATURES = [
    F("persistence_indicator", "bool", "persistence", KIND_INDICATOR, "The command touches any persistence surface."),
    F("persistence_indicator_count", "int", "persistence", KIND_INDICATOR, "Number of distinct persistence surfaces touched."),
    F("cron_persistence", "bool", "persistence", KIND_INDICATOR, "crontab command or a cron path is referenced."),
    F("crontab_edit", "bool", "persistence", KIND_INDICATOR, "'crontab -e' / 'crontab <file>' installs a crontab."),
    F("crontab_list", "bool", "persistence", KIND_INDICATOR, "'crontab -l' lists a crontab."),
    F("systemd_persistence", "bool", "persistence", KIND_INDICATOR, "systemctl or a systemd unit path is referenced."),
    F("systemd_unit_write", "bool", "persistence", KIND_INDICATOR, "A systemd unit file is written or edited."),
    F("service_enable", "bool", "persistence", KIND_INDICATOR, "'systemctl enable' (or chkconfig/update-rc.d) is used."),
    F("daemon_reload", "bool", "persistence", KIND_INDICATOR, "'systemctl daemon-reload' is used."),
    F("ssh_persistence", "bool", "persistence", KIND_INDICATOR, "authorized_keys / known_hosts are referenced."),
    F("authorized_keys_write", "bool", "persistence", KIND_INDICATOR, "authorized_keys is written to or appended to."),
    F("shell_startup_persistence", "bool", "persistence", KIND_INDICATOR, "A shell startup file is referenced."),
    F("shell_startup_write", "bool", "persistence", KIND_INDICATOR, "A shell startup file is written or appended to."),
    F("init_script_persistence", "bool", "persistence", KIND_INDICATOR, "rc.local or an init script is referenced."),
    F("preload_persistence", "bool", "persistence", KIND_INDICATOR, "ld.so.preload / ld.so.conf is referenced."),
    F("udev_persistence", "bool", "persistence", KIND_INDICATOR, "A udev rules path is referenced."),
    F("pam_configuration", "bool", "persistence", KIND_INDICATOR, "PAM configuration is referenced."),
    F("sudo_configuration", "bool", "persistence", KIND_INDICATOR, "sudoers configuration is referenced."),
    F("module_persistence", "bool", "persistence", KIND_INDICATOR, "Kernel module auto-load configuration is referenced."),
    F("autostart_persistence", "bool", "persistence", KIND_INDICATOR, "A desktop autostart path is referenced."),
    F("at_job_persistence", "bool", "persistence", KIND_INDICATOR, "'at'/'batch' scheduling is used."),
    F("timer_persistence", "bool", "persistence", KIND_INDICATOR, "A systemd timer unit is referenced."),
]


def _touches(ctx: CommandContext, prefixes: Sequence[str]) -> bool:
    return bool(ctx.path_matches(*[p.lower() for p in prefixes]))


def _writes_to(ctx: CommandContext, prefixes: Sequence[str] = (), basenames: Sequence[str] = ()) -> bool:
    """Heuristic: is one of these paths a write target rather than just a read?"""
    lowered_prefixes = [p.lower() for p in prefixes]
    for command in ctx.parsed.commands:
        for op, target in command.redirects:
            if not target:
                continue
            low = target.lower()
            if any(low.startswith(p) for p in lowered_prefixes) or \
                    target.rsplit("/", 1)[-1].lower() in basenames:
                if ">" in op:
                    return True
    if ctx.uses(*WRITE_TOOLS):
        if _touches(ctx, prefixes) or (basenames and ctx.basename_matches(*basenames)):
            return True
    return False


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute persistence-surface features for one event."""
    crontab = ctx.executions_of("crontab")
    systemctl = ctx.executions_of("systemctl", "service", "chkconfig", "update-rc.d")
    systemctl_args = [a for e in systemctl for a in e.args]

    cron = bool(crontab) or _touches(ctx, CRON_PATHS)
    systemd = bool(systemctl) or _touches(ctx, SYSTEMD_PATHS)
    ssh_persist = bool(ctx.basename_matches(*SSH_PERSIST_BASENAMES))
    shell_startup = bool(ctx.basename_matches(*SHELL_STARTUP_BASENAMES)) or _touches(ctx, SHELL_STARTUP_PATHS)
    init_script = _touches(ctx, INIT_PATHS)
    preload = _touches(ctx, PRELOAD_PATHS)
    udev = _touches(ctx, UDEV_PATHS)
    pam = _touches(ctx, PAM_PATHS)
    sudoers = _touches(ctx, SUDO_PATHS) or ctx.uses("visudo")
    modules = _touches(ctx, MODULE_PATHS)
    autostart = _touches(ctx, AUTOSTART_PATHS)
    at_job = ctx.uses("at", "batch", "atq", "atrm")
    timer = any(p.raw.endswith(".timer") for p in ctx.paths) or "timer" in " ".join(systemctl_args)

    surfaces = [cron, systemd, ssh_persist, shell_startup, init_script, preload, udev,
                pam, sudoers, modules, autostart, at_job]

    return {
        "persistence_indicator": int(any(surfaces)),
        "persistence_indicator_count": sum(int(bool(s)) for s in surfaces),
        "cron_persistence": int(cron),
        "crontab_edit": int(any(("-e" in e.args) or (e.positionals and "-l" not in e.args)
                                for e in crontab)),
        "crontab_list": int(any("-l" in e.args for e in crontab)),
        "systemd_persistence": int(systemd),
        "systemd_unit_write": int(_writes_to(ctx, SYSTEMD_PATHS)
                                  or any(p.raw.endswith((".service", ".timer", ".socket"))
                                         and p.from_redirect for p in ctx.paths)),
        "service_enable": int(any(a in ("enable", "--now") for a in systemctl_args)
                              or ctx.uses("chkconfig", "update-rc.d")),
        "daemon_reload": int("daemon-reload" in systemctl_args or "daemon-reexec" in systemctl_args),
        "ssh_persistence": int(ssh_persist),
        "authorized_keys_write": int(_writes_to(ctx, basenames=("authorized_keys", "authorized_keys2"))),
        "shell_startup_persistence": int(shell_startup),
        "shell_startup_write": int(_writes_to(ctx, SHELL_STARTUP_PATHS, SHELL_STARTUP_BASENAMES)),
        "init_script_persistence": int(init_script),
        "preload_persistence": int(preload),
        "udev_persistence": int(udev),
        "pam_configuration": int(pam),
        "sudo_configuration": int(sudoers),
        "module_persistence": int(modules),
        "autostart_persistence": int(autostart),
        "at_job_persistence": int(at_job),
        "timer_persistence": int(bool(timer)),
    }
