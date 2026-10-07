"""Filesystem path features (section 9 of the spec).

Paths are classified by prefix into behavioural categories (temporary,
credential, persistence, system configuration, ...).  A path being "sensitive"
says something about *what the command touches*, never that the command is bad:
sysadmins read ``/etc/shadow`` metadata and back up ``/root`` legitimately.
"""

from __future__ import annotations

from typing import Dict, List, Sequence, Tuple

from ..context import CommandContext
from ..schema import F, KIND_INDICATOR, KIND_STRUCTURAL
from ..textutil import PathRef

#: prefix -> category.  Matching is done on lower-cased paths, longest first.
PATH_CLASSES: Dict[str, Tuple[str, ...]] = {
    "temporary": ("/tmp", "/var/tmp", "/dev/shm"),
    "credential": ("/etc/shadow", "/etc/passwd", "/etc/gshadow", "/etc/security/opasswd",
                   "~/.ssh", "~/.aws", "~/.kube", "~/.docker/config.json", "~/.netrc",
                   "~/.git-credentials", "~/.pgpass"),
    "ssh": ("~/.ssh", "/etc/ssh", "/root/.ssh"),
    "persistence": ("/etc/cron", "/var/spool/cron", "/etc/systemd", "/lib/systemd",
                    "/usr/lib/systemd", "~/.config/systemd", "/etc/rc.local", "/etc/init.d",
                    "/etc/profile", "/etc/profile.d", "/etc/ld.so.preload", "/etc/ld.so.conf",
                    "/etc/udev", "/etc/pam.d", "/etc/sudoers", "/etc/sudoers.d",
                    "/etc/modules", "/etc/modprobe.d", "/etc/rc.d", "/etc/xdg/autostart"),
    "system_configuration": ("/etc",),
    "log": ("/var/log", "/var/adm"),
    "proc": ("/proc",),
    "sys": ("/sys",),
    "device": ("/dev",),
    "boot": ("/boot",),
    "binary": ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt"),
    "spool": ("/var/spool",),
    "var_lib": ("/var/lib",),
    "root_home": ("/root",),
    "home": ("/home", "~"),
}

#: Exact files / basenames that get their own boolean.
NAMED_PATHS = {
    "touches_passwd": ("/etc/passwd",),
    "touches_shadow": ("/etc/shadow", "/etc/gshadow"),
    "touches_group_file": ("/etc/group",),
    "touches_sudoers": ("/etc/sudoers", "/etc/sudoers.d"),
    "touches_ssh_config": ("/etc/ssh", "~/.ssh/config", "/root/.ssh/config"),
    "touches_ld_preload": ("/etc/ld.so.preload", "/etc/ld.so.conf"),
    "touches_crontab_path": ("/etc/crontab", "/etc/cron", "/var/spool/cron"),
    "touches_systemd_path": ("/etc/systemd", "/lib/systemd", "/usr/lib/systemd", "~/.config/systemd"),
}
NAMED_BASENAMES = {
    "touches_authorized_keys": ("authorized_keys", "authorized_keys2"),
    "touches_known_hosts": ("known_hosts",),
    "touches_shell_rc": (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile",
                         ".bash_login", ".bash_logout", ".kshrc", ".cshrc"),
    "touches_private_key": ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "server.key"),
}

SENSITIVE_CATEGORIES = ("credential", "ssh", "persistence", "system_configuration",
                        "proc", "sys", "boot", "root_home")
EXECUTABLE_EXTENSIONS = frozenset({"bin", "elf", "so", "ko", "run", "out", "appimage", "exe"})
SCRIPT_EXTENSIONS = frozenset({"sh", "bash", "zsh", "ksh", "py", "pl", "rb", "php",
                               "js", "lua", "awk", "exp", "ps1", "r"})

_COUNT_FEATURES = [
    ("path_count", "Filesystem paths referenced."),
    ("absolute_path_count", "Absolute paths."),
    ("relative_path_count", "Relative paths."),
    ("sensitive_path_count", "Paths in a sensitive category (credential, ssh, persistence, system config, proc, sys, boot, root)."),
    ("temporary_path_count", "Paths under /tmp, /var/tmp or /dev/shm."),
    ("credential_path_count", "Paths that hold credentials or key material."),
    ("ssh_path_count", "SSH configuration or key paths."),
    ("persistence_path_count", "Paths used by persistence mechanisms."),
    ("system_configuration_path_count", "Paths under /etc."),
    ("log_path_count", "Paths under /var/log."),
    ("proc_path_count", "Paths under /proc."),
    ("sys_path_count", "Paths under /sys."),
    ("device_path_count", "Paths under /dev."),
    ("boot_path_count", "Paths under /boot."),
    ("binary_path_count", "Paths under system binary directories."),
    ("spool_path_count", "Paths under /var/spool."),
    ("var_lib_path_count", "Paths under /var/lib."),
    ("home_path_count", "Paths under a home directory."),
    ("root_home_path_count", "Paths under /root."),
    ("redirect_target_count", "Paths that are redirection targets."),
    ("hidden_file_count", "Dot-files referenced."),
]

FEATURES = (
    [F(name, "int", "paths", KIND_STRUCTURAL, desc) for name, desc in _COUNT_FEATURES]
    + [
        F("max_path_depth", "int", "paths", KIND_STRUCTURAL, "Deepest path referenced (component count)."),
        F("mean_path_depth", "float", "paths", KIND_STRUCTURAL, "Mean path depth.", 0.0),
        F("file_extension", "str", "paths", KIND_STRUCTURAL, "Extension of the first path with one.", ""),
        F("has_hidden_file", "bool", "paths", KIND_STRUCTURAL, "A dot-file is referenced."),
        F("has_executable_extension", "bool", "paths", KIND_STRUCTURAL, "A binary-looking extension is referenced."),
        F("has_script_extension", "bool", "paths", KIND_STRUCTURAL, "A script extension is referenced."),
        F("touches_tmp", "bool", "paths", KIND_INDICATOR, "Touches a temporary directory."),
        F("touches_dev_shm", "bool", "paths", KIND_INDICATOR, "Touches /dev/shm."),
        F("touches_etc", "bool", "paths", KIND_INDICATOR, "Touches /etc."),
        F("touches_var_log", "bool", "paths", KIND_INDICATOR, "Touches /var/log."),
        F("touches_proc", "bool", "paths", KIND_INDICATOR, "Touches /proc."),
        F("touches_sys", "bool", "paths", KIND_INDICATOR, "Touches /sys."),
        F("touches_dev", "bool", "paths", KIND_INDICATOR, "Touches /dev."),
        F("touches_boot", "bool", "paths", KIND_INDICATOR, "Touches /boot."),
        F("touches_root_home", "bool", "paths", KIND_INDICATOR, "Touches /root."),
        F("touches_home", "bool", "paths", KIND_INDICATOR, "Touches a home directory."),
        F("touches_sensitive_path", "bool", "paths", KIND_INDICATOR, "Touches any sensitive-category path."),
    ]
    + [F(name, "bool", "paths", KIND_INDICATOR, "Touches %s." % " / ".join(values))
       for name, values in NAMED_PATHS.items()]
    + [F(name, "bool", "paths", KIND_INDICATOR, "References %s." % " / ".join(values))
       for name, values in NAMED_BASENAMES.items()]
)


def _expand_home(path: str) -> str:
    """Map ``/home/<user>/x`` and ``$HOME/x`` onto the ``~/x`` form used above."""
    lowered = path.lower()
    if lowered.startswith("${home}"):
        return "~" + lowered[7:]
    if lowered.startswith("$home"):
        return "~" + lowered[5:]
    if lowered.startswith("/home/"):
        rest = lowered.split("/", 3)
        return "~/" + rest[3] if len(rest) > 3 else "~"
    if lowered.startswith("/root/"):
        return "~" + lowered[5:]
    return lowered


def classify(path: PathRef) -> List[str]:
    """Return the categories a path belongs to."""
    candidates = {path.lowered, _expand_home(path.raw)}
    categories: List[str] = []
    for category, prefixes in PATH_CLASSES.items():
        for prefix in prefixes:
            for candidate in candidates:
                if candidate == prefix or candidate.startswith(prefix.rstrip("/") + "/") \
                        or candidate == prefix.rstrip("/"):
                    categories.append(category)
                    break
            else:
                continue
            break
    return categories


def _matches_named(paths: Sequence[PathRef], prefixes: Sequence[str]) -> bool:
    for path in paths:
        candidates = {path.lowered, _expand_home(path.raw)}
        for prefix in prefixes:
            for candidate in candidates:
                if candidate == prefix or candidate.startswith(prefix.rstrip("/") + "/"):
                    return True
    return False


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute path features for one event."""
    paths = ctx.paths
    counts = {category: 0 for category in PATH_CLASSES}
    for path in paths:
        for category in classify(path):
            counts[category] += 1

    depths = [p.depth for p in paths]
    extensions = [p.extension for p in paths if p.extension]
    sensitive = sum(counts[c] for c in SENSITIVE_CATEGORIES)

    features: Dict[str, object] = {
        "path_count": len(paths),
        "absolute_path_count": sum(1 for p in paths if p.absolute),
        "relative_path_count": sum(1 for p in paths if not p.absolute),
        "sensitive_path_count": sensitive,
        "temporary_path_count": counts["temporary"],
        "credential_path_count": counts["credential"],
        "ssh_path_count": counts["ssh"],
        "persistence_path_count": counts["persistence"],
        "system_configuration_path_count": counts["system_configuration"],
        "log_path_count": counts["log"],
        "proc_path_count": counts["proc"],
        "sys_path_count": counts["sys"],
        "device_path_count": counts["device"],
        "boot_path_count": counts["boot"],
        "binary_path_count": counts["binary"],
        "spool_path_count": counts["spool"],
        "var_lib_path_count": counts["var_lib"],
        "home_path_count": counts["home"],
        "root_home_path_count": counts["root_home"],
        "redirect_target_count": sum(1 for p in paths if p.from_redirect),
        "hidden_file_count": sum(1 for p in paths if p.hidden),
        "max_path_depth": max(depths) if depths else 0,
        "mean_path_depth": round(sum(depths) / len(depths), 3) if depths else 0.0,
        "file_extension": extensions[0] if extensions else "",
        "has_hidden_file": int(any(p.hidden for p in paths)),
        "has_executable_extension": int(any(e in EXECUTABLE_EXTENSIONS for e in extensions)),
        "has_script_extension": int(any(e in SCRIPT_EXTENSIONS for e in extensions)),
        "touches_tmp": int(counts["temporary"] > 0),
        "touches_dev_shm": int(any(p.lowered.startswith("/dev/shm") for p in paths)),
        "touches_etc": int(counts["system_configuration"] > 0),
        "touches_var_log": int(counts["log"] > 0),
        "touches_proc": int(counts["proc"] > 0),
        "touches_sys": int(counts["sys"] > 0),
        "touches_dev": int(counts["device"] > 0),
        "touches_boot": int(counts["boot"] > 0),
        "touches_root_home": int(counts["root_home"] > 0),
        "touches_home": int(counts["home"] > 0),
        "touches_sensitive_path": int(sensitive > 0),
    }
    for name, prefixes in NAMED_PATHS.items():
        features[name] = int(_matches_named(paths, prefixes))
    basenames = {p.basename.lower() for p in paths}
    for name, wanted in NAMED_BASENAMES.items():
        features[name] = int(bool(basenames & set(wanted)))
    return features
