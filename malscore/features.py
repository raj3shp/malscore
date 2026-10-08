"""Feature extraction: one command line in, a flat record of observations out.

Each group function (``chains``, ``network``, ``tradecraft``, ...) takes a
:class:`~malscore.context.CommandContext` and returns named features.  A feature
is an observation ("a ``/dev/tcp`` redirection is present", "a download is
piped into a shell"), never a verdict -- weighing observations is the job of
:mod:`malscore.signals`.  Only features that some signal or the script analysis
reads are computed.

Nothing here executes, expands or resolves anything.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .context import (
    INTERPRETERS,
    SHELLS,
    CommandContext,
    Execution,
    PathRef,
    build_context,
    flag_letters,
    resolve_execution,
)
from .lexer import SimpleCommand, tokenize

Record = Dict[str, object]

#: Longer command lines are truncated before analysis.
MAX_COMMAND_LENGTH = 8192

TEMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
#: Redirect targets that discard or pass through output rather than write a file.
DISCARD_TARGETS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"})


# --------------------------------------------------------------------------
# download / execute chains
# --------------------------------------------------------------------------
RETRIEVAL_TOOLS = frozenset({"curl", "wget", "aria2c", "axel", "fetch", "tftp",
                             "nc", "ncat", "netcat", "socat", "scp", "rsync", "sftp", "lftp"})
OUTPUT_FLAGS = frozenset({"-o", "--output", "--output-dir"})
WGET_DIR_FLAGS = frozenset({"-P", "--directory-prefix"})
CHAIN_FLAGS = ("download_then_execute", "network_to_shell_pipeline", "network_to_interpreter_pipeline",
               "download_to_tmp", "downloaded_file_executed", "chmod_following_download")


def _is_retrieval(execution: Execution) -> bool:
    """True when this stage pulls remote content onto this host."""
    if execution.basename not in RETRIEVAL_TOOLS:
        return False
    if execution.basename in ("scp", "rsync", "sftp", "lftp"):
        positionals = execution.positionals
        return bool(positionals) and (":" in positionals[0] or "@" in positionals[0])
    return True


def _output_path(execution: Execution) -> Optional[str]:
    """Where a retrieval tool writes its result, if it can be determined."""
    args = execution.args
    base = execution.basename
    for index, token in enumerate(args):
        if token in OUTPUT_FLAGS and index + 1 < len(args):
            return args[index + 1]
        if token.startswith("--output="):
            return token.split("=", 1)[1]
        if base == "wget" and token == "-O" and index + 1 < len(args):
            return args[index + 1]
        if base == "wget" and token in WGET_DIR_FLAGS and index + 1 < len(args):
            return args[index + 1].rstrip("/") + "/"
    if execution.command is not None:
        for op, target in execution.command.redirects:
            if op.endswith(">"):
                return target
    if base == "curl" and any(t in ("-O", "--remote-name") for t in args):
        return "./"
    if base in ("scp", "rsync", "sftp") and len(execution.positionals) >= 2:
        # only a remote -> local copy retrieves anything; an upload's last
        # positional is the destination, not something fetched to this host
        source = execution.positionals[0]
        if ":" in source or "@" in source:
            return execution.positionals[-1]
    return None


def _chain_group(commands: Sequence[SimpleCommand]) -> Record:
    """Chain analysis for one ordered group of simple commands."""
    result: Record = dict.fromkeys(CHAIN_FLAGS, 0)
    result["download_output_path"] = ""
    resolved = [(command, resolve_execution(command)) for command in commands]

    for index, (command, execution) in enumerate(resolved):
        if execution is None or not _is_retrieval(execution):
            continue
        output = _output_path(execution)
        if output:
            if not result["download_output_path"]:
                result["download_output_path"] = output
            if output.lower().startswith(TEMP_DIRS):
                result["download_to_tmp"] = 1

        for later_command, later in resolved[index + 1:]:
            if later is None:
                continue
            base = later.basename
            same_pipeline = (later_command.pipeline_id == command.pipeline_id
                             and later_command.pipeline_index > command.pipeline_index)
            if same_pipeline and base in SHELLS:
                result["network_to_shell_pipeline"] = 1
                result["download_then_execute"] = 1
            elif same_pipeline and base in INTERPRETERS:
                result["network_to_interpreter_pipeline"] = 1
                result["download_then_execute"] = 1
            if base == "chmod":
                result["chmod_following_download"] = 1
                if output and any(output.rstrip("/") in arg for arg in later.args):
                    result["download_then_execute"] = 1
            if output:
                target = output.rstrip("/")
                names = {target, target.lstrip("./"), "./" + target.lstrip("./")}
                if later.name in names or (base in INTERPRETERS and any(a in names for a in later.args)):
                    result["downloaded_file_executed"] = 1
                    result["download_then_execute"] = 1
    return result


def chains(ctx: CommandContext) -> Record:
    """Does a retrieval feed a shell, get chmod-ed, or get run later in the line?"""
    merged = _chain_group(ctx.parsed.commands)
    for payload in ctx.shell_payloads + ctx.remote_payloads:
        if payload.strip():
            other = _chain_group(tokenize(payload).commands)
            if not merged["download_output_path"]:
                merged["download_output_path"] = other["download_output_path"]
            for key in CHAIN_FLAGS:
                merged[key] = max(merged[key], other[key])  # type: ignore[type-var]
    return merged


# --------------------------------------------------------------------------
# encoding and obfuscation
# --------------------------------------------------------------------------
DECODE_TOOLS = ("base64", "base32", "uudecode", "xxd", "openssl", "basenc")
DECODE_FLAGS = frozenset({"-d", "--decode", "-D", "-di", "--decode=1", "-r", "-p"})
HEX_ESCAPE_RE = re.compile(r"\\x[0-9A-Fa-f]{2}")
OCTAL_ESCAPE_RE = re.compile(r"\\[0-7]{3}")


def _pipes_into_interpreter(ctx: CommandContext, sources: Sequence[str]) -> bool:
    """True when a stage running one of ``sources`` pipes into an interpreter."""
    for execution in ctx.executions_of(*sources):
        command = execution.command
        if command is None or command.pipeline_length <= 1:
            continue
        for other in ctx.executions:
            if (other is not execution and other.command is not None
                    and other.command.pipeline_id == command.pipeline_id
                    and other.command.pipeline_index > command.pipeline_index
                    and other.basename in INTERPRETERS):
                return True
    return False


def encoding(ctx: CommandContext) -> Record:
    """Decoding, escape sequences and dynamically built commands."""
    text = ctx.scan_text
    lower = ctx.lower
    decode = any(flag in DECODE_FLAGS for e in ctx.executions_of(*DECODE_TOOLS) for flag in e.args) \
        or "b64decode" in lower or "base64 -d" in lower
    echo_to_interpreter = _pipes_into_interpreter(ctx, ("echo", "printf", "cat"))
    uses_eval = ctx.uses("eval") or " eval " in " %s " % lower
    dynamic = ctx.uses("eval") or any(
        e.name.startswith(("$", "`")) or "$(" in e.name for e in ctx.executions)
    hex_escape = bool(HEX_ESCAPE_RE.search(text))
    char_construction = hex_escape or "chr(" in lower or ctx.parsed.ansi_c_quote_count > 0
    indirection = "${!" in text
    backslashes = text.count("\\")
    excessive_backslash = backslashes >= 8 or (bool(text) and backslashes / len(text) > 0.05)

    characteristics = (decode, hex_escape, bool(OCTAL_ESCAPE_RE.search(text)), char_construction,
                       indirection, excessive_backslash, text.count("\\\\") >= 2, dynamic,
                       uses_eval, echo_to_interpreter)
    return {
        "base64_decode": int(decode),
        "base64_to_interpreter": int(_pipes_into_interpreter(ctx, DECODE_TOOLS)),
        "echo_to_interpreter": int(echo_to_interpreter),
        "dynamic_command_construction": int(dynamic),
        "char_construction": int(char_construction),
        "variable_indirection": int(indirection),
        "obfuscation_characteristic_count": sum(int(bool(c)) for c in characteristics),
    }


# --------------------------------------------------------------------------
# network
# --------------------------------------------------------------------------
NET_TRANSFER_TOOLS = ("curl", "wget", "aria2c", "fetch", "ftp", "tftp", "sftp", "scp",
                      "rsync", "rclone", "lftp", "httpie", "http", "axel")
SOCKET_TOOLS = ("nc", "ncat", "netcat", "socat", "telnet", "openssl", "cryptcat")
REMOTE_SHELL_TOOLS = ("ssh", "sshpass", "mosh", "telnet", "rsh", "rlogin")
CAPTURE_TOOLS = ("tcpdump", "tshark", "wireshark", "dumpcap", "ngrep", "termshark")
SCAN_TOOLS = ("nmap", "masscan", "zmap", "hping3", "fping", "arp-scan", "nikto")
DNS_TOOLS = ("dig", "nslookup", "host", "resolvectl", "drill", "delv")
NET_CONFIG_TOOLS = ("ip", "ifconfig", "route", "arp", "ss", "netstat", "iptables",
                    "nft", "firewall-cmd", "ufw", "ethtool", "brctl", "tc")
REACHABILITY_TOOLS = ("ping", "ping6", "traceroute", "tracepath", "mtr", "nping")
NETWORK_TOOLS = frozenset(NET_TRANSFER_TOOLS + SOCKET_TOOLS + REMOTE_SHELL_TOOLS + CAPTURE_TOOLS
                          + SCAN_TOOLS + DNS_TOOLS + NET_CONFIG_TOOLS + REACHABILITY_TOOLS)
UPLOAD_FLAGS = frozenset({"-T", "--upload-file", "-F", "--form", "--data-binary", "-d",
                          "--data", "--data-raw", "--post-file"})

#: Ports that are unremarkable in a corporate Linux estate.
COMMON_PORTS = frozenset({
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 135, 137, 138, 139, 143,
    161, 162, 389, 443, 445, 464, 465, 514, 587, 631, 636, 873, 989, 990, 993, 995,
    1433, 1521, 2049, 2181, 2379, 3000, 3128, 3260, 3306, 3389, 4369, 5000, 5432,
    5601, 5672, 6379, 8000, 8080, 8081, 8088, 8443, 8500, 9000, 9090, 9092, 9093,
    9100, 9200, 9300, 11211, 15672, 27017,
})


def _is_download(execution: Execution) -> bool:
    base = execution.basename
    if base in ("wget", "aria2c", "axel", "fetch", "tftp"):
        return True
    if base == "curl":
        return not any(flag in UPLOAD_FLAGS for flag in execution.args)
    positionals = execution.positionals
    if base == "scp":
        source = positionals[0] if positionals else ""
        return "@" in source or ":" in source
    if base in ("rsync", "rclone", "sftp", "lftp", "ftp"):
        return len(positionals) >= 2 and (":" in positionals[0] or "@" in positionals[0])
    return False


def _is_upload(execution: Execution) -> bool:
    base = execution.basename
    if base == "curl":
        return any(flag in UPLOAD_FLAGS for flag in execution.args)
    if base in ("scp", "rsync", "rclone", "sftp", "lftp"):
        positionals = execution.positionals
        return len(positionals) >= 2 and (":" in positionals[-1] or "@" in positionals[-1])
    if base in ("nc", "ncat", "netcat", "socat"):
        return execution.command is not None and any(
            op.endswith("<") for op, _target in execution.command.redirects)
    if base == "tftp":
        return "put" in execution.args
    return False


def network(ctx: CommandContext) -> Record:
    """Network tools, destinations and transfer direction."""
    return {
        "has_http_url": int(any(u.scheme == "http" for u in ctx.urls)),
        "url_has_ip_host": int(any(u.host_is_ip for u in ctx.urls)),
        "has_public_ip": int(any(ipaddress.ip_address(ip).is_global for ip in ctx.ipv4s + ctx.ipv6s)),
        "has_nonstandard_port": int(any(p not in COMMON_PORTS for p in ctx.ports)),
        "network_tool_used": int(any(e.basename in NETWORK_TOOLS for e in ctx.executions)),
        "uses_socket_tool": int(ctx.uses(*SOCKET_TOOLS)),
        "uses_capture_tool": int(ctx.uses(*CAPTURE_TOOLS)),
        "uses_scan_tool": int(ctx.uses(*SCAN_TOOLS)),
        "network_download": int(any(_is_download(e) for e in ctx.executions)),
        "network_upload": int(any(_is_upload(e) for e in ctx.executions)),
    }


# --------------------------------------------------------------------------
# outbound data transfer
# --------------------------------------------------------------------------
TRANSFER_TOOLS = ("curl", "wget", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat",
                  "ftp", "lftp", "tftp", "rclone", "aws", "gsutil", "az", "s3cmd", "mc",
                  "gcloud", "b2", "dropbox_uploader.sh", "httpie")
CLOUD_TOOLS = ("aws", "gsutil", "gcloud", "az", "s3cmd", "rclone", "mc", "b2")
REMOTE_COPY_TOOLS = ("scp", "rsync", "sftp", "lftp")
STREAM_ARCHIVE_TOOLS = ("tar", "gzip", "zip", "7z", "xz", "bzip2", "zstd", "cpio")


def _is_remote(token: str) -> bool:
    if "@" in token and ":" in token:
        return True
    if token.startswith(("s3://", "gs://", "az://", "http://", "https://", "ftp://", "sftp://")):
        return True
    if ":" in token and not token.startswith("/") and "://" not in token:
        host = token.split(":", 1)[0]
        return bool(host) and "/" not in host and not host.isdigit()
    return False


def transfer(ctx: CommandContext) -> Record:
    """Is local data being sent somewhere remote?"""
    executions = ctx.executions_of(*TRANSFER_TOOLS)
    upload = False
    for execution in executions:
        base = execution.basename
        positionals = execution.positionals
        if base in REMOTE_COPY_TOOLS and len(positionals) >= 2:
            if _is_remote(positionals[-1]) and not _is_remote(positionals[0]):
                upload = True
        if base in CLOUD_TOOLS and any(a in ("cp", "sync", "mv", "put", "upload") for a in execution.args):
            if positionals and _is_remote(positionals[-1]):
                upload = True
        if base == "curl" and any(a in ("-T", "--upload-file", "-F", "--form", "--data-binary", "--post-file")
                                  for a in execution.args):
            upload = True
        if base in ("nc", "ncat", "netcat", "socat") and execution.command is not None:
            if execution.command.pipeline_index > 0 or any(
                    op.endswith("<") for op, _target in execution.command.redirects):
                upload = True

    archive_to_transfer = any(
        transfer.command is not None
        and transfer.command.pipeline_id == archive.command.pipeline_id
        and transfer.command.pipeline_index > archive.command.pipeline_index
        for archive in ctx.executions_of(*STREAM_ARCHIVE_TOOLS)
        if archive.command is not None and archive.command.pipeline_length > 1
        for transfer in executions
    )
    return {
        "remote_copy": int(ctx.uses(*REMOTE_COPY_TOOLS)),
        "upload_indicator": int(upload),
        "outbound_transfer_indicator": int(upload or archive_to_transfer),
        "transfer_over_socket_tool": int(ctx.uses("nc", "ncat", "netcat", "socat", "cryptcat")),
        "archive_to_transfer_pipeline": int(archive_to_transfer),
    }


# --------------------------------------------------------------------------
# filesystem paths
# --------------------------------------------------------------------------
#: Path categories, matched on lower-cased paths with home directories folded to ``~``.
PATH_CLASSES: Dict[str, Tuple[str, ...]] = {
    "temporary": TEMP_DIRS,
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
    "proc": ("/proc",),
    "sys": ("/sys",),
    "boot": ("/boot",),
    "root_home": ("/root",),
    "home": ("/home", "~"),
}
SENSITIVE_CATEGORIES = ("credential", "ssh", "persistence", "system_configuration",
                        "proc", "sys", "boot", "root_home")
NAMED_PATHS = {
    "touches_passwd": ("/etc/passwd",),
    "touches_shadow": ("/etc/shadow", "/etc/gshadow"),
    "touches_crontab_path": ("/etc/crontab", "/etc/cron", "/var/spool/cron"),
}


def _expand_home(path: str) -> str:
    """Map ``/home/<user>/x``, ``/root/x`` and ``$HOME/x`` onto ``~/x``."""
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


def _under(paths: Iterable[PathRef], prefixes: Sequence[str]) -> bool:
    """True when any path equals or lies beneath one of ``prefixes``."""
    for path in paths:
        for candidate in (path.lowered, _expand_home(path.raw)):
            if any(candidate == p or candidate.startswith(p + "/") for p in prefixes):
                return True
    return False


def paths(ctx: CommandContext) -> Record:
    """Which filesystem areas the command touches."""
    touched = {category for category, prefixes in PATH_CLASSES.items() if _under(ctx.paths, prefixes)}
    features: Record = {
        "path_count": len(ctx.paths),
        "touches_tmp": int("temporary" in touched),
        "touches_etc": int("system_configuration" in touched),
        "touches_home": int("home" in touched),
        "touches_sensitive_path": int(any(c in touched for c in SENSITIVE_CATEGORIES)),
    }
    for name, prefixes in NAMED_PATHS.items():
        features[name] = int(_under(ctx.paths, prefixes))
    return features


# --------------------------------------------------------------------------
# interpreters and privilege
# --------------------------------------------------------------------------
SCRIPT_EXTENSIONS = frozenset({"sh", "bash", "zsh", "ksh", "py", "py3", "pl", "rb",
                               "php", "js", "mjs", "lua", "awk", "sed", "exp", "ps1", "r"})
USER_TOOLS = ("useradd", "adduser", "usermod", "userdel", "deluser", "chage", "passwd", "newusers")
WORLD_WRITABLE_TOKENS = ("777", "666", "o+w", "a+w", "a=rwx")


def _is_script_file(token: str) -> bool:
    base = token.rsplit("/", 1)[-1]
    return "." in base and base.rsplit(".", 1)[-1].lower() in SCRIPT_EXTENSIONS


def executables(ctx: CommandContext) -> Record:
    """How code is run: interpreters, scripts by path, programs read from stdin."""
    interpreters = [e for e in ctx.executions if e.basename in INTERPRETERS]
    return {
        "interpreter_used": int(bool(interpreters)),
        "script_path_execution": int(any(
            _is_script_file(e.name) and ("/" in e.name or e.name.startswith("."))
            for e in ctx.executions)),
        "stdin_script_execution": int(any(
            op.endswith("<") for e in interpreters if e.command is not None
            for op, _target in e.command.redirects)),
    }


def privilege(ctx: CommandContext) -> Record:
    """sudo, account management and permission changes."""
    sudo = [e for e in ctx.executions if e.basename == "sudo"]
    chmod_args = " ".join(a for e in ctx.executions_of("chmod", "find", "install") for a in e.args)
    return {
        "uses_sudo": int(bool(sudo) or any("sudo" in e.wrappers for e in ctx.executions)),
        "sudo_list_permissions": int(any("-l" in e.args or "--list" in e.args for e in sudo)),
        "user_management": int(ctx.uses(*USER_TOOLS)),
        "chmod_world_writable": int(ctx.uses("chmod") and any(t in chmod_args for t in WORLD_WRITABLE_TOKENS)),
    }


# --------------------------------------------------------------------------
# persistence surfaces
# --------------------------------------------------------------------------
SYSTEMD_PATHS = ("/etc/systemd", "/lib/systemd", "/usr/lib/systemd", "~/.config/systemd",
                 "/run/systemd/system")
SHELL_STARTUP_BASENAMES = (".bashrc", ".bash_profile", ".bash_login", ".profile",
                           ".zshrc", ".zprofile", ".kshrc", ".cshrc", ".bash_logout")
SHELL_STARTUP_PATHS = ("/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/zsh")
INIT_PATHS = ("/etc/rc.local", "/etc/init.d", "/etc/rc.d", "/etc/inittab")
PRELOAD_PATHS = ("/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d")
UDEV_PATHS = ("/etc/udev", "/lib/udev", "/usr/lib/udev")
PAM_PATHS = ("/etc/pam.d", "/etc/pam.conf", "/etc/security")
PERSISTENCE_WRITE_TOOLS = ("tee", "cp", "mv", "install", "touch", "truncate", "dd", "sed", "vi", "vim",
                           "nano", "emacs", "ed", "patch", "ln")


def _writes_to(ctx: CommandContext, prefixes: Sequence[str] = (), basenames: Sequence[str] = ()) -> bool:
    """Heuristic: is one of these paths a write target rather than just a read?"""
    for command in ctx.parsed.commands:
        for op, target in command.redirects:
            low = target.lower()
            if target and ">" in op and (
                    low.startswith(tuple(prefixes)) or low.rsplit("/", 1)[-1] in basenames):
                return True
    return ctx.uses(*PERSISTENCE_WRITE_TOOLS) and bool(
        ctx.path_matches(*prefixes) or ctx.basename_matches(*basenames))


def persistence(ctx: CommandContext) -> Record:
    """cron, systemd, shell startup files, authorized_keys and friends."""
    crontab = ctx.executions_of("crontab")
    service_args = [a for e in ctx.executions_of("systemctl", "service", "chkconfig", "update-rc.d")
                    for a in e.args]
    return {
        "crontab_edit": int(any("-e" in e.args or (e.positionals and "-l" not in e.args) for e in crontab)),
        "systemd_unit_write": int(_writes_to(ctx, SYSTEMD_PATHS) or any(
            p.raw.endswith((".service", ".timer", ".socket")) and p.from_redirect for p in ctx.paths)),
        "service_enable": int(any(a in ("enable", "--now") for a in service_args)
                              or ctx.uses("chkconfig", "update-rc.d")),
        "authorized_keys_write": int(_writes_to(ctx, basenames=("authorized_keys", "authorized_keys2"))),
        "shell_startup_write": int(_writes_to(ctx, SHELL_STARTUP_PATHS, SHELL_STARTUP_BASENAMES)),
        "init_script_persistence": int(bool(ctx.path_matches(*INIT_PATHS))),
        "preload_persistence": int(bool(ctx.path_matches(*PRELOAD_PATHS))),
        "udev_persistence": int(bool(ctx.path_matches(*UDEV_PATHS))),
        "pam_configuration": int(bool(ctx.path_matches(*PAM_PATHS))),
        "at_job_persistence": int(ctx.uses("at", "batch", "atq", "atrm")),
    }


# --------------------------------------------------------------------------
# credentials
# --------------------------------------------------------------------------
CLOUD_CREDENTIAL_KEYWORDS = ("aws_access_key_id", "aws_secret_access_key", "aws_session_token",
                             ".aws/credentials", "google_application_credentials", "gcloud auth",
                             "azure_client_secret", "service_account.json", ".kube/config", "kubeconfig")
CREDENTIAL_FILES = frozenset({"shadow", "gshadow", "passwd", ".netrc", ".pgpass",
                              ".git-credentials", "credentials", "config", ".htpasswd"})


def credentials(ctx: CommandContext) -> Record:
    """References to credential files and cloud/cluster credentials."""
    return {
        "cloud_credential_reference": int(any(k in ctx.lower for k in CLOUD_CREDENTIAL_KEYWORDS)),
        "kube_config_reference": int(".kube/config" in ctx.lower or "kubeconfig" in ctx.lower),
        "credential_file_reference": int(any(p.basename.lower() in CREDENTIAL_FILES for p in ctx.paths)),
    }


# --------------------------------------------------------------------------
# file operations and archives
# --------------------------------------------------------------------------
FILE_WRITE_TOOLS = ("touch", "tee", "install", "truncate", "dd", "ln", "mkdir", "mktemp", "split")
EDIT_TOOLS = ("sed", "perl", "awk", "ed", "patch", "vi", "vim", "nvim", "nano", "emacs")
ARCHIVE_TOOLS = ("tar", "gzip", "gunzip", "zip", "unzip", "7z", "7za", "xz", "unxz",
                 "bzip2", "bunzip2", "zstd", "unzstd", "compress", "cpio", "ar", "rar", "unrar")
ARCHIVE_EXTENSIONS = frozenset({"tar", "tgz", "gz", "bz2", "xz", "zst", "zip", "7z", "rar", "z", "lz4", "cpio"})
CREATE_FLAGS = frozenset({"-c", "-cf", "-czf", "-cvf", "-czvf", "-cjf", "-cJf", "--create", "a"})


def file_ops(ctx: CommandContext) -> Record:
    """Writes, edits, secure deletion and timestamp changes."""
    writes_by_redirect = any(op.endswith(">") for command in ctx.parsed.commands
                             for op, target in command.redirects if target not in DISCARD_TARGETS)
    inplace = any(a in ("-i", "--in-place") or a.startswith(("-i.", "--in-place="))
                  for e in ctx.executions_of("sed", "perl", "ruby") for a in e.args)
    return {
        "file_write_indicator": int(writes_by_redirect or ctx.uses(*FILE_WRITE_TOOLS) or inplace),
        "file_edit_indicator": int(ctx.uses(*EDIT_TOOLS)),
        "secure_delete": int(ctx.uses("shred", "wipe", "srm")),
        "timestamp_modification": int(any(a in ("-t", "-d", "-r", "--date", "--reference")
                                          for e in ctx.executions_of("touch") for a in e.args)),
    }


def archives(ctx: CommandContext) -> Record:
    """Archive creation and the archive file it produces."""
    executions = ctx.executions_of(*ARCHIVE_TOOLS)
    args = [a for e in executions for a in e.args]
    flags = {a for a in args if a.startswith("-")} | set(args[:1])
    creating = bool(flags & CREATE_FLAGS) or ctx.uses("gzip", "bzip2", "xz", "zstd", "zip", "compress")
    if executions and executions[0].basename == "tar":
        joined = " ".join(args)
        creating = creating or ("c" in joined and "-x" not in joined)
    archive_paths = [p for p in ctx.paths if p.extension in ARCHIVE_EXTENSIONS
                     or p.raw.endswith((".tar.gz", ".tar.bz2", ".tar.xz"))]
    return {
        "archive_creation": int(bool(executions) and creating),
        "archive_path": archive_paths[0].raw if archive_paths else "",
    }


# --------------------------------------------------------------------------
# containers, discovery, kernel and processes
# --------------------------------------------------------------------------
CONTAINER_TOOLS = ("docker", "podman", "nerdctl", "kubectl", "crictl", "ctr", "lxc",
                   "lxc-attach", "machinectl", "helm", "oc", "singularity", "apptainer")
RUNTIME_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd",
                   "/var/run/containerd", "/run/crio", "/var/run/crio", "/run/podman")
DISCOVERY_CATEGORIES: Tuple[Tuple[str, ...], ...] = (
    ("whoami", "id", "groups", "logname", "who", "w", "users", "last", "lastlog"),
    ("uname", "hostname", "hostnamectl", "uptime", "lsb_release", "dmidecode",
     "timedatectl", "localectl", "arch"),
    ("ps", "top", "htop", "pgrep", "pstree", "pidof", "lsof", "fuser"),
    ("ip", "ifconfig", "ss", "netstat", "route", "arp", "resolvectl", "iptables", "nft",
     "firewall-cmd", "traceroute", "ping", "dig", "nslookup", "host", "nmap"),
    ("ls", "find", "locate", "tree", "du", "df", "stat", "file", "readlink", "realpath",
     "mount", "lsblk", "blkid"),
    ("lscpu", "lsusb", "lspci", "lsblk", "lshw", "free", "nproc", "sensors", "nvidia-smi", "dmidecode"),
    ("systemctl", "service", "journalctl", "chkconfig", "initctl", "supervisorctl", "rc-status"),
    ("env", "printenv", "set", "export", "history", "pwd", "which", "whereis", "type",
     "command", "alias", "ulimit", "locale"),
)
#: Credential discovery tools only count when an argument names credentials.
CREDENTIAL_DISCOVERY_TOOLS = ("getent", "passwd", "vault", "aws", "gcloud", "az", "kubectl", "keyctl")
CREDENTIAL_ARG_HINTS = ("passwd", "shadow", "secret", "credential", "token", "key", "login")
HISTORY_FILES = (".bash_history", ".zsh_history")
TRACER_TOOLS = ("strace", "ltrace", "ptrace", "bpftrace", "perf", "systemtap", "stap", "dtrace",
                "gdb", "lldb", "radare2", "r2", "objdump", "readelf", "nm", "edb")


def containers(ctx: CommandContext) -> Record:
    """Container breakout primitives and cluster secret access."""
    args = [a for e in ctx.executions_of(*CONTAINER_TOOLS) for a in e.args]
    joined = " ".join(args)
    return {
        "container_privileged_flag": int("--privileged" in args),
        "container_host_namespace": int(any(
            a.startswith(("--pid=host", "--net=host", "--network=host", "--ipc=host", "--userns=host"))
            for a in args) or "hostPID" in joined or "hostNetwork" in joined),
        "container_host_mount": int(
            any(a.startswith(("-v", "--volume", "--mount")) or ":/" in a for a in args)
            and any(a.startswith(("/", "-v /", "--volume=/")) for a in args)),
        "docker_socket_access": int(any(sock in ctx.lower for sock in RUNTIME_SOCKETS)),
        "kubernetes_secret_access": int(ctx.uses("kubectl", "oc") and ("secret" in args or "secrets" in args)),
    }


def discovery(ctx: CommandContext) -> Record:
    """Reconnaissance breadth and shell history tampering."""
    categories = sum(int(ctx.uses(*tools)) for tools in DISCOVERY_CATEGORIES)
    categories += int(any(any(hint in a.lower() for hint in CREDENTIAL_ARG_HINTS)
                          for e in ctx.executions_of(*CREDENTIAL_DISCOVERY_TOOLS) for a in e.args))
    lower = ctx.lower
    history_paths = [p for p in ctx.paths if p.basename in HISTORY_FILES]
    return {
        "discovery_category_count": categories,
        "history_cleared": int(
            "history -c" in lower or "unset histfile" in lower
            or "histfile=/dev/null" in lower.replace(" ", "")
            or any(p.from_redirect for p in history_paths)
            or (ctx.uses("rm", "shred", "truncate") and bool(history_paths))),
    }


def kernel_and_processes(ctx: CommandContext) -> Record:
    """Kernel module loading and access to other processes."""
    modprobe_args = [a for e in ctx.executions_of("modprobe") for a in e.args]
    return {
        "kernel_module_load": int(ctx.uses("insmod") or (ctx.uses("modprobe") and "-r" not in modprobe_args)),
        "attaches_to_pid": int(any("-p" in e.args or "--pid" in e.args for e in ctx.executions_of(*TRACER_TOOLS))),
        "proc_mem_access": int(any(p.lowered.startswith("/proc") and p.lowered.endswith(("/mem", "/maps", "/smaps"))
                                   for p in ctx.paths)),
    }


# --------------------------------------------------------------------------
# tradecraft: specific, well-documented attacker techniques
# --------------------------------------------------------------------------
TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
#: Dot-directories the system itself creates under /tmp.
BENIGN_TEMP_DOTDIRS = frozenset({".x11-unix", ".ice-unix", ".font-unix", ".xim-unix", ".test-unix"})
RETRIEVAL_NAMES = ("curl", "wget", "fetch", "aria2c", "nc", "ncat", "netcat", "socat")

DISK_DEVICE_RE = re.compile(r"^/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|md\d|dm-\d|mapper/|disk/)")
ROOT_TARGETS = frozenset({"/", "/*", "/.", "/./", "/..", "--no-preserve-root"})
SYSTEM_DIRECTORIES = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/var",
                      "/home", "/root", "/opt", "/srv")
ACCOUNT_DATABASES = ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow")
SUDOERS_PATHS = ("/etc/sudoers",)
LOG_ARTIFACTS = ("/var/log/", "/var/run/utmp", "/run/utmp", "/var/log/wtmp", "/var/log/btmp",
                 "/var/log/lastlog", "/var/adm/")
READ_TOOLS = frozenset({"cat", "less", "more", "head", "tail", "base64", "base32", "xxd", "od",
                        "strings", "cp", "mv", "tar", "zip", "7z", "gzip", "curl", "wget", "nc",
                        "ncat", "socat", "scp", "rsync", "dd", "tac", "nl", "hexdump", "gpg"})
SSH_PRIVATE_KEY_RE = re.compile(r"(?:^|/)(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?|ssh_host_\w+_key|identity)$")
PRIVATE_KEY_DIRS = ("~/.ssh/", "/root/.ssh/", "/etc/ssh/", "/etc/ssl/private/", "/home/")

CREDENTIAL_SEARCH_RE = re.compile(
    r"(?i)(pass(?:word|wd)?|secret|token|api[_-]?key|aws_secret|private[ _]key|"
    r"BEGIN [A-Z ]*PRIVATE|credential)"
)
CREDENTIAL_FILE_GLOB_RE = re.compile(
    r"(?i)(id_rsa|id_ed25519|\*\.pem|\*\.key|\*\.ppk|\*\.kdbx|\.env\b|wallet\.dat|\.git-credentials|"
    r"\.netrc|\.pgpass|credentials|\.htpasswd|\*\.p12|\*\.pfx)"
)
BROAD_SEARCH_ROOTS = frozenset({"/", "/home", "/etc", "/var", "/opt", "/root", "/srv", "~", "/usr", "/mnt"})

SOCKET_CONNECT_RE = re.compile(
    r"(?i)(socket\.socket|\.connect\(|tcpsocket|fsockopen|socket\(|net\.connect|net\.socket|"
    r"io::socket|new socket|/dev/tcp/)"
)
SOCKET_SHELL_RE = re.compile(
    r"(?i)(dup2|/bin/(?:ba)?sh\b|\bsh\s*-i\b|subprocess|spawn|popen|proc_open|shell_exec|"
    r"\bsystem\s*\(|child_process|exec\s*\(?\s*['\"]/bin)"
)
EMBEDDED_DOWNLOAD_EXEC_RE = re.compile(
    r"(?i)\b(?:curl|wget|fetch)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:\S*/)?(?:ba|da|z|k|a)?sh\b|"
    r"\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:\S*/)?(?:python[23]?|perl|ruby|php|node)\b"
)
EMBEDDED_REVERSE_SHELL_RE = re.compile(
    r"(?i)/dev/(?:tcp|udp)/|\bnc(?:at)?\b[^|;&\n]*\s-[a-z]*[ec]\b|\bsocat\b[^\n]*\b(?:exec|system):"
)
SUBSTITUTION_RETRIEVAL_RE = re.compile(
    r"(?:\$\(|<\(|`)\s*(?:sudo\s+)?(?:\S*/)?(?:%s)\b" % "|".join(RETRIEVAL_NAMES)
)
#: Encryption invoked as a find -exec / xargs payload, where it is an argument.
BULK_ENCRYPT_RE = re.compile(r"(?:-exec|xargs)\s[^;]*\b(?:openssl\s+enc|gpg2?\s+(?:-c|--symmetric|-e|--encrypt))\b")
FORK_BOMB_RE = re.compile(r"(\S+)\s*\(\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1")
UID0_LINE_RE = re.compile(r":0:0?:")
SETUID_MODE_RES = (re.compile(r"[ugoa]*\+[rwxt]*s[rwxt]*"), re.compile(r"[ugo]*=[rwx]*s[rwx]*"),
                   re.compile(r"0?[246][0-7]{3}"))
SUID_PERM_RE = re.compile(r"(^|[-/])(u=s|g=s|[246]000)$")
IMMUTABLE_RE = re.compile(r"\+[aiA-Z]*[ia][a-zA-Z]*")
LD_PRELOAD_RE = re.compile(r"(^|[\s;&|])LD_PRELOAD=")
ASLR_OFF_RES = (
    re.compile(r"randomize_va_space\s*=?\s*['\"]?0\b"),
    re.compile(r"echo\s+['\"]?0['\"]?\s*>+\s*/proc/sys/kernel/randomize_va_space"),
    re.compile(r"ptrace_scope\s*=?\s*['\"]?0\b"),
    re.compile(r"echo\s+['\"]?0['\"]?\s*>+\s*/proc/sys/kernel/yama/ptrace_scope"),
)
SOCAT_TCP_RE = re.compile(r"(?i)tcp[46]?(-listen)?:")

OFFENSIVE_TOOLS = frozenset({
    "linpeas", "linenum", "lse", "les", "linux-exploit-suggester", "linux-smart-enumeration",
    "unix-privesc-check", "pspy", "pspy32", "pspy64", "mimipenguin", "lazagne", "msfconsole",
    "msfvenom", "meterpreter", "hydra", "medusa", "ncrack", "john", "hashcat", "sqlmap", "nikto",
    "gobuster", "dirb", "ffuf", "wfuzz", "chisel", "ligolo", "ligolo-ng", "crackmapexec", "netexec",
    "nxc", "responder", "sliver", "sliver-client", "deepce", "cdk", "peirates", "kube-hunter",
    "evil-winrm", "traitor", "gtfonow", "pwncat", "pwncat-cs", "linikatz", "sshamble",
})
MINER_TOOLS = frozenset({"xmrig", "xmr-stak", "minerd", "cpuminer", "cgminer", "bfgminer",
                         "ethminer", "nbminer", "t-rex", "lolminer", "phoenixminer", "kdevtmpfsi",
                         "kinsing", "xmrig-notls", "srbminer", "teamredminer"})
MINER_TEXT = ("stratum+tcp://", "stratum+ssl://", "stratum2+tcp://", "--donate-level",
              "minexmr", "supportxmr", "nanopool.org", "moneroocean", "2miners.com", "f2pool",
              "nicehash", "hashvault.pro", "c3pool")
EXFIL_DOMAINS = ("transfer.sh", "file.io", "0x0.st", "paste.ee", "pastebin.com", "hastebin",
                 "termbin.com", "anonfiles", "gofile.io", "bashupload.com", "temp.sh", "oshi.at",
                 "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "webhook.site",
                 "requestbin", "pipedream.net", "interact.sh", "oast.fun", "oast.pro", "oast.live",
                 "burpcollaborator.net", "discord.com/api/webhooks", "discordapp.com/api/webhooks",
                 "api.telegram.org", "pastes.io", "catbox.moe", "filebin.net", "tmpfiles.org")
METADATA_ENDPOINTS = ("169.254.169.254", "metadata.google.internal", "100.100.100.200",
                      "fd00:ec2::254", "169.254.170.2")
METADATA_CREDENTIAL_PATHS = ("security-credentials", "/identity", "service-accounts", "/token",
                             "iam/info", "access_token", "/credentials")
SECURITY_SERVICES = ("auditd", "apparmor", "selinux", "falcon-sensor", "falcond", "osqueryd",
                     "wazuh-agent", "ossec", "sysmon", "sentinelone", "sentinelagent", "cbagentd",
                     "cylancesvc", "ds_agent", "elastic-agent", "auditbeat", "filebeat", "rsyslog",
                     "syslog", "syslog-ng", "systemd-journald", "clamav-daemon", "clamd", "aide",
                     "fail2ban", "tripwire", "mdatp", "qualys-cloud-agent", "td-agent", "fluent-bit",
                     "splunkd", "splunk", "nxlog", "datadog-agent", "amazon-ssm-agent", "crowdstrike")
FIREWALL_SERVICES = ("firewalld", "ufw", "iptables", "nftables", "ip6tables")
DANGEROUS_CAPABILITIES = ("cap_setuid", "cap_setgid", "cap_sys_admin", "cap_dac_override",
                          "cap_dac_read_search", "cap_sys_ptrace", "cap_sys_module", "cap_chown",
                          "cap_fowner", "=ep")
TUNNEL_TOOLS = ("ngrok", "chisel", "frpc", "frps", "gost", "iodine", "dnscat", "dnscat2",
                "ptunnel", "bore", "rathole")
KERNEL_THREAD_NAMES = re.compile(r"^\[?(kworker|kthreadd|ksoftirqd|migration|rcu_\w+|kswapd\d*|"
                                 r"watchdog|jbd2|khugepaged|kdevtmpfs)[\w/:.-]*\]?$")


def _all_commands(ctx: CommandContext) -> List[SimpleCommand]:
    """Top-level and nested simple commands, each once."""
    seen = set()
    out: List[SimpleCommand] = []
    for command in list(ctx.parsed.commands) + [e.command for e in ctx.executions if e.command]:
        if id(command) not in seen:
            seen.add(id(command))
            out.append(command)
    return out


def _write_targets(ctx: CommandContext) -> List[str]:
    """Paths this command line writes to: redirects, tee, dd of=, sed -i, cp/mv/install dest."""
    targets: List[str] = []
    for command in _all_commands(ctx):
        for op, target in command.redirects:
            if target and op.endswith(">") and target not in DISCARD_TARGETS:
                targets.append(target)
    for execution in ctx.executions:
        base = execution.basename
        positionals = execution.positionals
        if base == "tee":
            targets.extend(positionals)
        elif base == "dd":
            targets.extend(a.split("=", 1)[1] for a in execution.args if a.startswith("of="))
        elif base in ("sed", "perl") and any(a == "-i" or a.startswith("-i") and len(a) <= 6
                                             or a.startswith("--in-place") for a in execution.args):
            targets.extend(positionals[1:] if base == "sed" else positionals[-1:])
        elif base in ("cp", "mv", "install", "ln", "rsync") and len(positionals) >= 2:
            targets.append(positionals[-1])
        elif base in ("truncate", "shred"):
            targets.extend(positionals)
    return targets


def _matches(path: str, prefixes: Iterable[str]) -> bool:
    low = path.lower()
    return any(low == p.rstrip("/") or low.startswith(p) for p in prefixes)


def _has_flag(args: List[str], *names: str) -> bool:
    letters = flag_letters(args)
    return any(a in names for a in args) or any(n in letters for n in names)


def _reverse_shells(ctx: CommandContext) -> Record:
    netcat_exec = listener = False
    for execution in ctx.executions_of("nc", "ncat", "netcat", "socat"):
        args = execution.args
        if execution.basename == "socat":
            joined = " ".join(args).lower()
            netcat_exec = netcat_exec or "exec:" in joined or "system:" in joined
            listener = listener or "listen" in joined
            continue
        if _has_flag(args, "-e", "-c") or any(a.startswith(("--exec", "--sh-exec", "--lua-exec")) for a in args):
            netcat_exec = True
        if _has_flag(args, "-l") or "--listen" in args:
            listener = True

    # quoted word values and inline script payloads -- where payloads hide
    quoted = [t.value for t in ctx.parsed.tokens if t.kind == "word" and t.quoted] + ctx.script_payloads
    fifo_relay = (ctx.uses("mkfifo") or any(e.basename == "mknod" and "p" in e.args for e in ctx.executions)) \
        and any(b in SHELLS for b in ctx.basenames) \
        and ctx.uses("nc", "ncat", "netcat", "socat", "openssl", "telnet")
    substitution_fed = any(
        any(SUBSTITUTION_RETRIEVAL_RE.search(a) for a in e.args)
        for e in ctx.executions if e.basename in INTERPRETERS or e.basename in ("eval", "source", "."))

    return {
        "dev_tcp_redirect": int("/dev/tcp/" in ctx.lower or "/dev/udp/" in ctx.lower),
        "netcat_exec_flag": int(netcat_exec),
        "socket_shell_payload": int(any(SOCKET_CONNECT_RE.search(p) and SOCKET_SHELL_RE.search(p)
                                        for p in ctx.script_payloads)),
        "named_pipe_shell_relay": int(bool(fifo_relay)),
        "socket_listener": int(listener),
        "embedded_download_exec": int(any(EMBEDDED_DOWNLOAD_EXEC_RE.search(t) for t in quoted)),
        "embedded_reverse_shell": int(any(
            EMBEDDED_REVERSE_SHELL_RE.search(t) or (SOCKET_CONNECT_RE.search(t) and SOCKET_SHELL_RE.search(t))
            for t in quoted)),
        "substitution_fed_interpreter": int(substitution_fed),
    }


def _destruction(ctx: CommandContext, targets: List[str]) -> Record:
    root_delete = system_delete = False
    for execution in ctx.executions_of("rm"):
        args = execution.args
        if "--no-preserve-root" in args:
            root_delete = True
        if not (_has_flag(args, "-r", "-R") or "--recursive" in args):
            continue
        for target in execution.positionals:
            clean = target.rstrip("/") or "/"
            if target in ROOT_TARGETS or clean in ("/", "/*"):
                root_delete = True
            elif clean.rstrip("/*") in SYSTEM_DIRECTORIES:
                system_delete = True
    raw_disk = any(DISK_DEVICE_RE.match(t) for t in targets) or any(
        DISK_DEVICE_RE.match(p)
        for e in ctx.executions if e.basename.startswith("mkfs") or e.basename in ("wipefs", "blkdiscard")
        for p in e.positionals)
    return {
        "root_filesystem_delete": int(root_delete),
        "system_directory_delete": int(system_delete),
        "raw_disk_write": int(raw_disk),
        "fork_bomb": int(bool(FORK_BOMB_RE.search(ctx.raw))),
    }


def _accounts_and_privilege(ctx: CommandContext, targets: List[str]) -> Record:
    uid0 = False
    for execution in ctx.executions_of("useradd", "adduser", "usermod"):
        args = execution.args
        if "--uid=0" in args or any(token in ("-u", "--uid") and args[index + 1:index + 2] == ["0"]
                                    for index, token in enumerate(args)):
            uid0 = True
        if "-o" in args and ("-u" in args or "--uid" in args) and "0" in args:
            uid0 = True
    account_write = any(_matches(t, ACCOUNT_DATABASES) for t in targets)
    if account_write and UID0_LINE_RE.search(ctx.raw):
        uid0 = True

    chmod_args = [a for e in ctx.executions_of("chmod", "install") for a in e.args]
    return {
        "uid0_account_creation": int(uid0),
        "account_database_write": int(account_write),
        "sudoers_write": int(any(_matches(t, SUDOERS_PATHS) for t in targets) and not ctx.uses("visudo")),
        "setuid_bit_set": int(any(r.fullmatch(a) for a in chmod_args for r in SETUID_MODE_RES)),
        "suid_binary_search": int(any("-perm" in e.args and any(SUID_PERM_RE.search(a) for a in e.args)
                                      for e in ctx.executions_of("find"))),
        "dangerous_capability_grant": int(ctx.uses("setcap") and any(c in ctx.lower for c in DANGEROUS_CAPABILITIES)),
        "host_namespace_entry": int(any(
            "--target=1" in e.args or "-t1" in e.args
            or any(a in ("-t", "--target") and e.args[i + 1:i + 2] == ["1"] for i, a in enumerate(e.args))
            for e in ctx.executions_of("nsenter"))),
        "immutable_attribute_set": int(any(IMMUTABLE_RE.fullmatch(a)
                                           for e in ctx.executions_of("chattr") for a in e.args)),
        "ld_preload_env": int(
            any(a.startswith("LD_PRELOAD=") for e in ctx.executions for a in e.assignments)
            or any(a.startswith("LD_PRELOAD=") for e in ctx.executions_of("export", "env") for a in e.args)
            or bool(LD_PRELOAD_RE.search(ctx.raw))),
    }


def _defense_evasion(ctx: CommandContext, targets: List[str]) -> Record:
    lower = ctx.lower
    log_tamper = any(_matches(t, LOG_ARTIFACTS) for t in targets) or any(
        _matches(p, LOG_ARTIFACTS)
        for e in ctx.executions_of("rm", "shred", "unlink", "truncate", "srm", "wipe") for p in e.positionals
    ) or any(a.startswith(("--vacuum", "--rotate")) for e in ctx.executions_of("journalctl") for a in e.args)

    monitoring_off = firewall_off = False
    for execution in ctx.executions:
        base, args = execution.basename, [a.lower() for a in execution.args]
        if base == "setenforce" and args[:1] in (["0"], ["permissive"]):
            monitoring_off = True
        if base == "auditctl" and ("-D" in execution.args or args[:2] == ["-e", "0"]):
            monitoring_off = True
        if base == "systemctl" and args and args[0] in ("stop", "disable", "mask", "kill"):
            units = [u.replace(".service", "") for u in args[1:] if not u.startswith("-")]
            monitoring_off = monitoring_off or any(u in SECURITY_SERVICES for u in units)
            firewall_off = firewall_off or any(u in FIREWALL_SERVICES for u in units)
        if base == "service" and len(args) >= 2 and args[1] == "stop":
            monitoring_off = monitoring_off or args[0] in SECURITY_SERVICES
            firewall_off = firewall_off or args[0] in FIREWALL_SERVICES
        if base in ("pkill", "killall") and any(a in SECURITY_SERVICES for a in args):
            monitoring_off = True
        if base == "ufw" and "disable" in args:
            firewall_off = True
        if base in ("iptables", "ip6tables") and (
                _has_flag(execution.args, "-F") or "--flush" in args
                or (("-p" in execution.args or "--policy" in args) and "accept" in args)):
            firewall_off = True
        if base == "nft" and "flush" in args and "ruleset" in args:
            firewall_off = True
    compact = lower.replace(" ", "")
    if "selinux=disabled" in compact and any("selinux" in t.lower() for t in targets):
        monitoring_off = True
    if ("selinux=disabled" in compact or "selinux=permissive" in compact) \
            and any("/etc/selinux" in p.lowered for p in ctx.paths):
        monitoring_off = True

    hidden_temp = False
    for path in ctx.paths:
        low = path.lowered
        if low.startswith(TEMP_PREFIXES):
            parts = low.split("/")[3:] if low.startswith("/dev/shm/") else low.split("/")[2:]
            if any(part.startswith(".") and part not in (".", "..") and part not in BENIGN_TEMP_DOTDIRS
                   for part in parts):
                hidden_temp = True
    temp_exec = any(e.name.lower().startswith(TEMP_PREFIXES) for e in ctx.executions) or any(
        (e.basename in INTERPRETERS or e.basename in ("source", "."))
        and e.positionals and e.positionals[0].lower().startswith(TEMP_PREFIXES)
        for e in ctx.executions)
    masquerade = any(e.basename == "exec" and "-a" in e.args for e in ctx.executions) or any(
        KERNEL_THREAD_NAMES.match(e.basename) and "/" in e.name for e in ctx.executions)

    return {
        "log_tampering": int(log_tamper),
        "security_monitoring_disabled": int(monitoring_off),
        "firewall_disabled": int(firewall_off),
        "aslr_or_ptrace_protection_disabled": int(any(r.search(lower) for r in ASLR_OFF_RES)),
        "hidden_temp_path": int(hidden_temp),
        "exec_from_temp": int(temp_exec),
        "process_name_masquerade": int(bool(masquerade)),
    }


def _tooling_and_destinations(ctx: CommandContext) -> Record:
    lower = ctx.lower
    names: List[str] = list(ctx.basenames)
    for path in ctx.paths:
        names.append(path.basename.lower().rsplit(".", 1)[0])
    for url in ctx.urls:
        tail = url.path.rstrip("/").rsplit("/", 1)[-1].lower()
        if tail:
            names.append(tail.rsplit(".", 1)[0])
    metadata = any(ep in lower for ep in METADATA_ENDPOINTS)

    credential_search = False
    for execution in ctx.executions_of("grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "locate"):
        args = execution.args
        joined = " ".join(args)
        broad = any(p.rstrip("/") in BROAD_SEARCH_ROOTS or p in ("/", "~/") for p in execution.positionals)
        if execution.basename in ("find", "locate"):
            if CREDENTIAL_FILE_GLOB_RE.search(joined) and (broad or execution.basename == "locate"):
                credential_search = True
        elif CREDENTIAL_SEARCH_RE.search(joined) and broad and (
                _has_flag(args, "-r", "-R") or "--recursive" in args or execution.basename in ("rg", "ag", "ack")):
            credential_search = True

    private_key = any(op == "<" and SSH_PRIVATE_KEY_RE.search(target.lower())
                      for command in _all_commands(ctx) for op, target in command.redirects)
    for execution in ctx.executions:
        if execution.basename not in READ_TOOLS:
            continue
        for index, arg in enumerate(execution.args):
            if index > 0 and execution.args[index - 1] == "-i":
                continue
            low = arg.lower()
            if SSH_PRIVATE_KEY_RE.search(low) or (
                    low.endswith((".pem", ".key", ".ppk")) and _matches(low, PRIVATE_KEY_DIRS)):
                private_key = True

    tunnel = ctx.uses(*TUNNEL_TOOLS) \
        or any(_has_flag(e.args, "-R", "-D", "-w") for e in ctx.executions_of("ssh")) \
        or any(e.basename == "cloudflared" and "tunnel" in e.args for e in ctx.executions) \
        or any(e.basename == "socat" and sum(1 for a in e.args if SOCAT_TCP_RE.match(a)) >= 2
               for e in ctx.executions)

    encrypts = any(e.basename == "openssl" and e.args[:1] == ["enc"] for e in ctx.executions) or any(
        e.basename in ("gpg", "gpg2") and (_has_flag(e.args, "-c") or "--symmetric" in e.args
                                           or "--encrypt" in e.args) for e in ctx.executions) or \
        ctx.uses("ccrypt", "age") or bool(BULK_ENCRYPT_RE.search(lower))

    return {
        "offensive_tool_reference": int(any(n in OFFENSIVE_TOOLS or n.startswith("impacket-") for n in names)),
        "crypto_miner_reference": int(any(n in MINER_TOOLS for n in names) or any(t in lower for t in MINER_TEXT)),
        "exfil_service_domain": int(any(d in lower for d in EXFIL_DOMAINS)),
        "cloud_metadata_access": int(metadata),
        "cloud_metadata_credential_path": int(metadata and any(p in lower for p in METADATA_CREDENTIAL_PATHS)),
        "credential_search": int(credential_search),
        "private_key_file_access": int(bool(private_key)),
        "tunnel_or_proxy": int(bool(tunnel)),
        "noninteractive_remote_auth": int(ctx.uses("sshpass") or "stricthostkeychecking=no" in lower.replace(" ", "")),
        "bulk_encryption": int(bool(encrypts and (ctx.uses("find", "xargs", "parallel") or "for " in lower))),
    }


def tradecraft(ctx: CommandContext) -> Record:
    """Command shapes documented in public attack write-ups."""
    targets = _write_targets(ctx)
    record = _reverse_shells(ctx)
    record.update(_destruction(ctx, targets))
    record.update(_accounts_and_privilege(ctx, targets))
    record.update(_defense_evasion(ctx, targets))
    record.update(_tooling_and_destinations(ctx))
    return record


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
GROUPS = (chains, encoding, network, transfer, paths, executables, privilege, persistence,
          credentials, file_ops, archives, containers, discovery, kernel_and_processes, tradecraft)


def extract_features(command: str) -> Record:
    """Compute every feature for one command line.

    A group that raises on some odd input is skipped -- its features read as
    unset -- so one malformed command line never aborts a script or a feed.
    """
    ctx = build_context(command[:MAX_COMMAND_LENGTH])
    record: Record = {}
    for group in GROUPS:
        try:
            record.update(group(ctx))
        except Exception:                          # pragma: no cover - defensive
            continue
    return record
