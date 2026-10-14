"""Feature extraction: one command line in, a flat record of observations out.

Each group function (``chains``, ``network``, ...) takes a
:class:`~malscore.context.CommandContext` and returns named features.  A feature
is an observation ("a ``/dev/tcp`` redirection is present", "a download is
piped into a shell"), never a verdict -- weighing observations is the job of
:mod:`malscore.signals`.  Only features that some signal or the session analysis
reads are computed.

Technique-specific shapes (reverse shells, credential hunting, ...) live in
:mod:`malscore.tradecraft`.  Nothing here executes, expands or resolves anything.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, Iterable, Optional, Sequence, Tuple

from .context import (
    DISCARD_TARGETS,
    INTERPRETERS,
    SHELLS,
    TEMP_DIRS,
    CommandContext,
    Execution,
    PathRef,
    build_context,
    resolve_execution,
)
from .lexer import SimpleCommand, tokenize
from .tradecraft import tradecraft

Record = Dict[str, object]

#: Longer command lines are truncated before analysis.
MAX_COMMAND_LENGTH = 8192

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
    """How code is run: interpreters and scripts executed by path."""
    interpreters = [e for e in ctx.executions if e.basename in INTERPRETERS]
    return {
        "interpreter_used": int(bool(interpreters)),
        "script_path_execution": int(any(
            _is_script_file(e.name) and ("/" in e.name or e.name.startswith("."))
            for e in ctx.executions)),
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
    compact = lower.replace(" ", "")
    history_paths = [p for p in ctx.paths if p.basename in HISTORY_FILES]
    history_cleared = (
        "history -c" in lower or "history -d" in lower or "unset histfile" in lower
        or "histfile=/dev/null" in compact
        or "histsize=0" in compact or "histfilesize=0" in compact
        or "set+ohistory" in compact
        or "histcontrol=ignorespace" in compact or "histcontrol=ignoreboth" in compact
        or any(p.from_redirect for p in history_paths)
        or (ctx.uses("rm", "shred", "truncate", "ln") and bool(history_paths)))
    return {
        "discovery_category_count": categories,
        "history_cleared": int(history_cleared),
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
# entry point
# --------------------------------------------------------------------------
GROUPS = (chains, encoding, network, transfer, paths, executables, privilege, persistence,
          credentials, file_ops, archives, containers, discovery, kernel_and_processes, tradecraft)


def extract_features(command: str) -> Record:
    """Compute every feature for one command line.

    A group that raises on some odd input is skipped -- its features read as
    unset -- so one malformed command line never aborts a session or a feed.
    """
    ctx = build_context(command[:MAX_COMMAND_LENGTH])
    record: Record = {}
    for group in GROUPS:
        try:
            record.update(group(ctx))
        except Exception:                          # pragma: no cover - defensive
            continue
    return record
