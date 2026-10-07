"""Tradecraft features: command shapes documented in public attack write-ups.

The other modules describe *what* a command touches.  This one recognises a
small set of specific, well-known techniques -- reverse shells, destructive disk
writes, log wiping, disabling audit tooling -- whose shape is distinctive enough
that a structural check is far more precise than combining generic indicators.

As everywhere else in this package, the features are observations ("a
``/dev/tcp`` redirection is present"), not verdicts.  Weighing them is the job of
:mod:`cmdfeat.scoring`.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Set

from ..context import SCRIPT_INTERPRETERS, SHELLS, CommandContext, flag_letters, is_flag
from ..lexer import SimpleCommand
from ..schema import F, KIND_INDICATOR

TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
#: Dot-directories the system itself creates under /tmp.
BENIGN_TEMP_DOTDIRS = frozenset({".x11-unix", ".ice-unix", ".font-unix", ".xim-unix", ".test-unix"})
DISCARD_TARGETS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"})
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
KERNEL_THREAD_NAMES = re.compile(r"^\[?(kworker|kthreadd|ksoftirqd|migration|rcu_\w+|kswapd\d*|"
                                 r"watchdog|jbd2|khugepaged|kdevtmpfs)[\w/:.-]*\]?$")

FEATURES = [
    F("dev_tcp_redirect", "bool", "tradecraft", KIND_INDICATOR, "A /dev/tcp or /dev/udp pseudo-device is used (bash network redirection)."),
    F("netcat_exec_flag", "bool", "tradecraft", KIND_INDICATOR, "nc/ncat/socat is asked to hand a program to the socket (-e, -c, --exec, EXEC:)."),
    F("socket_shell_payload", "bool", "tradecraft", KIND_INDICATOR, "An inline script opens a socket and spawns a shell or duplicates descriptors."),
    F("named_pipe_shell_relay", "bool", "tradecraft", KIND_INDICATOR, "A named pipe relays a shell through a socket tool (mkfifo + sh + nc)."),
    F("socket_listener", "bool", "tradecraft", KIND_INDICATOR, "A raw socket tool listens for inbound connections."),
    F("embedded_download_exec", "bool", "tradecraft", KIND_INDICATOR, "A quoted string or payload contains a download piped into an interpreter."),
    F("embedded_reverse_shell", "bool", "tradecraft", KIND_INDICATOR, "A quoted string or payload contains a reverse-shell construct."),
    F("substitution_fed_interpreter", "bool", "tradecraft", KIND_INDICATOR, "An interpreter, eval or source runs the output of a retrieval ($(curl ...), <(wget ...))."),
    F("root_filesystem_delete", "bool", "tradecraft", KIND_INDICATOR, "A recursive delete targets / (or --no-preserve-root)."),
    F("system_directory_delete", "bool", "tradecraft", KIND_INDICATOR, "A recursive delete targets a top-level system directory."),
    F("raw_disk_write", "bool", "tradecraft", KIND_INDICATOR, "A block device is overwritten or reformatted (dd of=/dev/sda, mkfs, wipefs)."),
    F("fork_bomb", "bool", "tradecraft", KIND_INDICATOR, "A self-replicating function definition (fork bomb)."),
    F("uid0_account_creation", "bool", "tradecraft", KIND_INDICATOR, "An account is created or modified with uid 0, or a uid-0 line is written to /etc/passwd."),
    F("account_database_write", "bool", "tradecraft", KIND_INDICATOR, "/etc/passwd, /etc/shadow or /etc/group is written directly."),
    F("sudoers_write", "bool", "tradecraft", KIND_INDICATOR, "sudoers configuration is written without visudo."),
    F("log_tampering", "bool", "tradecraft", KIND_INDICATOR, "Log files or login records are deleted, truncated, overwritten or edited in place."),
    F("security_monitoring_disabled", "bool", "tradecraft", KIND_INDICATOR, "Audit, EDR, logging or MAC enforcement is stopped or disabled."),
    F("firewall_disabled", "bool", "tradecraft", KIND_INDICATOR, "Host firewall rules are flushed or the firewall is disabled."),
    F("hidden_temp_path", "bool", "tradecraft", KIND_INDICATOR, "A hidden (dot) file or directory under /tmp, /var/tmp or /dev/shm is used."),
    F("exec_from_temp", "bool", "tradecraft", KIND_INDICATOR, "A program or script located in a temporary directory is executed."),
    F("process_name_masquerade", "bool", "tradecraft", KIND_INDICATOR, "The process name is spoofed (exec -a) or mimics a kernel thread."),
    F("offensive_tool_reference", "bool", "tradecraft", KIND_INDICATOR, "A well-known offensive security / post-exploitation tool is run or fetched."),
    F("offensive_tool_name", "str", "tradecraft", KIND_INDICATOR, "Name of the first offensive tool found.", ""),
    F("crypto_miner_reference", "bool", "tradecraft", KIND_INDICATOR, "A cryptocurrency miner binary, pool or stratum URL is referenced."),
    F("exfil_service_domain", "bool", "tradecraft", KIND_INDICATOR, "A paste, file-drop, tunnel or webhook service is contacted."),
    F("cloud_metadata_access", "bool", "tradecraft", KIND_INDICATOR, "A cloud instance metadata endpoint is contacted."),
    F("cloud_metadata_credential_path", "bool", "tradecraft", KIND_INDICATOR, "The metadata request targets credentials or tokens."),
    F("credential_search", "bool", "tradecraft", KIND_INDICATOR, "A broad or recursive search for credential keywords or key files."),
    F("private_key_file_access", "bool", "tradecraft", KIND_INDICATOR, "A private key file is read, copied or sent by a non-SSH tool."),
    F("ld_preload_env", "bool", "tradecraft", KIND_INDICATOR, "LD_PRELOAD is set for a command or exported."),
    F("setuid_bit_set", "bool", "tradecraft", KIND_INDICATOR, "A setuid/setgid bit is set on a file."),
    F("suid_binary_search", "bool", "tradecraft", KIND_INDICATOR, "The filesystem is searched for setuid/setgid binaries."),
    F("dangerous_capability_grant", "bool", "tradecraft", KIND_INDICATOR, "setcap grants a privilege-equivalent capability."),
    F("host_namespace_entry", "bool", "tradecraft", KIND_INDICATOR, "nsenter joins the namespaces of pid 1 (the host)."),
    F("immutable_attribute_set", "bool", "tradecraft", KIND_INDICATOR, "chattr sets the immutable or append-only attribute."),
    F("tunnel_or_proxy", "bool", "tradecraft", KIND_INDICATOR, "A reverse/dynamic SSH tunnel or tunnelling tool is started."),
    F("noninteractive_remote_auth", "bool", "tradecraft", KIND_INDICATOR, "sshpass or disabled host-key checking is used."),
    F("bulk_encryption", "bool", "tradecraft", KIND_INDICATOR, "Files are encrypted in bulk (find/xargs + openssl enc/gpg -c)."),
    F("aslr_or_ptrace_protection_disabled", "bool", "tradecraft", KIND_INDICATOR, "ASLR or ptrace scope protection is turned off."),
]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _all_commands(ctx: CommandContext) -> List[SimpleCommand]:
    """Top-level and nested simple commands, each once."""
    seen: Set[int] = set()
    out: List[SimpleCommand] = []
    for command in list(ctx.parsed.commands) + [e.command for e in ctx.executions if e.command]:
        if id(command) not in seen:
            seen.add(id(command))
            out.append(command)
    return out


def write_targets(ctx: CommandContext) -> List[str]:
    """Paths this command line writes to: redirects, tee, dd of=, sed -i, cp/mv/install dest."""
    targets: List[str] = []
    for command in _all_commands(ctx):
        for op, target in command.redirects:
            if target and (op.endswith(">") or op.endswith(">>")) and target not in DISCARD_TARGETS:
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


def _quoted_texts(ctx: CommandContext) -> List[str]:
    """Quoted word values and inline script payloads -- where payloads hide."""
    texts = [t.value for t in ctx.parsed.tokens if t.kind == "word" and t.quoted]
    return texts + list(ctx.script_payloads)


def _has_flag(args: List[str], *names: str) -> bool:
    letters = flag_letters(args)
    return any(a in names for a in args) or any(n in letters for n in names)


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------
def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute tradecraft features for one event."""
    lower = ctx.lower
    executions = ctx.executions
    quoted = _quoted_texts(ctx)
    targets = write_targets(ctx)
    lowered_targets = [t.lower() for t in targets]

    # -- reverse shells / C2 ---------------------------------------------------
    dev_tcp = "/dev/tcp/" in lower or "/dev/udp/" in lower
    netcat_exec = False
    listener = False
    for execution in ctx.executions_of("nc", "ncat", "netcat", "socat"):
        args = execution.args
        if execution.basename == "socat":
            joined = " ".join(args).lower()
            netcat_exec = netcat_exec or "exec:" in joined or "system:" in joined
            listener = listener or "listen" in joined
            continue
        if _has_flag(args, "-e", "-c") or any(a.startswith(("--exec", "--sh-exec", "--lua-exec"))
                                              for a in args):
            netcat_exec = True
        if _has_flag(args, "-l") or "--listen" in args:
            listener = True
    socket_payload = any(SOCKET_CONNECT_RE.search(p) and SOCKET_SHELL_RE.search(p)
                         for p in ctx.script_payloads)
    fifo_relay = (ctx.uses("mkfifo") or any(e.basename == "mknod" and "p" in e.args for e in executions)) \
        and any(b in SHELLS for b in ctx.basenames) \
        and ctx.uses("nc", "ncat", "netcat", "socat", "openssl", "telnet")

    embedded_dl = any(EMBEDDED_DOWNLOAD_EXEC_RE.search(t) for t in quoted)
    embedded_rs = any(EMBEDDED_REVERSE_SHELL_RE.search(t) for t in quoted) or any(
        SOCKET_CONNECT_RE.search(t) and SOCKET_SHELL_RE.search(t) for t in quoted)

    substitution_fed = False
    for execution in executions:
        if execution.basename in SHELLS or execution.basename in SCRIPT_INTERPRETERS \
                or execution.basename in ("eval", "source", "."):
            if any(SUBSTITUTION_RETRIEVAL_RE.search(a) for a in execution.args):
                substitution_fed = True

    # -- destruction -----------------------------------------------------------
    root_delete = system_delete = False
    for execution in ctx.executions_of("rm"):
        args = execution.args
        recursive = _has_flag(args, "-r", "-R") or "--recursive" in args
        if "--no-preserve-root" in args:
            root_delete = True
        if not recursive:
            continue
        for target in execution.positionals:
            clean = target.rstrip("/") or "/"
            if target in ROOT_TARGETS or clean in ("/", "/*"):
                root_delete = True
            elif clean.rstrip("/*") in SYSTEM_DIRECTORIES:
                system_delete = True
    raw_disk = any(DISK_DEVICE_RE.match(t) for t in targets)
    for execution in executions:
        if execution.basename.startswith("mkfs") or execution.basename in ("wipefs", "blkdiscard"):
            raw_disk = raw_disk or any(DISK_DEVICE_RE.match(p) for p in execution.positionals)
    fork_bomb = bool(FORK_BOMB_RE.search(ctx.raw))

    # -- accounts and privilege -------------------------------------------------
    uid0 = False
    for execution in ctx.executions_of("useradd", "adduser", "usermod"):
        args = execution.args
        for index, token in enumerate(args):
            if token in ("-u", "--uid") and index + 1 < len(args) and args[index + 1] == "0":
                uid0 = True
            if token in ("--uid=0",):
                uid0 = True
        if "-o" in args and ("-u" in args or "--uid" in args) and any(a == "0" for a in args):
            uid0 = True
    account_write = any(_matches(t, ACCOUNT_DATABASES) for t in lowered_targets)
    if account_write and re.search(r":0:0?:", ctx.raw):
        uid0 = True
    sudoers_write = any(_matches(t, SUDOERS_PATHS) for t in lowered_targets) and not ctx.uses("visudo")

    chmod_args = [a for e in ctx.executions_of("chmod", "install") for a in e.args]
    setuid_set = any(
        re.fullmatch(r"[ugoa]*\+[rwxt]*s[rwxt]*", a) or re.fullmatch(r"[ugo]*=[rwx]*s[rwx]*", a)
        or re.fullmatch(r"0?[246][0-7]{3}", a)
        for a in chmod_args
    )
    suid_search = any(
        "-perm" in e.args and any(re.search(r"(^|[-/])(u=s|g=s|[246]000)$", a) for a in e.args)
        for e in ctx.executions_of("find")
    )
    dangerous_cap = ctx.uses("setcap") and any(cap in lower for cap in DANGEROUS_CAPABILITIES)
    host_ns = any(
        any(a in ("-t", "--target") and i + 1 < len(e.args) and e.args[i + 1] == "1"
            for i, a in enumerate(e.args)) or "--target=1" in e.args or "-t1" in e.args
        for e in ctx.executions_of("nsenter")
    )
    immutable = any(re.fullmatch(r"\+[aiA-Z]*[ia][a-zA-Z]*", a) for e in ctx.executions_of("chattr")
                    for a in e.args)
    ld_preload = any(a.startswith("LD_PRELOAD=") for e in executions for a in e.assignments) or \
        any(a.startswith("LD_PRELOAD=") for e in ctx.executions_of("export", "env") for a in e.args) or \
        bool(re.search(r"(^|[\s;&|])LD_PRELOAD=", ctx.raw))

    # -- defense evasion ---------------------------------------------------------
    log_tamper = any(_matches(t, LOG_ARTIFACTS) for t in lowered_targets)
    for execution in ctx.executions_of("rm", "shred", "unlink", "truncate", "srm", "wipe"):
        if any(_matches(p, LOG_ARTIFACTS) for p in execution.positionals):
            log_tamper = True
    for execution in ctx.executions_of("journalctl"):
        if any(a.startswith(("--vacuum", "--rotate")) for a in execution.args):
            log_tamper = True

    monitoring_off = firewall_off = False
    for execution in executions:
        base, args = execution.basename, [a.lower() for a in execution.args]
        if base == "setenforce" and args[:1] in (["0"], ["permissive"]):
            monitoring_off = True
        if base == "auditctl" and ("-D" in execution.args or args[:2] == ["-e", "0"]):
            monitoring_off = True
        if base == "systemctl" and args and args[0] in ("stop", "disable", "mask", "kill"):
            units = [u.replace(".service", "") for u in args[1:] if not u.startswith("-")]
            if any(u in SECURITY_SERVICES for u in units):
                monitoring_off = True
            if any(u in FIREWALL_SERVICES for u in units):
                firewall_off = True
        if base == "service" and len(args) >= 2 and args[1] == "stop":
            if args[0] in SECURITY_SERVICES:
                monitoring_off = True
            if args[0] in FIREWALL_SERVICES:
                firewall_off = True
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
    if "selinux=disabled" in lower.replace(" ", "") and any("selinux" in t for t in lowered_targets):
        monitoring_off = True
    if ("selinux=disabled" in lower.replace(" ", "") or "selinux=permissive" in lower.replace(" ", "")) \
            and any("/etc/selinux" in p.lowered for p in ctx.paths):
        monitoring_off = True
    aslr_off = bool(re.search(r"randomize_va_space\s*=?\s*['\"]?0\b", lower)) or \
        bool(re.search(r"echo\s+['\"]?0['\"]?\s*>+\s*/proc/sys/kernel/randomize_va_space", lower)) or \
        bool(re.search(r"ptrace_scope\s*=?\s*['\"]?0\b", lower)) or \
        bool(re.search(r"echo\s+['\"]?0['\"]?\s*>+\s*/proc/sys/kernel/yama/ptrace_scope", lower))

    hidden_temp = False
    for path in ctx.paths:
        low = path.lowered
        if low.startswith(TEMP_PREFIXES):
            parts = low.split("/")[2:] if not low.startswith("/dev/shm/") else low.split("/")[3:]
            if any(part.startswith(".") and part not in (".", "..") and part not in BENIGN_TEMP_DOTDIRS
                   for part in parts):
                hidden_temp = True
    temp_exec = any(e.name.lower().startswith(TEMP_PREFIXES) for e in executions) or any(
        (e.basename in SHELLS or e.basename in SCRIPT_INTERPRETERS or e.basename in ("source", "."))
        and e.positionals and e.positionals[0].lower().startswith(TEMP_PREFIXES)
        for e in executions
    )
    masquerade = any(e.basename == "exec" and "-a" in e.args for e in executions) or any(
        KERNEL_THREAD_NAMES.match(e.basename) and "/" in e.name for e in executions)

    # -- tooling and destinations ------------------------------------------------
    candidate_names: List[str] = [e.basename for e in executions]
    for path in ctx.paths:
        stem = path.basename.lower()
        candidate_names.append(stem.rsplit(".", 1)[0] if "." in stem else stem)
    for url in ctx.urls:
        tail = url.path.rstrip("/").rsplit("/", 1)[-1].lower()
        if tail:
            candidate_names.append(tail.rsplit(".", 1)[0] if "." in tail else tail)
    offensive_name = next((n for n in candidate_names
                           if n in OFFENSIVE_TOOLS or n.startswith("impacket-")), "")
    miner = any(n in MINER_TOOLS for n in candidate_names) or any(t in lower for t in MINER_TEXT)
    exfil_domain = any(d in lower for d in EXFIL_DOMAINS)
    metadata = any(ep in lower for ep in METADATA_ENDPOINTS)
    metadata_creds = metadata and any(p in lower for p in METADATA_CREDENTIAL_PATHS)

    credential_search = False
    for execution in ctx.executions_of("grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "locate"):
        args = execution.args
        joined = " ".join(args)
        recursive = _has_flag(args, "-r", "-R") or "--recursive" in args or execution.basename in ("rg", "ag", "ack")
        broad = any(p.rstrip("/") in BROAD_SEARCH_ROOTS or p in ("/", "~/") for p in execution.positionals)
        if execution.basename in ("find", "locate"):
            if CREDENTIAL_FILE_GLOB_RE.search(joined) and (broad or execution.basename == "locate"):
                credential_search = True
        elif CREDENTIAL_SEARCH_RE.search(joined) and recursive and broad:
            credential_search = True

    private_key = False
    for execution in executions:
        if execution.basename not in READ_TOOLS:
            continue
        for index, arg in enumerate(execution.args):
            if index > 0 and execution.args[index - 1] == "-i":
                continue
            low = arg.lower()
            if SSH_PRIVATE_KEY_RE.search(low) or (
                    low.endswith((".pem", ".key", ".ppk")) and _matches(low, PRIVATE_KEY_DIRS)):
                private_key = True
    for command in _all_commands(ctx):
        for op, target in command.redirects:
            if op == "<" and SSH_PRIVATE_KEY_RE.search(target.lower()):
                private_key = True

    tunnel = False
    for execution in ctx.executions_of("ssh"):
        if _has_flag(execution.args, "-R", "-D", "-w"):
            tunnel = True
    if ctx.uses("ngrok", "chisel", "frpc", "frps", "gost", "iodine", "dnscat", "dnscat2",
                "ptunnel", "bore", "rathole") or \
            any(e.basename == "cloudflared" and "tunnel" in e.args for e in executions):
        tunnel = True
    if any(e.basename == "socat" and sum(1 for a in e.args if re.match(r"(?i)tcp[46]?(-listen)?:", a)) >= 2
           for e in executions):
        tunnel = True
    noninteractive_auth = ctx.uses("sshpass") or "stricthostkeychecking=no" in lower.replace(" ", "")

    encrypts = any(e.basename == "openssl" and e.args[:1] == ["enc"] for e in executions) or any(
        e.basename in ("gpg", "gpg2") and (_has_flag(e.args, "-c") or "--symmetric" in e.args
                                           or "--encrypt" in e.args) for e in executions) or \
        ctx.uses("ccrypt", "age") or bool(BULK_ENCRYPT_RE.search(lower))
    bulk = encrypts and (ctx.uses("find", "xargs", "parallel") or "for " in lower)

    return {
        "dev_tcp_redirect": int(dev_tcp),
        "netcat_exec_flag": int(netcat_exec),
        "socket_shell_payload": int(bool(socket_payload)),
        "named_pipe_shell_relay": int(bool(fifo_relay)),
        "socket_listener": int(listener),
        "embedded_download_exec": int(embedded_dl),
        "embedded_reverse_shell": int(bool(embedded_rs)),
        "substitution_fed_interpreter": int(substitution_fed),
        "root_filesystem_delete": int(root_delete),
        "system_directory_delete": int(system_delete),
        "raw_disk_write": int(raw_disk),
        "fork_bomb": int(fork_bomb),
        "uid0_account_creation": int(uid0),
        "account_database_write": int(account_write),
        "sudoers_write": int(sudoers_write),
        "log_tampering": int(log_tamper),
        "security_monitoring_disabled": int(monitoring_off),
        "firewall_disabled": int(firewall_off),
        "hidden_temp_path": int(hidden_temp),
        "exec_from_temp": int(temp_exec),
        "process_name_masquerade": int(bool(masquerade)),
        "offensive_tool_reference": int(bool(offensive_name)),
        "offensive_tool_name": offensive_name,
        "crypto_miner_reference": int(miner),
        "exfil_service_domain": int(exfil_domain),
        "cloud_metadata_access": int(metadata),
        "cloud_metadata_credential_path": int(metadata_creds),
        "credential_search": int(credential_search),
        "private_key_file_access": int(private_key),
        "ld_preload_env": int(ld_preload),
        "setuid_bit_set": int(bool(setuid_set)),
        "suid_binary_search": int(suid_search),
        "dangerous_capability_grant": int(bool(dangerous_cap)),
        "host_namespace_entry": int(host_ns),
        "immutable_attribute_set": int(immutable),
        "tunnel_or_proxy": int(tunnel),
        "noninteractive_remote_auth": int(noninteractive_auth),
        "bulk_encryption": int(bool(bulk)),
        "aslr_or_ptrace_protection_disabled": int(aslr_off),
    }
