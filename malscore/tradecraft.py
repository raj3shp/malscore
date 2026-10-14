"""Tradecraft features: command shapes documented in public attack write-ups.

The generic feature groups in :mod:`malscore.features` describe *what* a command
touches.  This module recognises specific, well-known techniques -- reverse
shells, destructive disk writes, credential hunting, disabling audit tooling --
whose shape is distinctive enough that a structural check is far more precise
than combining generic indicators.  Features are observations, never verdicts.
"""

from __future__ import annotations

import re
from typing import Dict, List, Sequence

from .context import (
    INTERPRETERS,
    SHELLS,
    TEMP_PREFIXES,
    CommandContext,
    all_commands,
    has_flag,
    path_has_prefix,
    write_targets,
)

Record = Dict[str, object]

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

# -- additional techniques (ATT&CK / GTFOBins) -----------------------------------
GREP_TOOLS = ("grep", "egrep", "fgrep", "rg", "ag", "ack", "pcregrep", "findstr")
#: File extensions that mark a configuration file worth searching for secrets.
CONFIG_EXTENSIONS = frozenset({"properties", "conf", "cfg", "ini", "env", "yaml", "yml",
                               "json", "xml", "toml", "config"})
#: Credential files whose *read* (not mere reference) is strong evidence.
CRED_FILE_BASENAMES = frozenset({".pgpass", ".netrc", ".my.cnf", ".git-credentials",
                                 ".vault-token", ".boto", ".s3cfg"})
CRED_FILE_SUBPATHS = (".aws/credentials", ".docker/config.json", ".kube/config", "credentials.json")
HISTORY_READ_FILES = frozenset({".bash_history", ".zsh_history", ".sh_history", ".history",
                                ".python_history", ".mysql_history", ".psql_history", ".rediscli_history"})
#: Looser keyword set for the narrow "dump the environment, grep it" shape.
ENV_SECRET_RE = re.compile(r"(?i)(pass|secret|token|key|cred|api[_-]?)")
PROC_ENVIRON_RE = re.compile(r"/proc/(?:\d+|self)/environ")
#: Literal needles that appear when hunting for provider key / token formats.
SECRET_PATTERN_NEEDLES = ("akia[0-9a-z", "akia[a-z0-9", "xox[bp]", "ghp_", "-----begin",
                          "begin rsa private", "begin openssh private", "aws_secret_access_key")
SSH_AGENT_RE = re.compile(r"SSH_AUTH_SOCK=['\"]?(?:/tmp/|/var/tmp/|/dev/shm/)")

DB_CLIENTS = ("psql", "mysql", "mariadb", "mongo", "mongosh", "sqlite3", "clickhouse-client", "cqlsh", "redis-cli")
DUMP_TOOLS = ("pg_dump", "pg_dumpall", "mysqldump", "mongodump", "mongoexport")
COMPRESSORS = {"gzip": ".gz", "bzip2": ".bz2", "xz": ".xz", "zstd": ".zst", "lz4": ".lz4", "compress": ".Z"}
#: Table/column names that denote regulated or secret data (word-bounded).
SENSITIVE_TABLE_RE = re.compile(
    r"(?i)\b(card(holder|_?number)?|pan|cvv|cvc|ssn|tokens?|passw(or)?ds?|secrets?|credentials?|"
    r"customers?|cardholders?|iban|accounts?)\b")
#: Regex *as typed into a search tool* for card numbers or SSNs.
DATA_PATTERN_RE = re.compile(
    r"(?:\[0-9\]|\\d)\s*\{\s*1[3-9]\s*\}|4\[0-9\]\{15\}|"
    r"(?:\[0-9\]|\\d)\{3\}[- ]?(?:\[0-9\]|\\d)\{2\}[- ]?(?:\[0-9\]|\\d)\{4\}")
DB_DESTROY_RE = re.compile(
    r"(?i)\b(?:drop\s+(?:table|database|schema)|truncate\s+(?:table\s+)?\w|"
    r"delete\s+from\s+[\w.\"'`]+\s*(?:;|$))")
PATH_HIJACK_RE = re.compile(r"(?:^|[\s;&|(])PATH=['\"]?(?:\.|/tmp|/var/tmp|/dev/shm)(?=[:/\s'\"]|$)")
SUDO_UID_BYPASS_RE = re.compile(r"(?:-u|--user[= ])\s*#\s*(?:-1|4294967295)")
IMMUTABLE_REMOVE_RE = re.compile(r"-[A-Za-z]*[ia][A-Za-z]*$")
#: Security products, in the short forms people actually grep for.
SECURITY_DISCOVERY_NEEDLES = ("falcon", "crowdstrike", "auditd", "osquery", "wazuh", "ossec",
                              "sentinelone", "sentinel-agent", "carbonblack", "cbagent", "clamav",
                              "clamd", "tripwire", "aide", "mdatp", "defender", "qualys", "datadog",
                              "splunk", "nessus", "sysmon", "elastic-agent", "filebeat", "auditbeat")
SANDBOX_NEEDLES = ("/proc/1/cgroup", "/.dockerenv", "systemd-detect-virt", "/sys/hypervisor",
                   "system-product-name", "/proc/xen", "container=")
#: Paths whose write installs a login/execution hook.
PERSISTENCE_HOOK_PREFIXES = ("/etc/update-motd.d", "/etc/apt/apt.conf.d", "/etc/xdg/autostart",
                             "~/.config/autostart", "/etc/profile.d", "/usr/lib/update-notifier")
PERSISTENCE_HOOK_SUBPATHS = (".ssh/rc", ".git/hooks/", ".config/autostart")
ALIAS_HIJACK_RE = re.compile(r"(?i)alias\s+(sudo|ssh|ls|cat|cd)\s*=")
DNS_TOOLS = ("dig", "nslookup", "host", "drill", "dog", "kdig")
ENCODERS = ("base64", "base32", "xxd", "openssl", "gzip", "bzip2", "xz", "zstd")
EXFIL_SINKS = ("curl", "wget", "nc", "ncat", "netcat", "socat")
#: Spelled as a regex so the literal call text never appears in this source
#: (the non-execution safety test greps for it).
TTY_UPGRADE_RE = re.compile(r"pty\.(?:spawn|openpty)|import\s+pty|tty\.setraw|spawn\s+/bin/")
FILELESS_NEEDLES = ("memfd_create", "/proc/self/fd/", "/dev/fd/")
GTFO_INTERPRETERS = ("perl", "ruby", "lua", "php")


def _reverse_shells(ctx: CommandContext) -> Record:
    netcat_exec = listener = False
    for execution in ctx.executions_of("nc", "ncat", "netcat", "socat"):
        args = execution.args
        if execution.basename == "socat":
            joined = " ".join(args).lower()
            netcat_exec = netcat_exec or "exec:" in joined or "system:" in joined
            listener = listener or "listen" in joined
            continue
        if has_flag(args, "-e", "-c") or any(a.startswith(("--exec", "--sh-exec", "--lua-exec")) for a in args):
            netcat_exec = True
        if has_flag(args, "-l") or "--listen" in args:
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
        if not (has_flag(args, "-r", "-R") or "--recursive" in args):
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
    account_write = any(path_has_prefix(t, ACCOUNT_DATABASES) for t in targets)
    if account_write and UID0_LINE_RE.search(ctx.raw):
        uid0 = True

    chmod_args = [a for e in ctx.executions_of("chmod", "install") for a in e.args]
    return {
        "uid0_account_creation": int(uid0),
        "account_database_write": int(account_write),
        "sudoers_write": int(any(path_has_prefix(t, SUDOERS_PATHS) for t in targets) and not ctx.uses("visudo")),
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
    log_tamper = any(path_has_prefix(t, LOG_ARTIFACTS) for t in targets) or any(
        path_has_prefix(p, LOG_ARTIFACTS)
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
                has_flag(execution.args, "-F") or "--flush" in args
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
                has_flag(args, "-r", "-R") or "--recursive" in args or execution.basename in ("rg", "ag", "ack")):
            credential_search = True

    private_key = any(op == "<" and SSH_PRIVATE_KEY_RE.search(target.lower())
                      for command in all_commands(ctx) for op, target in command.redirects)
    for execution in ctx.executions:
        if execution.basename not in READ_TOOLS:
            continue
        for index, arg in enumerate(execution.args):
            if index > 0 and execution.args[index - 1] == "-i":
                continue
            low = arg.lower()
            if SSH_PRIVATE_KEY_RE.search(low) or (
                    low.endswith((".pem", ".key", ".ppk")) and path_has_prefix(low, PRIVATE_KEY_DIRS)):
                private_key = True

    tunnel = ctx.uses(*TUNNEL_TOOLS) \
        or any(has_flag(e.args, "-R", "-D", "-w") for e in ctx.executions_of("ssh")) \
        or any(e.basename == "cloudflared" and "tunnel" in e.args for e in ctx.executions) \
        or any(e.basename == "socat" and sum(1 for a in e.args if SOCAT_TCP_RE.match(a)) >= 2
               for e in ctx.executions)

    encrypts = any(e.basename == "openssl" and e.args[:1] == ["enc"] for e in ctx.executions) or any(
        e.basename in ("gpg", "gpg2") and (has_flag(e.args, "-c") or "--symmetric" in e.args
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


def _db_sql(ctx: CommandContext) -> str:
    """Argument text of database clients and dump tools (holds the SQL / tables)."""
    return " ".join(a for e in ctx.executions_of(*DB_CLIENTS, *DUMP_TOOLS) for a in e.args)


def _staged_paths(ctx: CommandContext) -> List[str]:
    """Paths this command writes, including an archive/compressor's renamed output."""
    paths = list(write_targets(ctx))
    for execution in ctx.executions:
        base = execution.basename
        if base in COMPRESSORS and not (has_flag(execution.args, "-d", "-c")
                                        or "--decompress" in execution.args or "--stdout" in execution.args):
            paths.extend(p + COMPRESSORS[base] for p in execution.positionals)
        elif base in ("zip", "7z", "7za", "rar") and execution.positionals:
            paths.append(execution.positionals[0])
    return paths


def _credential_access(ctx: CommandContext) -> Record:
    greps = ctx.executions_of(*GREP_TOOLS)
    config_present = any(p.extension in CONFIG_EXTENSIONS for p in ctx.paths)
    keyword_search = secret_pattern = False
    for execution in greps:
        joined = " ".join(execution.args)
        recursive = has_flag(execution.args, "-r", "-R") or "--recursive" in execution.args \
            or execution.basename in ("rg", "ag", "ack")
        if CREDENTIAL_SEARCH_RE.search(joined) and (recursive or config_present):
            keyword_search = True
        if any(n in joined.lower() for n in SECRET_PATTERN_NEEDLES):
            secret_pattern = True

    cred_file_read = False
    for execution in ctx.executions_of(*READ_TOOLS):
        for arg in execution.positionals:
            low = arg.lower().rstrip("/")
            if low.rsplit("/", 1)[-1] in CRED_FILE_BASENAMES or any(sp in low for sp in CRED_FILE_SUBPATHS):
                cred_file_read = True

    env_dump = ctx.uses("env", "printenv", "set") and any(ENV_SECRET_RE.search(" ".join(e.args)) for e in greps)
    environ_file = any(PROC_ENVIRON_RE.search(p.lowered) for p in ctx.paths)
    history_read = ctx.uses(*READ_TOOLS) and any(
        p.basename.lower() in HISTORY_READ_FILES and not p.from_redirect for p in ctx.paths)

    return {
        "credential_keyword_search": int(keyword_search),
        "credential_file_read": int(cred_file_read),
        "environment_secret_read": int(env_dump or environ_file),
        "shell_history_read": int(history_read),
        "ssh_agent_hijack": int(bool(SSH_AGENT_RE.search(ctx.raw))),
        "secret_pattern_search": int(secret_pattern),
    }


def _sudo_target(execution) -> str:
    """The ``-u``/``--user`` value in the wrapper prefix; '' when none (i.e. root)."""
    argv = execution.command.argv if execution.command is not None else []
    prefix = argv[:max(0, len(argv) - len(execution.argv))]
    for index, token in enumerate(prefix):
        if token in ("-u", "--user") and index + 1 < len(prefix):
            return prefix[index + 1]
        if token.startswith("--user="):
            return token.split("=", 1)[1]
        if token.startswith("-u") and len(token) > 2 and not token.startswith("--"):
            return token[2:]
    return ""


def _shell_escape(ctx: CommandContext) -> bool:
    """A non-shell program is used to spawn a shell (GTFOBins style)."""
    for execution in ctx.executions_of("find"):
        args = execution.args
        for index, arg in enumerate(args):
            if arg in ("-exec", "-execdir", "-ok") and index + 1 < len(args):
                if args[index + 1].rsplit("/", 1)[-1] in SHELLS:
                    return True
    awk = " ".join(a for e in ctx.executions_of("awk", "gawk", "mawk", "nawk") for a in e.args)
    if "system(" in awk or re.search(r"print\s*\|\s*[\"']", awk):
        return True
    for execution in ctx.executions_of("vi", "vim", "nvim", "view", "rvim"):
        joined = " ".join(execution.args)
        if re.search(r":!|:shell|:py|system\(|/bin/(?:ba)?sh", joined):
            return True
    if any("--checkpoint-action" in a or a.startswith("--to-command") for e in ctx.executions_of("tar") for a in e.args):
        return True
    if any("--interactive" in e.args for e in ctx.executions_of("nmap")):
        return True
    for execution in ctx.executions_of(*GTFO_INTERPRETERS):
        if re.search(r"exec\s*\(?\s*[\"']/?(?:usr/)?bin/(?:ba|da|z|k)?sh", " ".join(execution.args)):
            return True
    for execution in ctx.executions:
        if "xargs" in execution.wrappers and execution.basename in SHELLS:
            return True
    return False


def _privilege_shells(ctx: CommandContext) -> Record:
    root_shell = other_shell = False
    for execution in ctx.executions_of("sudo", "doas"):
        if has_flag(execution.args, "-i", "-s") or "--login" in execution.args or "--shell" in execution.args:
            root_shell = True
    for execution in ctx.executions:
        if execution.basename in SHELLS and ({"sudo", "doas"} & set(execution.wrappers)):
            if _sudo_target(execution).lower() in ("", "root", "0"):
                root_shell = True
            else:
                other_shell = True
    for execution in ctx.executions_of("su", "runuser"):
        positionals = [a for a in execution.args if not a.startswith("-")]
        target = (_sudo_target(execution) or (positionals[0] if positionals else "")) \
            if execution.basename == "runuser" else (positionals[0] if positionals else "")
        if target.lower() in ("", "root"):
            root_shell = True
        else:
            other_shell = True

    sudo_present = ctx.uses("sudo", "doas") or any({"sudo", "doas"} & set(e.wrappers) for e in ctx.executions)
    escape = _shell_escape(ctx)
    return {
        "interactive_root_shell": int(root_shell),
        "shell_as_other_user": int(other_shell),
        "shell_escape": int(escape and not sudo_present),
        "privileged_shell_escape": int(escape and sudo_present),
        "sudo_uid_bypass": int(bool(SUDO_UID_BYPASS_RE.search(ctx.raw))),
        "path_hijack": int(bool(PATH_HIJACK_RE.search(ctx.raw))),
        "writable_path_search": int(any(
            "-writable" in e.args
            or any(a in ("-2", "-0002", "-o+w", "/2", "/0002", "-perm/2") for a in e.args)
            or any(prev == "-perm" and a in ("-2", "-0002", "-o+w", "/2", "/0002")
                   for prev, a in zip(e.args, e.args[1:]))
            for e in ctx.executions_of("find"))),
    }


def _execution_techniques(ctx: CommandContext) -> Record:
    text = ctx.lower
    tty = bool(TTY_UPGRADE_RE.search(ctx.scan_text)) \
        or any("/dev/null" in e.args for e in ctx.executions_of("script")) \
        or bool(re.search(r"stty\s+(?:raw\s+-echo|-echo\s+raw|raw;|-echo;)", text)) \
        or any(e.basename == "socat" and any("pty" in a.lower() for a in e.args) for e in ctx.executions)
    return {
        "tty_shell_upgrade": int(tty),
        "fileless_execution": int(any(n in ctx.scan_text for n in FILELESS_NEEDLES)),
    }


def _discovery_extra(ctx: CommandContext) -> Record:
    text = ctx.lower
    listing = ctx.uses("ps", "pgrep", "pidof", "top", "htop") or bool(ctx.executions_of(*GREP_TOOLS)) \
        or any(a in ("status", "is-active", "list-units", "list-unit-files")
               for e in ctx.executions_of("systemctl", "service") for a in e.args)
    security_discovery = listing and any(n in text for n in SECURITY_DISCOVERY_NEEDLES) \
        and not on_disabled(ctx)
    ssh_recon = ctx.uses(*READ_TOOLS) and any(
        "/.ssh/known_hosts" in p.lowered or "/.ssh/config" in p.lowered or p.basename.lower() == "known_hosts"
        for p in ctx.paths if not p.from_redirect)
    return {
        "security_software_discovery": int(security_discovery),
        "ssh_target_discovery": int(ssh_recon),
        "sandbox_check": int(any(n in text for n in SANDBOX_NEEDLES)),
    }


def on_disabled(ctx: CommandContext) -> bool:
    """True when the command stops/disables a service (handled as evasion, not discovery)."""
    return any(a in ("stop", "disable", "mask", "kill") for e in ctx.executions_of("systemctl", "service") for a in e.args) \
        or ctx.uses("pkill", "killall", "setenforce", "auditctl")


def _collection(ctx: CommandContext) -> Record:
    sql = _db_sql(ctx)
    db_dump = bool(ctx.executions_of(*DUMP_TOOLS)) \
        or any(e.basename == "redis-cli" and "--rdb" in e.args for e in ctx.executions) \
        or any(e.basename == "sqlite3" and any(".dump" in a for a in e.args) for e in ctx.executions)
    grep_awk = " ".join(a for e in ctx.executions_of(*GREP_TOOLS, "awk", "gawk", "mawk", "nawk") for a in e.args)
    pan_search = bool(DATA_PATTERN_RE.search(grep_awk))
    sensitive_table = bool(sql) and bool(SENSITIVE_TABLE_RE.search(sql))
    staged = _staged_paths(ctx)
    in_temp = (db_dump or pan_search) and any(path_has_prefix(p, TEMP_PREFIXES) for p in staged)
    capture = ctx.uses("scrot", "gnome-screenshot", "xwd", "maim", "flameshot") \
        or any(has_flag(e.args, "-o", "-out") for e in ctx.executions_of("xclip", "xsel")) \
        or any("-window" in e.args for e in ctx.executions_of("import"))
    return {
        "database_dump": int(db_dump),
        "sensitive_table_access": int(sensitive_table),
        "sensitive_data_pattern_search": int(pan_search),
        "data_staged_in_temp": int(bool(in_temp)),
        "clipboard_or_screen_capture": int(capture),
        "written_paths": "\n".join(staged),
    }


def _pipeline_feeds(ctx: CommandContext, sources: Sequence[str], sinks: Sequence[str]) -> bool:
    """True when a stage running one of ``sources`` pipes into one running a ``sink``."""
    source_cmds = [e.command for e in ctx.executions_of(*sources) if e.command is not None]
    sink_cmds = [e.command for e in ctx.executions_of(*sinks) if e.command is not None]
    for src in source_cmds:
        if src.pipeline_length <= 1:
            continue
        for sink in sink_cmds:
            if sink.pipeline_id == src.pipeline_id and sink.pipeline_index > src.pipeline_index:
                return True
    return False


def _exfil_extra(ctx: CommandContext) -> Record:
    dns = False
    for execution in ctx.executions_of(*DNS_TOOLS):
        for arg in execution.positionals:
            if "$(" in arg or "`" in arg:
                dns = True
            label = arg.split(".", 1)[0]
            if len(label) >= 20 and re.fullmatch(r"[0-9a-fA-F]+|[A-Za-z0-9+/=_-]+", label) and not label.isalpha():
                dns = True
    encoders = [e for e in ctx.executions_of(*ENCODERS)
                if not (e.basename in ("base64", "base32") and has_flag(e.args, "-d") or "--decode" in e.args)]
    encoded = bool(encoders) and _pipeline_feeds(ctx, ENCODERS, EXFIL_SINKS)
    return {
        "dns_exfiltration": int(dns),
        "encoded_exfiltration": int(encoded),
    }


def _evasion_extra(ctx: CommandContext, targets: List[str]) -> Record:
    immutable_removed = any(
        IMMUTABLE_REMOVE_RE.fullmatch(a) for e in ctx.executions_of("chattr") for a in e.args) \
        and any(path_has_prefix(t, SYSTEM_DIRECTORIES + LOG_ARTIFACTS) for t in targets + [p.raw for p in ctx.paths])
    proc_hide = any(e.basename == "mount" and ("--bind" in e.args or ("bind" in e.args and "-o" in e.args))
                    and any("/proc/" in a for a in e.positionals) for e in ctx.executions)
    return {
        "immutable_attribute_removed": int(bool(immutable_removed)),
        "proc_mount_hiding": int(bool(proc_hide)),
    }


def _persistence_extra(ctx: CommandContext, targets: List[str]) -> Record:
    hook = any(path_has_prefix(t, PERSISTENCE_HOOK_PREFIXES) or any(sp in t.lower() for sp in PERSISTENCE_HOOK_SUBPATHS)
               for t in targets) \
        or any("--user" in e.args and "enable" in e.args for e in ctx.executions_of("systemctl")) \
        or bool(ALIAS_HIJACK_RE.search(ctx.raw))
    return {"persistence_hook_write": int(bool(hook))}


def _impact_extra(ctx: CommandContext) -> Record:
    db_destroy = bool(DB_DESTROY_RE.search(_db_sql(ctx)))
    mass_kill = any(e.basename == "killall5" for e in ctx.executions) or any(
        "-1" in e.args and any(s in e.args for s in ("-9", "-KILL", "-SIGKILL", "-15", "-TERM"))
        for e in ctx.executions_of("kill"))
    return {
        "database_destruction": int(db_destroy),
        "mass_process_kill": int(bool(mass_kill)),
    }


def tradecraft(ctx: CommandContext) -> Record:
    """Command shapes documented in public attack write-ups."""
    targets = write_targets(ctx)
    record = _reverse_shells(ctx)
    record.update(_destruction(ctx, targets))
    record.update(_accounts_and_privilege(ctx, targets))
    record.update(_defense_evasion(ctx, targets))
    record.update(_tooling_and_destinations(ctx))
    record.update(_credential_access(ctx))
    record.update(_privilege_shells(ctx))
    record.update(_execution_techniques(ctx))
    record.update(_discovery_extra(ctx))
    record.update(_collection(ctx))
    record.update(_exfil_extra(ctx))
    record.update(_evasion_extra(ctx, targets))
    record.update(_persistence_extra(ctx, targets))
    record.update(_impact_extra(ctx))
    return record
