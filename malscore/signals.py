"""The signal catalogue: which features count as evidence, and how much.

A :class:`Signal` is a named predicate over one feature record plus a weight in
``(0, 1]``.  The weight reads as "how likely is this command to be hostile if
this were the only thing we knew about it".  Weights were set by hand from
public attack write-ups; they are a starting point, not a trained model.

Signals are grouped by MITRE ATT&CK tactic so a report can say *what kind* of
activity was seen, and each carries the technique ids an analyst would look up.

Rules of thumb used when choosing weights:

* ``>= 0.75`` -- the shape alone is rarely legitimate (reverse shell, wiping a disk);
* ``0.4 - 0.7`` -- legitimate uses exist but are uncommon (curl | sh, sudoers edit);
* ``0.15 - 0.35`` -- routine for admins, meaningful in combination (useradd, nmap);
* ``< 0.15`` -- context only; never enough to raise a score on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple, Union

Record = Dict[str, object]
Test = Callable[[Record], bool]

EXECUTION = "execution"
PERSISTENCE = "persistence"
PRIVILEGE_ESCALATION = "privilege-escalation"
DEFENSE_EVASION = "defense-evasion"
CREDENTIAL_ACCESS = "credential-access"
DISCOVERY = "discovery"
LATERAL_MOVEMENT = "lateral-movement"
COLLECTION = "collection"
COMMAND_AND_CONTROL = "command-and-control"
EXFILTRATION = "exfiltration"
IMPACT = "impact"


@dataclass(frozen=True)
class Signal:
    """One piece of evidence the scorer can find in a feature record."""

    id: str
    title: str
    weight: float
    tactic: str
    techniques: Tuple[str, ...]
    test: Test


def on(record: Record, *names: str) -> bool:
    """True when any of the named features is set."""
    return any(record.get(name) not in (None, 0, "", -1, 0.0, False) for name in names)


def every(record: Record, *names: str) -> bool:
    """True when all of the named features are set."""
    return all(on(record, name) for name in names)


def _s(id: str, title: str, weight: float, tactic: str, techniques: Tuple[str, ...],
       test: Union[Test, Tuple[str, ...]] = ()) -> Signal:
    """Signal shorthand; a tuple of feature names fires when any of them is set."""
    if not callable(test):
        names = test
        test = lambda r: on(r, *names)  # noqa: E731
    return Signal(id, title, weight, tactic, techniques, test)


def _download_to_interpreter(r: Record) -> bool:
    return on(r, "network_to_shell_pipeline", "network_to_interpreter_pipeline",
              "substitution_fed_interpreter")


SIGNALS: List[Signal] = [
    # -- execution / ingress ----------------------------------------------------
    _s("download_pipe_interpreter", "Remote content is executed directly by an interpreter", 0.55,
       EXECUTION, ("T1059.004", "T1105"),
       ("network_to_shell_pipeline", "network_to_interpreter_pipeline", "substitution_fed_interpreter")),
    _s("download_then_execute", "A downloaded file is made executable or run", 0.5,
       EXECUTION, ("T1105", "T1204.002"),
       lambda r: on(r, "download_then_execute", "downloaded_file_executed") and not _download_to_interpreter(r)),
    _s("embedded_download_exec", "A quoted payload contains download-and-execute", 0.45,
       EXECUTION, ("T1059.004", "T1105"),
       lambda r: on(r, "embedded_download_exec") and not _download_to_interpreter(r)),
    _s("decode_to_interpreter", "Decoded (base64) content is executed", 0.7,
       DEFENSE_EVASION, ("T1027", "T1140", "T1059.004"),
       ("base64_to_interpreter",)),
    _s("echo_to_interpreter", "Literal text is piped into an interpreter", 0.2,
       EXECUTION, ("T1059.004",),
       lambda r: on(r, "echo_to_interpreter") and not on(r, "base64_to_interpreter")),
    _s("base64_decode", "Content is base64-decoded", 0.12,
       DEFENSE_EVASION, ("T1140",),
       lambda r: on(r, "base64_decode") and not on(r, "base64_to_interpreter")),
    _s("obfuscation", "Several obfuscation characteristics are present", 0.35,
       DEFENSE_EVASION, ("T1027",),
       lambda r: int(r.get("obfuscation_characteristic_count", 0) or 0) >= 3),
    _s("dynamic_command", "The program name is built dynamically", 0.2,
       DEFENSE_EVASION, ("T1027",),
       ("dynamic_command_construction", "variable_indirection", "char_construction")),
    _s("exec_from_temp", "A program in a temporary directory is executed", 0.3,
       EXECUTION, ("T1059", "T1036.005"),
       ("exec_from_temp",)),
    _s("offensive_tool", "A known offensive-security tool is used or fetched", 0.55,
       EXECUTION, ("T1588.002",),
       ("offensive_tool_reference",)),

    # -- command and control ---------------------------------------------------
    _s("reverse_shell", "An interactive shell is bound to a network socket", 0.85,
       COMMAND_AND_CONTROL, ("T1059.004", "T1095"),
       ("dev_tcp_redirect", "netcat_exec_flag", "socket_shell_payload", "named_pipe_shell_relay",
        "embedded_reverse_shell")),
    _s("socket_listener", "A raw socket listener is opened", 0.3,
       COMMAND_AND_CONTROL, ("T1095",),
       ("socket_listener",)),
    _s("socket_tool_public_ip", "A raw socket tool talks to a public IP address", 0.3,
       COMMAND_AND_CONTROL, ("T1095",),
       lambda r: every(r, "uses_socket_tool", "has_public_ip")),
    _s("raw_ip_url", "A URL addresses a public IP instead of a hostname", 0.25,
       COMMAND_AND_CONTROL, ("T1071.001",),
       lambda r: every(r, "url_has_ip_host", "has_public_ip")),
    _s("plain_http_download", "Content is fetched over unencrypted HTTP", 0.05,
       COMMAND_AND_CONTROL, ("T1071.001",),
       lambda r: every(r, "has_http_url", "network_download")),
    _s("nonstandard_port", "A network tool uses a non-standard port", 0.1,
       COMMAND_AND_CONTROL, ("T1571",),
       lambda r: every(r, "has_nonstandard_port", "network_tool_used")),
    _s("tunnel_or_proxy", "A tunnel or reverse port-forward is opened", 0.3,
       COMMAND_AND_CONTROL, ("T1572", "T1090"),
       ("tunnel_or_proxy",)),

    # -- credential access -----------------------------------------------------
    _s("shadow_access", "The password hash database (/etc/shadow) is accessed", 0.55,
       CREDENTIAL_ACCESS, ("T1003.008",),
       ("touches_shadow",)),
    _s("private_key_access", "A private key file is read or copied", 0.45,
       CREDENTIAL_ACCESS, ("T1552.004",),
       ("private_key_file_access",)),
    _s("cloud_credential_file", "Cloud or cluster credential files are referenced", 0.35,
       CREDENTIAL_ACCESS, ("T1552.001",),
       lambda r: on(r, "cloud_credential_reference", "kube_config_reference") and on(r, "credential_file_reference", "path_count")),
    _s("cloud_metadata", "The cloud instance metadata service is queried", 0.3,
       CREDENTIAL_ACCESS, ("T1552.005",),
       lambda r: on(r, "cloud_metadata_access") and not on(r, "cloud_metadata_credential_path")),
    _s("cloud_metadata_credentials", "Instance credentials are requested from the metadata service", 0.6,
       CREDENTIAL_ACCESS, ("T1552.005",),
       ("cloud_metadata_credential_path",)),
    _s("credential_search", "The filesystem is searched for passwords or key files", 0.4,
       CREDENTIAL_ACCESS, ("T1552.001",),
       ("credential_search",)),
    _s("kubernetes_secret", "A Kubernetes secret is read", 0.25,
       CREDENTIAL_ACCESS, ("T1552.007",),
       ("kubernetes_secret_access",)),
    _s("process_memory", "Process memory is read via /proc", 0.45,
       CREDENTIAL_ACCESS, ("T1003.007",),
       ("proc_mem_access",)),
    _s("debugger_attach", "A debugger or tracer attaches to a running process", 0.3,
       CREDENTIAL_ACCESS, ("T1055.008",),
       ("attaches_to_pid",)),
    _s("credential_file", "A credential file (.netrc, .pgpass, .git-credentials...) is referenced", 0.15,
       CREDENTIAL_ACCESS, ("T1552.001",),
       lambda r: on(r, "credential_file_reference") and not on(r, "touches_shadow", "touches_passwd")),

    # -- persistence -------------------------------------------------------------
    _s("authorized_keys_write", "An SSH authorized_keys file is modified", 0.6,
       PERSISTENCE, ("T1098.004",),
       ("authorized_keys_write",)),
    _s("cron_install", "A cron job is installed", 0.35,
       PERSISTENCE, ("T1053.003",),
       lambda r: on(r, "crontab_edit") or (on(r, "touches_crontab_path") and on(r, "file_write_indicator"))),
    _s("systemd_unit_write", "A systemd unit file is written", 0.3,
       PERSISTENCE, ("T1543.002",),
       ("systemd_unit_write",)),
    _s("service_enable", "A service is enabled to start at boot", 0.12,
       PERSISTENCE, ("T1543.002",),
       ("service_enable",)),
    _s("shell_rc_write", "A shell startup file is written non-interactively", 0.35,
       PERSISTENCE, ("T1546.004",),
       lambda r: on(r, "shell_startup_write") and not on(r, "file_edit_indicator")),
    _s("shell_rc_edit", "A shell startup file is edited", 0.08,
       PERSISTENCE, ("T1546.004",),
       lambda r: on(r, "shell_startup_write") and on(r, "file_edit_indicator")),
    _s("preload_write", "The dynamic linker preload configuration is modified", 0.75,
       PERSISTENCE, ("T1574.006",),
       lambda r: every(r, "preload_persistence", "file_write_indicator")),
    _s("ld_preload_env", "LD_PRELOAD is set", 0.4,
       DEFENSE_EVASION, ("T1574.006",),
       ("ld_preload_env",)),
    _s("pam_write", "PAM configuration is modified", 0.5,
       PERSISTENCE, ("T1556.003",),
       lambda r: every(r, "pam_configuration", "file_write_indicator")),
    _s("init_or_udev_write", "An init script or udev rule is written", 0.35,
       PERSISTENCE, ("T1037.004", "T1546"),
       lambda r: on(r, "init_script_persistence", "udev_persistence") and on(r, "file_write_indicator")),
    _s("at_job", "A one-off job is scheduled with at/batch", 0.15,
       PERSISTENCE, ("T1053.002",),
       ("at_job_persistence",)),
    _s("kernel_module_load", "A kernel module is loaded", 0.3,
       PERSISTENCE, ("T1547.006",),
       ("kernel_module_load",)),
    _s("user_created", "A user account is created or modified", 0.2,
       PERSISTENCE, ("T1136.001",),
       ("user_management",)),
    _s("uid0_account", "An account with uid 0 (root-equivalent) is created", 0.85,
       PERSISTENCE, ("T1136.001", "T1078.003"),
       ("uid0_account_creation",)),
    _s("account_database_write", "/etc/passwd, /etc/shadow or /etc/group is written directly", 0.6,
       PERSISTENCE, ("T1098",),
       lambda r: on(r, "account_database_write") and not on(r, "uid0_account_creation")),

    # -- privilege escalation ----------------------------------------------------
    _s("sudoers_write", "sudoers is modified without visudo", 0.65,
       PRIVILEGE_ESCALATION, ("T1548.003",),
       ("sudoers_write",)),
    _s("setuid_set", "A setuid/setgid bit is set", 0.5,
       PRIVILEGE_ESCALATION, ("T1548.001",),
       ("setuid_bit_set",)),
    _s("suid_search", "The filesystem is searched for setuid binaries", 0.3,
       DISCOVERY, ("T1548.001", "T1083"),
       ("suid_binary_search",)),
    _s("dangerous_capability", "A privilege-equivalent Linux capability is granted", 0.6,
       PRIVILEGE_ESCALATION, ("T1548",),
       ("dangerous_capability_grant",)),
    _s("sudo_enumeration", "sudo rights are enumerated", 0.12,
       DISCOVERY, ("T1069.001",),
       ("sudo_list_permissions",)),
    _s("container_escape_primitive", "A container is given host-level access", 0.35,
       PRIVILEGE_ESCALATION, ("T1611",),
       ("container_privileged_flag", "container_host_mount", "container_host_namespace", "docker_socket_access")),
    _s("host_namespace_entry", "The host's namespaces are entered via pid 1", 0.6,
       PRIVILEGE_ESCALATION, ("T1611",),
       ("host_namespace_entry",)),
    _s("world_writable_system_path", "A system path is made world-writable", 0.45,
       DEFENSE_EVASION, ("T1222.002",),
       lambda r: on(r, "chmod_world_writable") and on(r, "touches_etc", "touches_sensitive_path")),
    _s("world_writable", "Permissions are opened to everyone (777/o+w)", 0.12,
       DEFENSE_EVASION, ("T1222.002",),
       lambda r: on(r, "chmod_world_writable") and not on(r, "touches_etc", "touches_sensitive_path")),

    # -- defense evasion ---------------------------------------------------------
    _s("history_cleared", "Shell history is cleared or disabled", 0.5,
       DEFENSE_EVASION, ("T1070.003",),
       ("history_cleared",)),
    _s("log_tampering", "Log files or login records are deleted or altered", 0.55,
       DEFENSE_EVASION, ("T1070.002",),
       ("log_tampering",)),
    _s("security_monitoring_disabled", "Audit, EDR or MAC enforcement is disabled", 0.65,
       DEFENSE_EVASION, ("T1562.001",),
       ("security_monitoring_disabled",)),
    _s("aslr_disabled", "ASLR or ptrace protection is turned off", 0.45,
       DEFENSE_EVASION, ("T1562.001",),
       ("aslr_or_ptrace_protection_disabled",)),
    _s("firewall_disabled", "The host firewall is flushed or disabled", 0.3,
       DEFENSE_EVASION, ("T1562.004",),
       ("firewall_disabled",)),
    _s("timestomp", "File timestamps are set explicitly", 0.35,
       DEFENSE_EVASION, ("T1070.006",),
       ("timestamp_modification",)),
    _s("secure_delete", "Files are securely shredded", 0.2,
       DEFENSE_EVASION, ("T1070.004",),
       lambda r: on(r, "secure_delete") and not on(r, "log_tampering")),
    _s("hidden_temp_path", "A hidden file in a temporary directory is used", 0.3,
       DEFENSE_EVASION, ("T1564.001",),
       ("hidden_temp_path",)),
    _s("masquerade", "The process name is spoofed", 0.5,
       DEFENSE_EVASION, ("T1036.004",),
       ("process_name_masquerade",)),
    _s("immutable_attribute", "A file is made immutable or append-only", 0.25,
       DEFENSE_EVASION, ("T1222.002",),
       ("immutable_attribute_set",)),

    # -- discovery ---------------------------------------------------------------
    _s("recon_burst", "Several discovery categories in one command line", 0.2,
       DISCOVERY, ("T1082", "T1033", "T1016"),
       lambda r: int(r.get("discovery_category_count", 0) or 0) >= 3),
    _s("network_scan", "A network scanner is run", 0.3,
       DISCOVERY, ("T1046",),
       ("uses_scan_tool",)),
    _s("packet_capture", "Network traffic is captured", 0.12,
       CREDENTIAL_ACCESS, ("T1040",),
       ("uses_capture_tool",)),
    _s("passwd_read", "The local account list is read", 0.08,
       DISCOVERY, ("T1087.001",),
       lambda r: on(r, "touches_passwd") and not on(r, "account_database_write")),

    # -- lateral movement ----------------------------------------------------------
    _s("noninteractive_remote_auth", "Remote login with scripted password or disabled host-key checks", 0.15,
       LATERAL_MOVEMENT, ("T1021.004",),
       ("noninteractive_remote_auth",)),

    # -- collection / exfiltration -------------------------------------------------
    _s("sensitive_archive", "Sensitive directories are archived", 0.25,
       COLLECTION, ("T1560.001",),
       lambda r: every(r, "archive_creation", "touches_sensitive_path")),
    _s("archive_to_network", "An archive is streamed straight to a network tool", 0.45,
       EXFILTRATION, ("T1048", "T1560.001"),
       ("archive_to_transfer_pipeline",)),
    _s("socket_transfer", "Data is sent over a raw socket", 0.35,
       EXFILTRATION, ("T1048",),
       lambda r: on(r, "transfer_over_socket_tool") and on(r, "upload_indicator", "outbound_transfer_indicator")),
    _s("upload_public_ip", "Data is uploaded to a public IP address", 0.35,
       EXFILTRATION, ("T1041",),
       lambda r: on(r, "upload_indicator", "network_upload") and on(r, "has_public_ip")),
    _s("upload", "Local data is uploaded", 0.1,
       EXFILTRATION, ("T1041",),
       lambda r: on(r, "upload_indicator", "network_upload") and not on(r, "has_public_ip")),
    _s("exfil_service", "A paste, file-drop, tunnel or webhook service is contacted", 0.5,
       EXFILTRATION, ("T1567",),
       ("exfil_service_domain",)),

    # -- impact ------------------------------------------------------------------
    _s("root_delete", "The root filesystem is recursively deleted", 0.95,
       IMPACT, ("T1485",),
       ("root_filesystem_delete",)),
    _s("system_directory_delete", "A system directory is recursively deleted", 0.6,
       IMPACT, ("T1485",),
       ("system_directory_delete",)),
    _s("disk_wipe", "A block device is overwritten or reformatted", 0.85,
       IMPACT, ("T1561.001",),
       ("raw_disk_write",)),
    _s("fork_bomb", "A fork bomb exhausts system resources", 0.9,
       IMPACT, ("T1499.001",),
       ("fork_bomb",)),
    _s("crypto_miner", "A cryptocurrency miner or mining pool is referenced", 0.8,
       IMPACT, ("T1496",),
       ("crypto_miner_reference",)),
    _s("bulk_encryption", "Files are encrypted in bulk", 0.5,
       IMPACT, ("T1486",),
       ("bulk_encryption",)),

    # -- combinations within one command line -------------------------------------
    _s("download_to_temp_exec", "Downloaded to a temp directory and executed", 0.3,
       EXECUTION, ("T1105",),
       lambda r: on(r, "download_to_tmp") and on(r, "download_then_execute", "chmod_following_download")),
    _s("download_with_persistence", "Remote content is fetched while installing persistence", 0.5,
       PERSISTENCE, ("T1105", "T1053.003"),
       lambda r: on(r, "network_download", "embedded_download_exec")
       and on(r, "crontab_edit", "systemd_unit_write", "shell_startup_write", "authorized_keys_write")),
    _s("credential_exfil", "Credential material is sent over the network", 0.6,
       EXFILTRATION, ("T1552", "T1041"),
       lambda r: on(r, "touches_shadow", "private_key_file_access", "cloud_credential_reference",
                    "credential_file_reference")
       and on(r, "upload_indicator", "network_upload", "transfer_over_socket_tool")),
    _s("kernel_module_from_temp", "A kernel module is loaded from a temp or home directory", 0.45,
       PERSISTENCE, ("T1547.006", "T1014"),
       lambda r: on(r, "kernel_module_load") and on(r, "touches_tmp", "touches_home")),
    _s("privileged_remote_exec", "Remote code is executed with elevated privileges", 0.15,
       PRIVILEGE_ESCALATION, ("T1548.003",),
       lambda r: on(r, "uses_sudo") and (_download_to_interpreter(r) or on(r, "download_then_execute"))),
]

if len({signal.id for signal in SIGNALS}) != len(SIGNALS):    # pragma: no cover - import-time guard
    raise ValueError("duplicate signal id in catalogue")


# -- signals that only exist across several statements of a script ---------------
SCRIPT_SIGNALS: Dict[str, Signal] = {
    s.id: s for s in [
        # fired by the cross-statement analysis in malscore.scoring, never by a record
        _s("staged_download_execution", "A file downloaded earlier in the script is executed later", 0.55,
           EXECUTION, ("T1105", "T1204.002")),
        _s("collect_then_exfiltrate", "An archive created in the script is later sent over the network", 0.5,
           EXFILTRATION, ("T1560.001", "T1041")),
        _s("credential_access_then_upload", "Credential access is followed by an outbound transfer", 0.4,
           EXFILTRATION, ("T1552", "T1041")),
        _s("download_and_persist", "The script both fetches remote content and installs persistence", 0.3,
           PERSISTENCE, ("T1105", "T1543")),
        _s("cover_tracks", "Activity is followed by clearing history or logs", 0.3,
           DEFENSE_EVASION, ("T1070",)),
        _s("multi_stage", "Activity spans three or more attack tactics", 0.35,
           EXECUTION, ("TA0002",)),
    ]
}
