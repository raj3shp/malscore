# Signal reference

> This file is generated from `malscore/signals.py`. Regenerate with
> `python tools/gen_signals_doc.py > docs/signals.md`; do not edit by hand.

`malscore` carries **113** command-level signals and **8** session (cross-command)
signals. Each signal is a predicate over the extracted features plus a weight in
`(0, 1]`, a MITRE ATT&CK tactic, and one or more technique ids.

## How signals become a score

1. Every signal whose predicate is true on the command "fires".
2. Signals that share a tactic are **damped**: the strongest keeps its weight,
   the next is multiplied by 0.55, the next by 0.55², and so on — so three
   redundant persistence checks do not count as three independent findings.
3. The damped weights are combined with a **noisy-OR**, `1 − ∏(1 − wᵢ)`, which
   keeps the result in `[0, 1)`; it is scaled to the 0–100 score.

| score | verdict |
| --- | --- |
| 80–100 | `critical` |
| 60–79 | `high` |
| 35–59 | `medium` |
| 15–34 | `low` |
| 0–14 | `benign` |

## Command signals

### Execution

| id | description | weight | techniques |
| --- | --- | --- | --- |
| `download_pipe_interpreter` | Remote content is executed directly by an interpreter | 0.55 | T1059.004 T1105 |
| `offensive_tool` | A known offensive-security tool is used or fetched | 0.55 | T1588.002 |
| `download_then_execute` | A downloaded file is made executable or run | 0.50 | T1105 T1204.002 |
| `tty_shell_upgrade` | A dumb shell is upgraded to a full TTY | 0.50 | T1059.006 T1059.004 |
| `embedded_download_exec` | A quoted payload contains download-and-execute | 0.45 | T1059.004 T1105 |
| `exec_from_temp` | A program in a temporary directory is executed | 0.30 | T1059 T1036.005 |
| `download_to_temp_exec` | Downloaded to a temp directory and executed | 0.30 | T1105 |
| `echo_to_interpreter` | Literal text is piped into an interpreter | 0.20 | T1059.004 |

### Persistence

| id | description | weight | techniques |
| --- | --- | --- | --- |
| `uid0_account` | An account with uid 0 (root-equivalent) is created | 0.85 | T1136.001 T1078.003 |
| `preload_write` | The dynamic linker preload configuration is modified | 0.75 | T1574.006 |
| `authorized_keys_write` | An SSH authorized_keys file is modified | 0.60 | T1098.004 |
| `account_database_write` | /etc/passwd, /etc/shadow or /etc/group is written directly | 0.60 | T1098 |
| `pam_write` | PAM configuration is modified | 0.50 | T1556.003 |
| `download_with_persistence` | Remote content is fetched while installing persistence | 0.50 | T1105 T1053.003 |
| `kernel_module_from_temp` | A kernel module is loaded from a temp or home directory | 0.45 | T1547.006 T1014 |
| `persistence_hook_write` | A login or tooling hook is installed for persistence | 0.40 | T1546 T1037 T1543.002 |
| `cron_install` | A cron job is installed | 0.35 | T1053.003 |
| `shell_rc_write` | A shell startup file is written non-interactively | 0.35 | T1546.004 |
| `init_or_udev_write` | An init script or udev rule is written | 0.35 | T1037.004 T1546 |
| `systemd_unit_write` | A systemd unit file is written | 0.30 | T1543.002 |
| `kernel_module_load` | A kernel module is loaded | 0.30 | T1547.006 |
| `user_created` | A user account is created or modified | 0.20 | T1136.001 |
| `at_job` | A one-off job is scheduled with at/batch | 0.15 | T1053.002 |
| `service_enable` | A service is enabled to start at boot | 0.12 | T1543.002 |
| `shell_rc_edit` | A shell startup file is edited | 0.08 | T1546.004 |

### Privilege Escalation

| id | description | weight | techniques |
| --- | --- | --- | --- |
| `sudo_uid_bypass` | sudo runas uid -1 bypass (CVE-2019-14287) | 0.80 | T1068 |
| `sudoers_write` | sudoers is modified without visudo | 0.65 | T1548.003 |
| `dangerous_capability` | A privilege-equivalent Linux capability is granted | 0.60 | T1548 |
| `host_namespace_entry` | The host's namespaces are entered via pid 1 | 0.60 | T1611 |
| `privileged_shell_escape` | A sudo-run utility is used to break out into a shell | 0.60 | T1548.003 T1059.004 |
| `setuid_set` | A setuid/setgid bit is set | 0.50 | T1548.001 |
| `container_escape_primitive` | A container is given host-level access | 0.35 | T1611 |
| `shell_escape` | A utility is used to break out into a shell (GTFOBins) | 0.35 | T1548.003 T1059.004 |
| `path_hijack` | PATH is prefixed with a writable directory | 0.35 | T1574.007 |
| `shell_as_other_user` | An interactive shell is opened as another account | 0.25 | T1078.003 |
| `interactive_root_shell` | An interactive root shell is opened (sudo su, sudo -i, su -) | 0.20 | T1548.003 T1078.003 |
| `privileged_remote_exec` | Remote code is executed with elevated privileges | 0.15 | T1548.003 |

### Defense Evasion

| id | description | weight | techniques |
| --- | --- | --- | --- |
| `proc_mount_hiding` | A bind mount is used to hide a process under /proc | 0.75 | T1564 |
| `decode_to_interpreter` | Decoded (base64) content is executed | 0.70 | T1027 T1140 T1059.004 |
| `security_monitoring_disabled` | Audit, EDR or MAC enforcement is disabled | 0.65 | T1562.001 |
| `fileless_execution` | Code is executed from memory or an anonymous file descriptor | 0.60 | T1620 |
| `log_tampering` | Log files or login records are deleted or altered | 0.55 | T1070.002 |
| `history_cleared` | Shell history is cleared or disabled | 0.50 | T1070.003 |
| `masquerade` | The process name is spoofed | 0.50 | T1036.004 |
| `world_writable_system_path` | A system path is made world-writable | 0.45 | T1222.002 |
| `aslr_disabled` | ASLR or ptrace protection is turned off | 0.45 | T1562.001 |
| `ld_preload_env` | LD_PRELOAD is set | 0.40 | T1574.006 |
| `obfuscation` | Several obfuscation characteristics are present | 0.35 | T1027 |
| `timestomp` | File timestamps are set explicitly | 0.35 | T1070.006 |
| `firewall_disabled` | The host firewall is flushed or disabled | 0.30 | T1562.004 |
| `hidden_temp_path` | A hidden file in a temporary directory is used | 0.30 | T1564.001 |
| `immutable_attribute` | A file is made immutable or append-only | 0.25 | T1222.002 |
| `immutable_attribute_removed` | The immutable/append-only attribute is cleared on a system path | 0.25 | T1222.002 |
| `dynamic_command` | The program name is built dynamically | 0.20 | T1027 |
| `secure_delete` | Files are securely shredded | 0.20 | T1070.004 |
| `base64_decode` | Content is base64-decoded | 0.12 | T1140 |
| `world_writable` | Permissions are opened to everyone (777/o+w) | 0.12 | T1222.002 |

### Credential Access

| id | description | weight | techniques |
| --- | --- | --- | --- |
| `cloud_metadata_credentials` | Instance credentials are requested from the metadata service | 0.60 | T1552.005 |
| `ssh_agent_hijack` | SSH_AUTH_SOCK is pointed at another user's agent socket | 0.60 | T1563.001 |
| `shadow_access` | The password hash database (/etc/shadow) is accessed | 0.55 | T1003.008 |
| `private_key_access` | A private key file is read or copied | 0.45 | T1552.004 |
| `process_memory` | Process memory is read via /proc | 0.45 | T1003.007 |
| `secret_pattern_search` | The filesystem is searched for key or token formats | 0.45 | T1552.001 |
| `credential_search` | The filesystem is searched for passwords or key files | 0.40 | T1552.001 |
| `cloud_credential_file` | Cloud or cluster credential files are referenced | 0.35 | T1552.001 |
| `credential_keyword_search` | A config file or tree is searched for credential keywords | 0.35 | T1552.001 |
| `credential_file_read` | A credential file (.pgpass, .netrc, cloud credentials...) is read | 0.35 | T1552.001 |
| `cloud_metadata` | The cloud instance metadata service is queried | 0.30 | T1552.005 |
| `debugger_attach` | A debugger or tracer attaches to a running process | 0.30 | T1055.008 |
| `environment_secret_read` | The process environment is searched for secrets | 0.30 | T1552.001 |
| `shell_history_read` | A shell history file is read | 0.30 | T1552.003 |
| `kubernetes_secret` | A Kubernetes secret is read | 0.25 | T1552.007 |
| `credential_file` | A credential file (.netrc, .pgpass, .git-credentials...) is referenced | 0.15 | T1552.001 |
| `packet_capture` | Network traffic is captured | 0.12 | T1040 |

### Discovery

| id | description | weight | techniques |
| --- | --- | --- | --- |
| `suid_search` | The filesystem is searched for setuid binaries | 0.30 | T1548.001 T1083 |
| `network_scan` | A network scanner is run | 0.30 | T1046 |
| `security_software_discovery` | Security or monitoring agents are enumerated | 0.30 | T1518.001 |
| `writable_path_search` | The filesystem is searched for world-writable files | 0.25 | T1083 |
| `recon_burst` | Several discovery categories in one command line | 0.20 | T1082 T1033 T1016 |
| `ssh_target_discovery` | SSH known_hosts/config is read to find pivot targets | 0.20 | T1018 |
| `sandbox_check` | The host is probed for virtualization or a container | 0.15 | T1497.001 |
| `sudo_enumeration` | sudo rights are enumerated | 0.12 | T1069.001 |
| `passwd_read` | The local account list is read | 0.08 | T1087.001 |

### Lateral Movement

| id | description | weight | techniques |
| --- | --- | --- | --- |
| `noninteractive_remote_auth` | Remote login with scripted password or disabled host-key checks | 0.15 | T1021.004 |

### Collection

| id | description | weight | techniques |
| --- | --- | --- | --- |
| `sensitive_data_pattern_search` | The filesystem is searched for card numbers or SSNs | 0.45 | T1005 T1119 |
| `sensitive_table_access` | A database query or dump targets regulated/secret data | 0.40 | T1213 |
| `clipboard_or_screen_capture` | The clipboard or screen is captured | 0.30 | T1115 T1113 |
| `sensitive_archive` | Sensitive directories are archived | 0.25 | T1560.001 |
| `database_dump` | A database is dumped wholesale | 0.25 | T1005 T1213 |
| `data_staged_in_temp` | Dumped or harvested data is written to a temporary directory | 0.20 | T1074.001 |

### Command And Control

| id | description | weight | techniques |
| --- | --- | --- | --- |
| `reverse_shell` | An interactive shell is bound to a network socket | 0.85 | T1059.004 T1095 |
| `socket_listener` | A raw socket listener is opened | 0.30 | T1095 |
| `socket_tool_public_ip` | A raw socket tool talks to a public IP address | 0.30 | T1095 |
| `tunnel_or_proxy` | A tunnel or reverse port-forward is opened | 0.30 | T1572 T1090 |
| `raw_ip_url` | A URL addresses a public IP instead of a hostname | 0.25 | T1071.001 |
| `nonstandard_port` | A network tool uses a non-standard port | 0.10 | T1571 |
| `plain_http_download` | Content is fetched over unencrypted HTTP | 0.05 | T1071.001 |

### Exfiltration

| id | description | weight | techniques |
| --- | --- | --- | --- |
| `credential_exfil` | Credential material is sent over the network | 0.60 | T1552 T1041 |
| `dns_exfiltration` | Data is tunnelled through DNS lookups | 0.60 | T1048.003 |
| `exfil_service` | A paste, file-drop, tunnel or webhook service is contacted | 0.50 | T1567 |
| `archive_to_network` | An archive is streamed straight to a network tool | 0.45 | T1048 T1560.001 |
| `encoded_exfiltration` | Encoded data is piped straight to a network tool | 0.40 | T1132.001 T1048 |
| `socket_transfer` | Data is sent over a raw socket | 0.35 | T1048 |
| `upload_public_ip` | Data is uploaded to a public IP address | 0.35 | T1041 |
| `upload` | Local data is uploaded | 0.10 | T1041 |

### Impact

| id | description | weight | techniques |
| --- | --- | --- | --- |
| `root_delete` | The root filesystem is recursively deleted | 0.95 | T1485 |
| `fork_bomb` | A fork bomb exhausts system resources | 0.90 | T1499.001 |
| `disk_wipe` | A block device is overwritten or reformatted | 0.85 | T1561.001 |
| `crypto_miner` | A cryptocurrency miner or mining pool is referenced | 0.80 | T1496 |
| `system_directory_delete` | A system directory is recursively deleted | 0.60 | T1485 |
| `mass_process_kill` | Every process is signalled (kill -1 / killall5) | 0.60 | T1489 |
| `database_destruction` | A database table or schema is dropped or truncated | 0.55 | T1485 |
| `bulk_encryption` | Files are encrypted in bulk | 0.50 | T1486 |

## Session signals

These fire only across multiple commands scored together with
`Analyzer.assess_session` (see [usage](usage.md)).

| id | description | weight | tactic | techniques |
| --- | --- | --- | --- | --- |
| `staged_download_execution` | A file downloaded earlier in the session is executed later | 0.55 | execution | T1105 T1204.002 |
| `collect_then_exfiltrate` | Data staged earlier in the session is later sent over the network | 0.50 | exfiltration | T1560.001 T1041 |
| `credential_access_then_upload` | Credential access is followed by an outbound transfer | 0.40 | exfiltration | T1552 T1041 |
| `cleanup_after_exfiltration` | Staged or transferred data is deleted after being sent | 0.30 | defense-evasion | T1070.004 |
| `escalation_then_credential_access` | Privilege escalation is followed by credential access | 0.40 | credential-access | T1548.003 T1552 |
| `download_and_persist` | The session both fetches remote content and installs persistence | 0.30 | persistence | T1105 T1543 |
| `cover_tracks` | Activity is followed by clearing history or logs | 0.30 | defense-evasion | T1070 |
| `multi_stage` | Activity spans three or more attack tactics | 0.35 | execution | TA0002 |
