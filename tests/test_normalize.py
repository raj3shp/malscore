"""Command normalization tests."""

from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401
from cmdfeat.context import build_context
from cmdfeat.events import Event
from cmdfeat.normalize import command_fingerprint, normalize_command


def normalize(command: str) -> str:
    return normalize_command(build_context(Event(0, 1, command=command)))


class NormalizeTest(unittest.TestCase):
    def test_url(self) -> None:
        self.assertEqual(normalize("curl https://example.com/a.sh"), "curl <URL>")
        self.assertEqual(normalize("curl https://example.com/a.sh"),
                         normalize("curl https://other.org/b.sh"))

    def test_user_at_host(self) -> None:
        self.assertEqual(normalize("ssh user@server1"), "ssh <USER>@<HOST>")
        self.assertEqual(normalize("ssh deploy@server2"), normalize("ssh user@server1"))

    def test_bare_host_argument(self) -> None:
        self.assertEqual(normalize("ssh app-prod-01"), normalize("ssh app-prod-07"))

    def test_ip_addresses(self) -> None:
        self.assertEqual(normalize("ping 10.0.0.1"), "ping <IPV4>")
        self.assertEqual(normalize("ping6 2001:db8::1"), "ping6 <IPV6>")

    def test_numbers_and_pids(self) -> None:
        self.assertEqual(normalize("kill -9 28841"), "kill -9 <NUM>")
        self.assertEqual(normalize("cat /proc/2841/status"), normalize("cat /proc/9/status"))

    def test_home_directory(self) -> None:
        self.assertEqual(normalize("vim /home/alice/notes.txt"),
                         normalize("vim /home/bob/notes.txt"))

    def test_dates_inside_tokens(self) -> None:
        self.assertEqual(normalize("tail /var/log/app-2026-09-08.log"),
                         normalize("tail /var/log/app-2026-09-09.log"))

    def test_pipeline_structure_is_preserved(self) -> None:
        self.assertEqual(normalize("curl https://x/i.sh | bash"), "curl <URL> | bash")

    def test_flags_are_kept(self) -> None:
        self.assertEqual(normalize("ls -la /etc"), "ls -la /etc")

    def test_flag_values_are_normalized(self) -> None:
        self.assertEqual(normalize("curl --url=https://a/b"), "curl --url=<URL>")

    def test_hash_and_uuid(self) -> None:
        self.assertIn("<HEX>", normalize("docker pull img@sha256:" + "a" * 64))
        self.assertEqual(normalize("systemd-run --unit 3f2504e0-4f89-11d3-9a0c-0305e82c3301"),
                         "systemd-run --unit <UUID>")

    def test_empty(self) -> None:
        self.assertEqual(normalize(""), "")

    def test_fingerprint_is_stable_and_short(self) -> None:
        self.assertEqual(command_fingerprint("curl <URL>"), command_fingerprint("curl <URL>"))
        self.assertEqual(len(command_fingerprint("curl <URL>")), 12)


if __name__ == "__main__":
    unittest.main()
