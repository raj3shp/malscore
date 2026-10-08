"""Safety tests: the analyzer must never execute what it analyses.

Two layers:

1. a static scan of every source file for execution primitives;
2. a runtime check that analysing file-mutating command lines leaves the
   filesystem untouched.
"""

from __future__ import annotations

import os
import re
import tempfile
import unittest
from typing import List

import _bootstrap  # noqa: F401
from malscore import Analyzer

ROOT = _bootstrap.ROOT
FORBIDDEN = [
    (re.compile(r"\bos\.system\s*\("), "os.system"),
    (re.compile(r"\bos\.popen\s*\("), "os.popen"),
    (re.compile(r"\bos\.exec[lv]"), "os.exec*"),
    (re.compile(r"^\s*import\s+subprocess", re.M), "import subprocess"),
    (re.compile(r"\bsubprocess\."), "subprocess call"),
    (re.compile(r"(?<![\w.])shell\s*=\s*True"), "shell=True"),
    (re.compile(r"(?<![\w.])eval\s*\("), "eval()"),
    (re.compile(r"(?<![\w.])exec\s*\("), "exec()"),
    (re.compile(r"\bcommands\.getoutput\b"), "commands.getoutput"),
    (re.compile(r"\bpty\.spawn\b"), "pty.spawn"),
]


def source_files() -> List[str]:
    paths: List[str] = []
    for directory, _dirs, files in os.walk(ROOT):
        if "/." in directory or "__pycache__" in directory:
            continue
        for name in files:
            if name.endswith(".py"):
                paths.append(os.path.join(directory, name))
    return paths


class StaticSafetyTest(unittest.TestCase):
    def test_no_execution_primitives_in_source(self) -> None:
        offenders = []
        for path in source_files():
            if path.endswith("test_safety.py"):
                continue                      # this file names them on purpose
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
            for pattern, label in FORBIDDEN:
                if pattern.search(text):
                    offenders.append("%s: %s" % (os.path.relpath(path, ROOT), label))
        self.assertEqual(offenders, [], "execution primitives found: %s" % offenders)

    def test_scans_a_meaningful_number_of_files(self) -> None:
        self.assertGreater(len(source_files()), 10)


class RuntimeSafetyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = Analyzer()
        self.tmpdir = tempfile.mkdtemp(prefix="malscore-safety-")

    def test_analysis_creates_nothing(self) -> None:
        target = os.path.join(self.tmpdir, "created.txt")
        directory = os.path.join(self.tmpdir, "created_dir")
        for command in ("touch %s" % target, "mkdir -p %s" % directory,
                        "echo hi > %s" % target, "curl -o %s http://127.0.0.1/x" % target):
            self.analyzer.assess(command)
        self.assertFalse(os.path.exists(target))
        self.assertFalse(os.path.exists(directory))

    def test_analysis_deletes_nothing(self) -> None:
        victim = os.path.join(self.tmpdir, "keep.txt")
        with open(victim, "w", encoding="utf-8") as handle:
            handle.write("data")
        for command in ("rm -rf %s" % victim, "shred -u %s" % victim,
                        "truncate -s 0 %s" % victim, "dd if=/dev/zero of=%s" % victim):
            self.analyzer.assess(command)
        self.assertTrue(os.path.exists(victim))
        with open(victim, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "data")

    def test_substitutions_are_not_evaluated(self) -> None:
        marker = os.path.join(self.tmpdir, "subst.txt")
        self.analyzer.assess("echo $(touch %s) `mkdir %s.d`" % (marker, marker))
        self.assertFalse(os.path.exists(marker))
        self.assertFalse(os.path.exists(marker + ".d"))

    def test_scripts_and_heredocs_are_not_run(self) -> None:
        marker = os.path.join(self.tmpdir, "script.txt")
        self.analyzer.assess("#!/bin/sh\ntouch %s\nbash <<SH\ntouch %s\nSH\n" % (marker, marker))
        self.assertFalse(os.path.exists(marker))

    def tearDown(self) -> None:
        for name in os.listdir(self.tmpdir):
            os.unlink(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)


if __name__ == "__main__":
    unittest.main()
