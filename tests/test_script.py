"""Tests for the non-executing script splitter."""

from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401
from cmdfeat.script import looks_like_script, split_script


class ScriptSplitTest(unittest.TestCase):
    def texts(self, script: str):
        return [s.text for s in split_script(script)]

    def test_comments_and_shebang_dropped(self) -> None:
        texts = self.texts("#!/bin/bash\n# a comment\nls -la  # trailing\n")
        self.assertEqual(texts, ["ls -la"])

    def test_line_continuation_joined(self) -> None:
        texts = self.texts("wget -q http://x/a \\\n   -O /tmp/k")
        self.assertEqual(len(texts), 1)
        self.assertIn("-O /tmp/k", texts[0])

    def test_trailing_pipe_joins(self) -> None:
        self.assertEqual(self.texts("ps aux |\n  grep java"), ["ps aux |   grep java"])

    def test_hash_inside_word_is_not_a_comment(self) -> None:
        texts = self.texts('echo "${#arr}"')
        self.assertEqual(texts, ['echo "${#arr}"'])

    def test_quote_spanning_newline(self) -> None:
        texts = self.texts('echo "line one\nline two # not a comment"')
        self.assertEqual(len(texts), 1)
        self.assertIn("not a comment", texts[0])

    def test_heredoc_body_kept_separate(self) -> None:
        script = "cat > /tmp/u <<'EOF'\nmalicious content\nEOF\nls"
        statements = split_script(script)
        self.assertEqual(statements[0].text, "cat > /tmp/u <<'EOF'")
        self.assertEqual(statements[0].heredocs[0].body, "malicious content")
        self.assertEqual(statements[-1].text, "ls")

    def test_tab_stripped_heredoc(self) -> None:
        script = "bash <<-SH\n\tid\n\tSH\nwhoami"
        statements = split_script(script)
        self.assertEqual(statements[0].heredocs[0].body, "id")
        self.assertEqual(statements[-1].text, "whoami")

    def test_line_numbers_are_reported(self) -> None:
        statements = split_script("#!/bin/sh\n\nls\nid")
        self.assertEqual((statements[0].text, statements[0].line), ("ls", 3))
        self.assertEqual((statements[1].text, statements[1].line), ("id", 4))

    def test_looks_like_script(self) -> None:
        self.assertTrue(looks_like_script("a\nb"))
        self.assertTrue(looks_like_script("#!/bin/bash"))
        self.assertFalse(looks_like_script("curl -s http://x | bash"))


if __name__ == "__main__":
    unittest.main()
