"""Lexer tests: quoting, operators, pipelines, redirections and malformed input."""

from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401
from malscore.lexer import tokenize


class TokenizeTest(unittest.TestCase):
    def test_simple_command(self) -> None:
        parsed = tokenize("ls -la /var/log")
        self.assertEqual(len(parsed.commands), 1)
        self.assertEqual(parsed.commands[0].argv, ["ls", "-la", "/var/log"])

    def test_empty_command(self) -> None:
        parsed = tokenize("")
        self.assertEqual(parsed.commands, [])
        self.assertEqual(parsed.tokens, [])

    def test_whitespace_only(self) -> None:
        self.assertEqual(tokenize("   \t ").commands, [])

    def test_single_quotes_keep_metacharacters(self) -> None:
        parsed = tokenize("python3 -c 'import os; print(1)'")
        self.assertEqual(parsed.commands[0].argv, ["python3", "-c", "import os; print(1)"])

    def test_double_quotes_and_expansion(self) -> None:
        parsed = tokenize('echo "${HOME}/a b"')
        self.assertEqual(parsed.commands[0].argv, ["echo", "${HOME}/a b"])

    def test_pipeline_stages(self) -> None:
        parsed = tokenize("cat a | grep b | wc -l")
        self.assertEqual(len(parsed.commands), 3)
        self.assertEqual([c.pipeline_index for c in parsed.commands], [0, 1, 2])
        self.assertEqual({c.pipeline_length for c in parsed.commands}, {3})

    def test_logical_operators_start_new_pipeline(self) -> None:
        parsed = tokenize("make build && make test")
        self.assertEqual(len(parsed.commands), 2)
        self.assertNotEqual(parsed.commands[0].pipeline_id, parsed.commands[1].pipeline_id)

    def test_redirections_are_not_arguments(self) -> None:
        parsed = tokenize("echo hi > /tmp/out 2>&1")
        command = parsed.commands[0]
        self.assertEqual(command.argv, ["echo", "hi"])
        self.assertIn((">", "/tmp/out"), command.redirects)
        self.assertIn(("2>&1", ""), command.redirects)

    def test_append_and_stderr_redirect(self) -> None:
        parsed = tokenize("cmd >> log 2> err")
        ops = [op for op, _ in parsed.commands[0].redirects]
        self.assertIn(">>", ops)
        self.assertIn("2>", ops)

    def test_command_substitution_captured(self) -> None:
        parsed = tokenize("echo $(whoami) `date`")
        self.assertEqual(parsed.substitutions, ["whoami", "date"])

    def test_subshell_and_background(self) -> None:
        parsed = tokenize("(cd /tmp && ls) &")
        self.assertEqual([c.argv for c in parsed.commands], [["cd", "/tmp"], ["ls"]])

    def test_unterminated_quote_does_not_raise(self) -> None:
        parsed = tokenize("echo 'unterminated")
        self.assertEqual(parsed.commands[0].argv, ["echo", "unterminated"])

    def test_malformed_operators_do_not_raise(self) -> None:
        for text in ("| | |", "&&", ">>>", "cmd |", "$(", "`", "a>b>c"):
            self.assertIsNotNone(tokenize(text))

    def test_control_characters_survive(self) -> None:
        parsed = tokenize("echo a\x00b")
        self.assertIn("\x00", parsed.raw)

    def test_escaped_space_stays_in_word(self) -> None:
        parsed = tokenize(r"grep -r foo\ bar /etc")
        self.assertEqual(parsed.commands[0].argv, ["grep", "-r", "foo bar", "/etc"])

    def test_quoted_words_are_marked(self) -> None:
        parsed = tokenize("echo 'a b' c")
        self.assertEqual([t.quoted for t in parsed.tokens if t.kind == "word"], [False, True, False])


if __name__ == "__main__":
    unittest.main()
