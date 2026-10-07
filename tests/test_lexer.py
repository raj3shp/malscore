"""Lexer tests: quoting, operators, pipelines, redirections and malformed input."""

from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401
from cmdfeat.lexer import tokenize


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
        self.assertEqual(parsed.single_quote_count, 1)

    def test_double_quotes_and_expansion(self) -> None:
        parsed = tokenize('echo "${HOME}/a b"')
        self.assertEqual(parsed.commands[0].argv, ["echo", "${HOME}/a b"])
        self.assertEqual(parsed.double_quote_count, 1)
        self.assertGreaterEqual(parsed.expansion_count, 1)

    def test_pipeline_stages(self) -> None:
        parsed = tokenize("cat a | grep b | wc -l")
        self.assertEqual(len(parsed.commands), 3)
        self.assertEqual(parsed.max_pipeline_length, 3)
        self.assertEqual([c.pipeline_index for c in parsed.commands], [0, 1, 2])

    def test_logical_operators_start_new_pipeline(self) -> None:
        parsed = tokenize("make build && make test")
        self.assertEqual(len(parsed.commands), 2)
        self.assertEqual(parsed.commands[1].preceding_op, "&&")
        self.assertEqual(parsed.max_pipeline_length, 1)

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
        self.assertEqual(parsed.dollar_paren_count, 1)
        self.assertEqual(parsed.backtick_count, 1)

    def test_subshell_and_background(self) -> None:
        parsed = tokenize("(cd /tmp && ls) &")
        self.assertIn("(", parsed.operators)
        self.assertIn("&", parsed.operators)
        self.assertGreaterEqual(parsed.max_subshell_depth, 1)

    def test_unterminated_quote_does_not_raise(self) -> None:
        parsed = tokenize("echo 'unterminated")
        self.assertTrue(parsed.unbalanced_quotes)
        self.assertEqual(parsed.commands[0].argv, ["echo", "unterminated"])

    def test_malformed_operators_do_not_raise(self) -> None:
        for text in ("| | |", "&&", ">>>", "cmd |", "$(", "`", "a>b>c"):
            self.assertIsNotNone(tokenize(text))

    def test_control_characters_survive(self) -> None:
        parsed = tokenize("echo a\x00b")
        self.assertIn("\x00", parsed.raw)

    def test_escapes_counted(self) -> None:
        parsed = tokenize(r"grep -r foo\ bar /etc")
        self.assertGreaterEqual(parsed.escape_count, 1)


if __name__ == "__main__":
    unittest.main()
