"""Input parsing tests: field aliases, optional fields, timestamps, formats."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

import _bootstrap  # noqa: F401
from cmdfeat.events import event_from_record, parse_timestamp, read_events, sort_events


class TimestampTest(unittest.TestCase):
    def test_iso_with_offset(self) -> None:
        parsed = parse_timestamp("2026-09-15T20:30:15+05:30")
        self.assertEqual((parsed.hour, parsed.minute), (20, 30))
        self.assertEqual(parsed.utcoffset().total_seconds(), 5.5 * 3600)

    def test_iso_zulu(self) -> None:
        self.assertEqual(parse_timestamp("2026-09-09T00:31:25Z").hour, 0)

    def test_fractional_seconds(self) -> None:
        self.assertIsNotNone(parse_timestamp("2026-09-09T00:31:25.123456Z"))

    def test_epoch_seconds_and_millis(self) -> None:
        self.assertEqual(parse_timestamp(0).year, 1970)
        self.assertEqual(parse_timestamp(1700000000000).year, parse_timestamp(1700000000).year)

    def test_unparsable(self) -> None:
        self.assertIsNone(parse_timestamp("last tuesday"))
        self.assertIsNone(parse_timestamp(""))
        self.assertIsNone(parse_timestamp(None))


class RecordTest(unittest.TestCase):
    def test_simple_format(self) -> None:
        event = event_from_record({"user": "alice", "command": "git status"}, 0, 1)
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.command, "git status")
        self.assertIsNone(event.timestamp)

    def test_missing_everything(self) -> None:
        event = event_from_record({}, 0, 1)
        self.assertEqual(event.command, "")
        self.assertEqual(event.user, "")
        self.assertIn("missing command line", event.parse_warnings)

    def test_argv_list_is_joined(self) -> None:
        event = event_from_record({"cmdline": ["ls", "-la", "/tmp"]}, 0, 1)
        self.assertEqual(event.command, "ls -la /tmp")

    def test_aliases(self) -> None:
        event = event_from_record(
            {"acct": "bob", "proctitle": "id", "@timestamp": "2026-01-01T00:00:00Z",
             "node": "host1", "pcomm": "sshd", "auid": 1000}, 0, 1)
        self.assertEqual(event.user, "bob")
        self.assertEqual(event.host, "host1")
        self.assertEqual(event.parent_exe, "sshd")

    def test_unknown_fields_go_to_extra(self) -> None:
        event = event_from_record({"user": "a", "command": "id", "scenario": "x"}, 0, 1)
        self.assertEqual(event.extra.get("scenario"), "x")

    def test_bad_timestamp_is_warned_not_fatal(self) -> None:
        event = event_from_record({"command": "id", "timestamp": "nope"}, 0, 1)
        self.assertIsNone(event.timestamp)
        self.assertTrue(any("unparsable" in w for w in event.parse_warnings))


class ReadEventsTest(unittest.TestCase):
    def _write(self, text: str, suffix: str = ".jsonl") -> str:
        handle = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8")
        handle.write(text)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_jsonl(self) -> None:
        path = self._write('{"user":"a","command":"ls"}\n{"user":"b","command":"id"}\n')
        self.assertEqual(len(read_events(path)), 2)

    def test_blank_and_bad_lines_skipped(self) -> None:
        path = self._write('{"user":"a","command":"ls"}\n\nnot json\n# comment\n')
        self.assertEqual(len(read_events(path)), 1)

    def test_strict_raises(self) -> None:
        path = self._write('{"user":"a","command":"ls"}\nnot json\n')
        with self.assertRaises(ValueError):
            read_events(path, strict=True)

    def test_json_array(self) -> None:
        path = self._write(json.dumps([{"user": "a", "cmdline": "ls"}, {"user": "b", "cmdline": "id"}]))
        self.assertEqual(len(read_events(path)), 2)

    def test_sort_puts_timeless_events_last_in_input_order(self) -> None:
        events = read_events(self._write(
            '{"command":"c","timestamp":"2026-01-02T00:00:00Z"}\n'
            '{"command":"a"}\n'
            '{"command":"b","timestamp":"2026-01-01T00:00:00Z"}\n'
        ))
        ordered = [e.command for e in sort_events(events)]
        self.assertEqual(ordered, ["b", "c", "a"])


if __name__ == "__main__":
    unittest.main()
