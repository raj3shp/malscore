"""Behavioural baseline tests, with emphasis on the no-future-leakage rule."""

from __future__ import annotations

import datetime as dt
import unittest
from typing import List

import _bootstrap  # noqa: F401
from cmdfeat.events import Event
from cmdfeat.pipeline import ExtractorConfig, FeatureExtractor

UTC = dt.timezone.utc


def make_events(commands: List[str], user: str = "alice", host: str = "h1",
                start: dt.datetime = None, step_seconds: int = 60) -> List[Event]:
    start = start or dt.datetime(2026, 3, 2, 9, 0, tzinfo=UTC)
    return [
        Event(index, index + 1, command=command, user=user, host=host,
              timestamp=start + dt.timedelta(seconds=index * step_seconds))
        for index, command in enumerate(commands)
    ]


class BaselineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.extractor = FeatureExtractor(ExtractorConfig())

    def test_first_occurrence_is_rare_then_becomes_common(self) -> None:
        records = self.extractor.extract_events(
            make_events(["git status", "ls", "git status", "git status", "git status"])
        )
        self.assertTrue(records[0]["first_seen_by_user"])
        self.assertEqual(records[0]["command_rarity"], 1.0)
        self.assertFalse(records[2]["first_seen_by_user"])
        self.assertEqual(records[2]["command_count_for_user"], 1)
        # a command the user keeps running gets less rare as history accumulates
        self.assertLess(records[4]["command_rarity"], records[2]["command_rarity"])

    def test_no_future_leakage(self) -> None:
        """A command repeated later must not lower the rarity of its first use."""
        records = self.extractor.extract_events(make_events(["ls", "ls", "ls", "ls", "ls"]))
        self.assertEqual(records[0]["command_rarity"], 1.0)
        self.assertEqual(records[0]["command_count_for_user"], 0)
        self.assertEqual(records[0]["user_history_size"], 0)
        for index, record in enumerate(records):
            self.assertEqual(record["user_event_index"], index)
            self.assertEqual(record["command_count_for_user"], index)

    def test_rarity_matches_prior_frequency(self) -> None:
        records = self.extractor.extract_events(make_events(["a", "b", "a", "c"]))
        # before event 4 the user has run: a, b, a  -> "c" unseen, history 3
        self.assertEqual(records[3]["user_history_size"], 3)
        self.assertEqual(records[3]["command_rarity"], 1.0)
        # event 3 is the second "a": 1 prior occurrence out of 2 events
        self.assertAlmostEqual(float(records[2]["command_rarity"]), 0.5, places=6)

    def test_users_have_independent_baselines(self) -> None:
        events = make_events(["docker ps"], user="alice") + make_events(["docker ps"], user="bob")
        records = self.extractor.extract_events(events)
        self.assertTrue(records[0]["first_seen_by_user"])
        self.assertTrue(records[1]["first_seen_by_user"])
        self.assertFalse(records[1]["first_seen_on_host"])   # host baseline is shared

    def test_normalization_groups_similar_commands(self) -> None:
        records = self.extractor.extract_events(make_events([
            "curl https://example.com/a.sh",
            "curl https://example.com/b.sh",
        ]))
        self.assertEqual(records[0]["normalized_command"], records[1]["normalized_command"])
        self.assertFalse(records[1]["first_seen_by_user"])

    def test_time_windows(self) -> None:
        records = self.extractor.extract_events(make_events(["ls"] * 6, step_seconds=60))
        self.assertEqual(records[0]["time_since_previous_command"], -1.0)
        self.assertEqual(records[1]["time_since_previous_command"], 60.0)
        self.assertEqual(records[5]["commands_in_previous_5_minutes"], 5)
        self.assertEqual(records[5]["commands_in_previous_hour"], 5)

    def test_time_window_expires(self) -> None:
        records = self.extractor.extract_events(make_events(["ls"] * 3, step_seconds=4000))
        self.assertEqual(records[2]["commands_in_previous_hour"], 0)

    def test_seconds_since_same_command(self) -> None:
        records = self.extractor.extract_events(make_events(["ls", "pwd", "ls"], step_seconds=30))
        self.assertEqual(records[0]["seconds_since_same_command"], -1.0)
        self.assertEqual(records[2]["seconds_since_same_command"], 60.0)

    def test_new_executable_and_domain(self) -> None:
        records = self.extractor.extract_events(make_events([
            "curl https://a.example.com/x",
            "curl https://a.example.com/y",
            "wget https://b.example.com/z",
        ]))
        self.assertTrue(records[0]["new_executable_for_user"])
        self.assertFalse(records[1]["new_executable_for_user"])
        self.assertFalse(records[1]["new_domain_for_user"])
        self.assertTrue(records[2]["new_domain_for_user"])
        self.assertTrue(records[2]["new_executable_for_user"])

    def test_usual_hour_tracking(self) -> None:
        start = dt.datetime(2026, 3, 2, 10, 0, tzinfo=UTC)
        events = make_events(["ls"] * 60, start=start, step_seconds=30)   # all near 10:00
        night = Event(99, 99, command="ls", user="alice", host="h1",
                      timestamp=dt.datetime(2026, 3, 5, 3, 0, tzinfo=UTC))
        records = self.extractor.extract_events(events + [night])
        last = records[-1]
        self.assertEqual(last["usual_hour"], 10)
        self.assertEqual(last["hour_deviation"], 7)
        self.assertTrue(last["unusual_hour"])

    def test_events_without_timestamps_still_work(self) -> None:
        events = [Event(i, i, command="ls", user="alice") for i in range(3)]
        records = self.extractor.extract_events(events)
        self.assertEqual(records[2]["command_count_for_user"], 2)
        self.assertEqual(records[2]["time_since_previous_command"], -1.0)
        self.assertEqual(records[2]["usual_hour"], -1)

    def test_extraction_sorts_by_time(self) -> None:
        late = Event(0, 1, command="second", user="alice",
                     timestamp=dt.datetime(2026, 3, 2, 12, 0, tzinfo=UTC))
        early = Event(1, 2, command="first", user="alice",
                      timestamp=dt.datetime(2026, 3, 2, 8, 0, tzinfo=UTC))
        records = FeatureExtractor(ExtractorConfig()).extract_events([late, early])
        self.assertEqual(records[0]["command"], "first")
        self.assertEqual(records[1]["user_history_size"], 1)


if __name__ == "__main__":
    unittest.main()
