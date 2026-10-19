# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-19

Initial release.

### Added
- Maliciousness scoring for a single Linux command: a 0–100 score with a verdict
  band (`benign`/`low`/`medium`/`high`/`critical`) and MITRE ATT&CK mapping.
- Session scoring (`Analyzer.assess_session`, `--session`): score a list of
  commands together, with cross-command signals for staged exfiltration, a
  download run later, privilege escalation followed by credential access, cleanup
  after exfiltration, and activity followed by history/log clearing.
- A catalogue of 113 command-level signals and 8 session signals spanning the
  Linux ATT&CK tactics — execution, persistence, privilege escalation, defense
  evasion, credential access, discovery, collection, command-and-control,
  exfiltration and impact — including GTFOBins shell escapes, credential hunting,
  database dumps and sensitive-data access, and DNS/encoded exfiltration.
- A non-executing shell lexer and analysis context; the non-execution guarantee is
  enforced by a static and runtime safety test.
- Command-line interface: argument/stdin/`--session`/`--batch` input, `--json`,
  `--explain`, `--redact`, `--min-verdict`, `--fail-on`, `--no-color`; `malscore`
  console script and `python -m malscore`.
- Python API: `Analyzer`, `Assessment`, `SIGNALS`, `SESSION_SIGNALS`,
  `verdict_for`.
- Zero runtime dependencies; Python 3.8+.

[Unreleased]: https://github.com/raj3shp/malscore/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/raj3shp/malscore/releases/tag/v0.1.0
