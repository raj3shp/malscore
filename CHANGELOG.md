# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-10-19

Packaging and documentation fixes; no library changes.

### Fixed
- Use absolute GitHub URLs for the documentation and license links in the README
  so they resolve on the PyPI project page instead of 404-ing.

### Changed
- Report Python support on PyPI through `Requires-Python` only; dropped the
  per-version `Programming Language :: Python :: 3.x` classifiers.
- Prettier centered README header (title, tagline, badge row).

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

[Unreleased]: https://github.com/raj3shp/malscore/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/raj3shp/malscore/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/raj3shp/malscore/releases/tag/v0.1.0
