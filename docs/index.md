# malscore documentation

`malscore` scores how malicious a Linux command — or a whole session of commands
— looks, on a 0–100 scale with a verdict band and MITRE ATT&CK mapping. It never
executes, expands or resolves anything; it only reads the text.

Start with the [README](../README.md) for an overview and quickstart, then dive in:

- **[Usage](usage.md)** — the command-line interface and the Python API.
- **[Signal reference](signals.md)** — every signal, its weight, tactic and
  technique ids, and how signals combine into a score.
- **[Architecture](architecture.md)** — the analysis pipeline, the non-execution
  guarantee, and how to extend the scorer.

See [CONTRIBUTING](../CONTRIBUTING.md) for development and release workflow, and
[CHANGELOG](../CHANGELOG.md) for release history.
