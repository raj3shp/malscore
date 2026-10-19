# Architecture

`malscore` turns command text into a score through a short, deterministic
pipeline. Every stage is read-only: no command is ever executed, expanded,
globbed or resolved.

```
command text
   │
   ▼
lexer      malscore/lexer.py       a forgiving, non-executing shell lexer:
   │                               words, operators, pipelines, redirections
   ▼
context    malscore/context.py     resolves the effective executable (unwraps
   │                               sudo/env/xargs), descends one level into
   │                               substitutions, -c payloads and remote
   │                               commands, and extracts paths, URLs, IPs, ports
   ▼
features   malscore/features.py    generic feature groups (network, paths,
           malscore/tradecraft.py  persistence, encoding, …) plus technique-
   │                               specific shapes (reverse shells, credential
   │                               hunting, data staging, …). Output is a flat
   │                               record of observations, never verdicts.
   ▼
signals    malscore/signals.py     ~120 named predicates over the feature record,
   │                               each with a weight, a MITRE tactic and
   │                               technique ids
   ▼
scoring    malscore/scoring.py     noisy-OR aggregation with per-tactic damping →
                                   0–100 score + verdict; plus cross-command
                                   session analysis
```

## The non-execution guarantee

The whole point of `malscore` is that it is safe to run on hostile input: it only
reads the text. This is enforced two ways by `tests/test_safety.py`:

1. a **static scan** of every source file for execution primitives
   (`os.system(`, `subprocess`, `eval(`, `exec(`, `pty.spawn`, …);
2. a **runtime check** that assessing file-creating, file-deleting and
   substitution-bearing commands leaves the filesystem untouched.

Because of the static scan, test code that needs to pass such a primitive as data
assembles the literal from pieces (e.g. `"pty." + "spawn"`) so the source file
itself stays clean.

## Features are observations, signals are judgement

A **feature** records something structural and literal — "a `/dev/tcp`
redirection is present", "a config file is searched for the word `password`", "a
`pg_dump` targets a table named `card_token`". Features never decide whether a
command is bad.

A **signal** (`malscore/signals.py`) attaches weight to a feature pattern: a
predicate over the record, a weight in `(0, 1]`, a tactic and technique ids. The
weight reads as "how likely is this hostile if it were the only thing we knew".

Keeping the two separate means the extractor can be exhaustive and neutral while
the scoring stays small, auditable, and easy to retune.

## From signals to a score

See the [signal reference](signals.md) for the exact rules. In short: signals that
share a tactic are damped (so redundant findings don't stack), then combined with
a noisy-OR that stays in `[0, 1)` and is scaled to 0–100.

## Session (cross-command) analysis

`Analyzer.assess_session` scores each command on its own, caps each command's
contribution, and then runs a second pass that only sees the sequence. That pass
catches staged attacks no single line reveals — a file downloaded by one command
and run by a later one, data dumped/archived then `scp`-ed away (and deleted
after), privilege escalation followed by credential access, or activity followed
by history/log clearing. These emit the session signals listed in the reference.

## Module map

| module | role |
| --- | --- |
| `malscore/lexer.py` | non-executing shell lexer |
| `malscore/context.py` | executable resolution, payload/path/URL/IP/port extraction, shared helpers |
| `malscore/features.py` | generic feature groups |
| `malscore/tradecraft.py` | technique-specific features, grouped by ATT&CK tactic |
| `malscore/signals.py` | weighted, MITRE-mapped signal catalogue |
| `malscore/scoring.py` | aggregation, verdicts, session analysis, `Analyzer` |
| `malscore/redaction.py` | credential redaction for echoed text |
| `malscore/cli.py` | command-line interface |

## Extending

- **New technique** → add a feature to `malscore/tradecraft.py` (or a generic
  group in `malscore/features.py`) and return it from the group function, then add
  a `Signal` for it in `malscore/signals.py`.
- **New weighting** → add or adjust a `Signal` in `malscore/signals.py`; no other
  file needs to change.

See [CONTRIBUTING](../CONTRIBUTING.md) for the full workflow and tests.
