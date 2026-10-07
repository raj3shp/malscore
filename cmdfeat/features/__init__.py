"""Feature extractor modules.

Each module exposes:

* ``FEATURES``: a list of :class:`cmdfeat.schema.FeatureSpec` declarations;
* ``extract(ctx) -> Dict[str, object]``: returns *every* declared feature for
  one event, using defaults where a feature does not apply.  A stable schema
  matters more than compact records for downstream ML.

Behavioral extractors additionally take a baseline store and are listed in
``cmdfeat.features.behavioral``.
"""

from __future__ import annotations

from . import (  # noqa: F401
    ancestry,
    arguments,
    archives,
    chains,
    containers,
    credentials,
    discovery,
    encoding,
    executables,
    file_ops,
    kernel,
    network,
    paths,
    persistence,
    privilege,
    processes,
    syntax,
    temporal,
    tradecraft,
    transfer,
)

#: Extractors that depend only on the command text / event fields.
STATELESS_MODULES = (
    syntax, executables, arguments, paths, network, chains, encoding, privilege,
    persistence, processes, kernel, containers, discovery, credentials, file_ops,
    archives, transfer, temporal, ancestry, tradecraft,
)
