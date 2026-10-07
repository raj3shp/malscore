"""cmdfeat -- feature extraction for Linux command-execution telemetry.

The package converts raw command events into a wide, stable feature record
suitable for anomaly detection.  It is purely analytical: no command is ever
executed, expanded or resolved.

Typical use::

    from cmdfeat.events import read_events
    from cmdfeat.pipeline import ExtractorConfig, FeatureExtractor

    extractor = FeatureExtractor(ExtractorConfig(redact_secrets=True))
    records = extractor.extract_events(read_events("events.jsonl"))
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = [
    "ExtractorConfig",
    "FeatureExtractor",
    "build_registry",
    "read_events",
    "__version__",
]


def __getattr__(name: str):
    """Lazy re-exports, so ``import cmdfeat`` stays cheap."""
    if name in ("ExtractorConfig", "FeatureExtractor", "build_registry"):
        from . import pipeline
        return getattr(pipeline, name)
    if name == "read_events":
        from .events import read_events
        return read_events
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
