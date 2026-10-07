"""Feature schema: declaration, registry and catalogue.

Every feature emitted by the pipeline is declared here (indirectly, via the
``FEATURES`` list each extractor module exposes).  Declaring features has three
benefits:

* the output schema is **stable** -- every record carries every key, which is
  what downstream ML code (scikit-learn, pandas) wants;
* the README feature catalogue can be generated from code, so docs cannot
  silently drift from the implementation;
* each feature records whether it is a *deterministic indicator* (an observable
  property of the command text) or a *behavioral* feature (depends on history),
  which matters a lot when interpreting anomaly scores later.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence

#: Feature "kinds" -- see README for how to read them.
KIND_STRUCTURAL = "structural"      # deterministic property of the command text
KIND_INDICATOR = "indicator"        # deterministic semantic indicator (touches /etc/shadow)
KIND_CONTEXT = "context"            # passthrough/derived context (hour, host, uid)
KIND_BEHAVIORAL = "behavioral"      # depends on previously seen events
KIND_TEXT = "text"                  # text representation, not a numeric feature

VALID_KINDS = frozenset(
    {KIND_STRUCTURAL, KIND_INDICATOR, KIND_CONTEXT, KIND_BEHAVIORAL, KIND_TEXT}
)


@dataclass(frozen=True)
class FeatureSpec:
    """Declaration of a single feature column."""

    name: str
    dtype: str          # "int" | "float" | "bool" | "str" | "list"
    group: str          # extractor group, e.g. "network"
    kind: str           # one of the KIND_* constants
    description: str
    default: object = 0

    def __post_init__(self) -> None:
        if self.kind not in VALID_KINDS:
            raise ValueError("unknown feature kind: %r" % (self.kind,))


def F(
    name: str,
    dtype: str,
    group: str,
    kind: str,
    description: str,
    default: object = 0,
) -> FeatureSpec:
    """Shorthand constructor used by the extractor modules."""
    return FeatureSpec(name, dtype, group, kind, description, default)


class FeatureRegistry:
    """Ordered collection of :class:`FeatureSpec` objects."""

    def __init__(self) -> None:
        self._specs: "Dict[str, FeatureSpec]" = {}

    def add_many(self, specs: Sequence[FeatureSpec]) -> None:
        for spec in specs:
            if spec.name in self._specs:
                raise ValueError("duplicate feature declaration: %s" % spec.name)
            self._specs[spec.name] = spec

    def __contains__(self, name: object) -> bool:
        return name in self._specs

    def __len__(self) -> int:
        return len(self._specs)

    def names(self) -> List[str]:
        return list(self._specs)

    def specs(self) -> List[FeatureSpec]:
        return list(self._specs.values())

    def get(self, name: str) -> FeatureSpec:
        return self._specs[name]

    def defaults(self) -> Dict[str, object]:
        """Template record with every feature set to its default value."""
        return {name: spec.default for name, spec in self._specs.items()}

    def by_group(self) -> "Dict[str, List[FeatureSpec]]":
        grouped: "Dict[str, List[FeatureSpec]]" = {}
        for spec in self._specs.values():
            grouped.setdefault(spec.group, []).append(spec)
        return grouped

    def numeric_names(self) -> List[str]:
        return [s.name for s in self._specs.values() if s.dtype in ("int", "float", "bool")]
