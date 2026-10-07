"""Feature normalization helpers (scaling, not command normalization).

Isolation Forest does not need scaled inputs, but One-Class SVM, k-means and
any distance-based method do, so the scaling step is provided here and kept
independent of extraction.  Pure Python by default; scikit-learn is used only
if it is installed *and* explicitly requested.
"""

from __future__ import annotations

from statistics import mean, pstdev
from typing import Dict, Iterable, List, Optional, Sequence

from .schema import FeatureRegistry

Number = float


def numeric_columns(records: Sequence[Dict[str, object]], registry: FeatureRegistry) -> List[str]:
    """Names of registry features that are numeric and present in ``records``."""
    if not records:
        return []
    present = set(records[0])
    return [name for name in registry.numeric_names() if name in present]


def fit_scaler(
    records: Sequence[Dict[str, object]],
    columns: Sequence[str],
    method: str = "zscore",
) -> Dict[str, Dict[str, float]]:
    """Compute per-column scaling parameters.

    ``method`` is ``"zscore"`` (mean/std) or ``"minmax"``.  Columns with zero
    variance are passed through unchanged rather than exploding to infinity.
    """
    if method not in ("zscore", "minmax"):
        raise ValueError("unknown scaling method: %r" % method)
    params: Dict[str, Dict[str, float]] = {}
    for column in columns:
        values = [float(record.get(column, 0) or 0) for record in records]
        if not values:
            continue
        if method == "zscore":
            centre = mean(values)
            spread = pstdev(values)
            params[column] = {"centre": centre, "spread": spread or 1.0}
        else:
            low, high = min(values), max(values)
            params[column] = {"centre": low, "spread": (high - low) or 1.0}
    return params


def apply_scaler(
    records: Sequence[Dict[str, object]],
    params: Dict[str, Dict[str, float]],
) -> List[Dict[str, object]]:
    """Return copies of ``records`` with scaled numeric columns."""
    scaled: List[Dict[str, object]] = []
    for record in records:
        row = dict(record)
        for column, param in params.items():
            if column in row:
                value = float(row[column] or 0)
                row[column] = round((value - param["centre"]) / param["spread"], 6)
        scaled.append(row)
    return scaled


def scale_records(
    records: Sequence[Dict[str, object]],
    registry: FeatureRegistry,
    method: str = "zscore",
    columns: Optional[Sequence[str]] = None,
) -> List[Dict[str, object]]:
    """Convenience wrapper: fit and apply in one call."""
    selected = list(columns) if columns else numeric_columns(records, registry)
    return apply_scaler(records, fit_scaler(records, selected, method))


def sklearn_encode_categoricals(
    records: Sequence[Dict[str, object]],
    columns: Sequence[str],
) -> List[Dict[str, object]]:
    """Ordinal-encode string columns with scikit-learn, if it is installed.

    Categorical features (``executable_basename``, ``interpreter_name``, ...)
    are emitted as strings so they stay readable.  This helper turns them into
    integers for estimators that cannot take strings.  It raises a clear
    ImportError rather than silently degrading, because a silently unencoded
    column would break a model fit much later.
    """
    try:
        from sklearn.preprocessing import OrdinalEncoder
    except ImportError as exc:                              # pragma: no cover
        raise ImportError(
            "scikit-learn is not installed; install it or encode categoricals "
            "yourself (the feature records are plain dicts)."
        ) from exc

    matrix = [[str(record.get(column, "")) for column in columns] for record in records]
    encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
    encoded = encoder.fit_transform(matrix)
    out: List[Dict[str, object]] = []
    for record, row in zip(records, encoded):
        new = dict(record)
        for column, value in zip(columns, row):
            new["%s_code" % column] = int(value)
        out.append(new)
    return out
