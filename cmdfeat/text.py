"""Text representations for later NLP-style modelling (section 24 of the spec).

The pipeline emits four text views of each command -- raw, normalized template,
token list and argument string -- and this module provides the corpus helpers
that a TF-IDF / n-gram / embedding stage will need.  No vectoriser is built
here: that is deliberately left for the modelling phase.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence

#: Field names that hold text views in a feature record.
TEXT_FIELDS = ("command", "normalized_command", "token_string", "executable_basename",
               "argument_string")


def build_corpus(records: Sequence[Dict[str, object]], field: str = "normalized_command") -> List[str]:
    """Extract one text column from feature records, ready for a vectoriser.

    Example::

        from sklearn.feature_extraction.text import TfidfVectorizer
        corpus = build_corpus(records, "normalized_command")
        X = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5)).fit_transform(corpus)
    """
    if field not in TEXT_FIELDS:
        raise ValueError("unknown text field %r (expected one of %s)" % (field, TEXT_FIELDS))
    return [str(record.get(field, "")) for record in records]


def char_ngrams(text: str, n: int = 4) -> List[str]:
    """Character n-grams of ``text`` (helper for quick experiments)."""
    if n <= 0 or len(text) < n:
        return [text] if text else []
    return [text[i:i + n] for i in range(len(text) - n + 1)]


def word_ngrams(tokens: Sequence[str], n: int = 2) -> List[str]:
    """Word n-grams over a token list."""
    if n <= 0 or len(tokens) < n:
        return [" ".join(tokens)] if tokens else []
    return [" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1)]
