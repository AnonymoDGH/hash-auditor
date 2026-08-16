"""Wordlist and corpus statistics for hash-auditor.

Analytical tooling for people who collect wordlists: given any iterable of
passwords, produce the statistics that predict how well the list will crack.

Metrics
-------
length_histogram / class_distribution
    basic shape of the corpus.
digit_suffix_rate / capitalization_rate
    the two mutations that dominate real breach lists.
top_repeats
    most duplicated entries (dedup efficiency).
zipf_fit
    fit the frequency distribution to Zipf's law and report the exponent
    via log-log linear regression; a corpus with exponent near 1 is
    "natural" breach material.
markov_transitions
    character bigram frequency table (basis for PCFG/Markov crackers).
corpus_report
    everything above in one dict.

Public API
----------
length_histogram(words)
class_distribution(words)
digit_suffix_rate(words)
capitalization_rate(words)
top_repeats(words, n)
zipf_fit(words)
markov_transitions(words)
corpus_report(words)

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable

__all__ = [
    "length_histogram",
    "class_distribution",
    "digit_suffix_rate",
    "capitalization_rate",
    "top_repeats",
    "zipf_fit",
    "markov_transitions",
    "corpus_report",
]


def _materialize(words: Iterable[str]) -> list[str]:
    return [w for w in words if w]


def length_histogram(words: Iterable[str]) -> dict[int, int]:
    """Password length -> count, sorted by length."""
    hist: Counter[int] = Counter(len(w) for w in _materialize(words))
    return dict(sorted(hist.items()))


def class_distribution(words: Iterable[str]) -> dict[str, int]:
    """Count passwords by the set of character classes they use.

    Keys are '+'-joined class names in the fixed order
    lower+upper+digit+symbol, e.g. 'lower+digit'.
    """
    out: Counter[str] = Counter()
    for w in _materialize(words):
        classes = []
        if any(c.islower() for c in w):
            classes.append("lower")
        if any(c.isupper() for c in w):
            classes.append("upper")
        if any(c.isdigit() for c in w):
            classes.append("digit")
        if any(not c.isalnum() for c in w):
            classes.append("symbol")
        out["+".join(classes) or "empty"] += 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))


def digit_suffix_rate(words: Iterable[str]) -> float:
    """Fraction of passwords ending in a digit (0.0 for an empty corpus)."""
    ws = _materialize(words)
    if not ws:
        return 0.0
    return sum(1 for w in ws if w[-1].isdigit()) / len(ws)


def capitalization_rate(words: Iterable[str]) -> float:
    """Fraction of passwords that start with an uppercase letter."""
    ws = _materialize(words)
    if not ws:
        return 0.0
    return sum(1 for w in ws if w[0].isupper()) / len(ws)


def top_repeats(words: Iterable[str], n: int = 10) -> list[tuple[str, int]]:
    """The BTQnBTQ most duplicated entries as (word, count), count > 1 only."""
    counts = Counter(_materialize(words))
    repeated = [(w, c) for w, c in counts.items() if c > 1]
    repeated.sort(key=lambda wc: (-wc[1], wc[0]))
    return repeated[:n]


def zipf_fit(words: Iterable[str]) -> dict:
    """Fit the frequency distribution to Zipf's law.

    Ranks entries by frequency and regresses log(freq) on log(rank)
    (ordinary least squares). Returns the exponent (positive; a natural
    corpus sits near 1.0), the r-squared goodness of fit, and the number of
    distinct entries used. Needs at least two distinct entries; otherwise
    the exponent is None.
    """
    counts = Counter(_materialize(words))
    if len(counts) < 2:
        return {"exponent": None, "r_squared": None,
                "distinct": len(counts)}
    freqs = sorted(counts.values(), reverse=True)
    xs = [math.log(rank) for rank in range(1, len(freqs) + 1)]
    ys = [math.log(f) for f in freqs]
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    sxx = sum((x - mean_x) ** 2 for x in xs)
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    syy = sum((y - mean_y) ** 2 for y in ys)
    slope = sxy / sxx if sxx else 0.0
    r_squared = (sxy * sxy) / (sxx * syy) if sxx and syy else 0.0
    return {
        "exponent": round(-slope, 4),
        "r_squared": round(r_squared, 4),
        "distinct": len(counts),
    }


def markov_transitions(words: Iterable[str],
                       normalize: bool = True) -> dict[str, dict[str, float]]:
    """Character bigram transition table over the corpus.

    For each character, the following-character frequencies. With
    BTQnormalizeBTQ each row sums to 1.0 (probabilities); otherwise raw
    counts. Rows are only present for characters that occur with a
    successor.
    """
    raw: dict[str, Counter[str]] = {}
    for w in _materialize(words):
        for a, b in zip(w, w[1:]):
            raw.setdefault(a, Counter())[b] += 1
    if not normalize:
        return {a: dict(row) for a, row in sorted(raw.items())}
    out: dict[str, dict[str, float]] = {}
    for a, row in sorted(raw.items()):
        total = sum(row.values())
        out[a] = {b: round(c / total, 6) for b, c in sorted(row.items())}
    return out


def corpus_report(words: Iterable[str]) -> dict:
    """One-stop statistics report for a wordlist or corpus."""
    ws = _materialize(words)
    counts = Counter(ws)
    unique = len(counts)
    total = len(ws)
    lengths = [len(w) for w in ws]
    return {
        "total": total,
        "unique": unique,
        "duplicate_rate": round(1 - unique / total, 4) if total else 0.0,
        "min_length": min(lengths) if lengths else 0,
        "max_length": max(lengths) if lengths else 0,
        "average_length": round(sum(lengths) / total, 2) if total else 0.0,
        "length_histogram": length_histogram(ws),
        "class_distribution": class_distribution(ws),
        "digit_suffix_rate": round(digit_suffix_rate(ws), 4),
        "capitalization_rate": round(capitalization_rate(ws), 4),
        "top_repeats": top_repeats(ws, 5),
        "zipf": zipf_fit(ws),
    }
