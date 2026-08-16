"""Deep entropy and randomness analysis for hash-auditor.

hash_auditor.entropy_bits() prices a password by its character-class pool --
fast, but blind to structure. This module measures what the pool model
misses:

shannon_entropy(text)
    per-character Shannon entropy of the observed distribution (bits).
char_distribution(text)
    normalised character frequencies.
chi_squared(text, expected)
    chi-squared statistic of the character counts against a uniform (or
    supplied) expectation; high values mean strongly non-random text.
markov_entropy(text, order)
    bits/char estimated from an order-N Markov model trained on the text
    itself -- structure (repeats, walks) lowers it.
randomness_report(text)
    combines pool entropy, Shannon entropy, chi-squared and unique ratio
    into a 0-100 randomness score with a verdict.
effective_bits(password)
    conservative entropy estimate: pool entropy penalised by structure.

Public API is the six functions above.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Mapping

__all__ = [
    "shannon_entropy",
    "char_distribution",
    "chi_squared",
    "markov_entropy",
    "randomness_report",
    "effective_bits",
]


def char_distribution(text: str) -> dict[str, float]:
    """Normalised character frequencies; empty text gives an empty dict."""
    if not text:
        return {}
    counts = Counter(text)
    total = len(text)
    return {ch: round(c / total, 6) for ch, c in sorted(counts.items())}


def shannon_entropy(text: str) -> float:
    """Per-character Shannon entropy in bits (0.0 for empty text).

    A string of one repeated character scores 0; a uniform distribution
    over N distinct characters scores log2(N).
    """
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def chi_squared(text: str,
                expected: Mapping[str, float] | None = None) -> float:
    """Chi-squared statistic of character counts vs an expectation.

    With no BTQexpectedBTQ mapping the characters present are expected to be
    uniform. Characters in the expectation with zero observed count still
    contribute. Returns 0.0 for empty text.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    if expected is None:
        keys = set(counts)
        expected = {ch: 1.0 / len(keys) for ch in keys}
    stat = 0.0
    for ch, prob in expected.items():
        exp = prob * total
        if exp <= 0:
            continue
        stat += (counts.get(ch, 0) - exp) ** 2 / exp
    # observed characters missing from the expectation add their full count
    for ch, obs in counts.items():
        if ch not in expected:
            stat += obs
    return round(stat, 4)


def markov_entropy(text: str, order: int = 1) -> float:
    """Bits per character from an order-N Markov model of BTQtextBTQ.

    The model is trained on the text itself: for each context of BTQorderBTQ
    characters, the conditional entropy of the next character is averaged
    over all contexts. Order 0 equals shannon_entropy(). Short texts that
    cannot produce a context return the order-0 value.
    """
    if order < 0:
        raise ValueError("order must be >= 0")
    if order == 0 or len(text) <= order:
        return shannon_entropy(text)
    contexts: dict[str, Counter[str]] = {}
    for i in range(len(text) - order):
        ctx = text[i:i + order]
        contexts.setdefault(ctx, Counter())[text[i + order]] += 1
    total = sum(sum(row.values()) for row in contexts.values())
    if total == 0:
        return shannon_entropy(text)
    bits = 0.0
    for row in contexts.values():
        row_total = sum(row.values())
        weight = row_total / total
        h = -sum((c / row_total) * math.log2(c / row_total)
                 for c in row.values())
        bits += weight * h
    return bits


def _pool_bits(password: str) -> float:
    """Classic pool-size entropy: len * log2(pool)."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33
    if pool == 0 or not password:
        return 0.0
    return len(password) * math.log2(pool)


def effective_bits(password: str) -> float:
    """Conservative entropy: pool entropy scaled by observed randomness.

    The scale factor is the ratio of the text's Shannon entropy to its
    theoretical maximum (log2 of distinct characters), so perfectly
    structured strings (all one character) collapse toward zero while
    well-mixed strings keep most of their pool entropy.
    """
    if not password:
        return 0.0
    pool = _pool_bits(password)
    distinct = len(set(password))
    if distinct <= 1:
        return 0.0
    max_shannon = math.log2(distinct)
    observed = shannon_entropy(password)
    return round(pool * (observed / max_shannon), 2)


def randomness_report(text: str) -> dict:
    """Combine the metrics into a 0-100 randomness score and verdict.

    The score blends: unique-character ratio (45%), Shannon entropy vs its
    maximum (35%), and a chi-squared uniformity term (20%). Verdicts:
    'random' >= 75, 'mixed' >= 45, 'structured' >= 20, else 'pattern'.
    """
    if not text:
        return {"score": 0, "verdict": "pattern", "shannon_bits": 0.0,
                "chi_squared": 0.0, "unique_ratio": 0.0,
                "effective_bits": 0.0}
    unique_ratio = len(set(text)) / len(text)
    distinct = len(set(text))
    if distinct == 1:
        # one repeated character: no entropy at all
        return {"score": 0, "verdict": "pattern", "shannon_bits": 0.0,
                "chi_squared": 0.0, "unique_ratio": round(unique_ratio, 4),
                "effective_bits": 0.0}
    max_shannon = math.log2(distinct)
    shannon = shannon_entropy(text)
    shannon_frac = shannon / max_shannon if max_shannon else 0.0
    chi = chi_squared(text)
    # Normalise against a loose critical value: under uniformity the
    # statistic sits near (distinct - 1); anything past ~4x that is
    # decisively non-uniform.
    critical = max(4.0 * (distinct - 1), 4.0)
    uniformity = max(0.0, 1.0 - chi / critical)

    score = int(round(100 * (0.45 * unique_ratio +
                             0.35 * shannon_frac +
                             0.20 * uniformity)))
    if score >= 75:
        verdict = "random"
    elif score >= 45:
        verdict = "mixed"
    elif score >= 20:
        verdict = "structured"
    else:
        verdict = "pattern"
    return {
        "score": score,
        "verdict": verdict,
        "shannon_bits": round(shannon, 4),
        "chi_squared": chi,
        "unique_ratio": round(unique_ratio, 4),
        "effective_bits": effective_bits(text),
    }
