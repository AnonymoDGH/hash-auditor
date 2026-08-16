"""Password structure fingerprinting for hash-auditor.

Two passwords that *look* alike usually share a structure: Capitalised word
+ digits + symbol. This module reduces a password to a structural
fingerprint -- a compact pattern string -- and uses those fingerprints to
cluster, count and compare password shapes.

Fingerprint alphabet
--------------------
    U  uppercase letter run      L  lowercase letter run
    D  digit run                 S  symbol (non-alnum) run
    X  other (unicode, control)  run

BTQPassword123!BTQ -> BTQULDSBTQ. Runs are collapsed, so the fingerprint captures
shape, not length. A verbose variant keeps run lengths: BTQU1L7D3S1BTQ.

Public API
----------
fingerprint(password)
    the collapsed pattern string.
fingerprint_verbose(password)
    pattern with run lengths.
parse_fingerprint(fp)
    inverse-ish: list of (class, length) for a verbose fingerprint.
fingerprint_stats(passwords)
    histogram of fingerprints over a corpus, top shapes, shape entropy.
cluster_by_fingerprint(passwords)
    group passwords sharing a fingerprint.
shape_similarity(fp_a, fp_b)
    0-1 similarity between two fingerprints (edit-distance based).

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable

__all__ = [
    "fingerprint",
    "fingerprint_verbose",
    "parse_fingerprint",
    "fingerprint_stats",
    "cluster_by_fingerprint",
    "shape_similarity",
    "char_class",
]


def char_class(ch: str) -> str:
    """Classify one character into U/L/D/S/X."""
    if ch.isupper():
        return "U"
    if ch.islower():
        return "L"
    if ch.isdigit():
        return "D"
    if not ch.isalnum():
        # ASCII punctuation vs anything exotic
        return "S" if ord(ch) < 128 else "X"
    return "X"  # unicode letters/digits that are not ASCII upper/lower


def _runs(password: str) -> list[tuple[str, int]]:
    """Collapse the password into (class, run_length) pairs."""
    runs: list[tuple[str, int]] = []
    for ch in password:
        cls = char_class(ch)
        if runs and runs[-1][0] == cls:
            runs[-1] = (cls, runs[-1][1] + 1)
        else:
            runs.append((cls, 1))
    return runs


def fingerprint(password: str) -> str:
    """Collapsed structural pattern, e.g. BTQPassword123!BTQ -> BTQULDSBTQ."""
    return "".join(cls for cls, _ in _runs(password))


def fingerprint_verbose(password: str) -> str:
    """Pattern with run lengths, e.g. BTQPassword123!BTQ -> BTQU1L7D3S1BTQ."""
    return "".join(f"{cls}{n}" for cls, n in _runs(password))


def parse_fingerprint(fp: str) -> list[tuple[str, int]]:
    """Parse a verbose fingerprint into (class, length) pairs.

    Raises ValueError on malformed input (class letters must be U/L/D/S/X
    followed by one or more digits).
    """
    out: list[tuple[str, int]] = []
    i = 0
    while i < len(fp):
        cls = fp[i]
        if cls not in "ULDSX":
            raise ValueError(f"bad class letter {cls!r} in fingerprint")
        i += 1
        j = i
        while j < len(fp) and fp[j].isdigit():
            j += 1
        if j == i:
            raise ValueError(f"class {cls!r} missing a run length")
        out.append((cls, int(fp[i:j])))
        i = j
    return out


def fingerprint_stats(passwords: Iterable[str]) -> dict:
    """Fingerprint histogram and shape statistics over a corpus.

    Returns total, unique-shape count, the top shapes with examples, and
    the Shannon entropy (bits) of the shape distribution -- low entropy
    means the corpus is structurally homogeneous.
    """
    fps: list[str] = []
    examples: dict[str, str] = {}
    for pw in passwords:
        fp = fingerprint(pw)
        fps.append(fp)
        examples.setdefault(fp, pw)
    counts = Counter(fps)
    total = len(fps)
    top = [
        {"fingerprint": fp, "count": count,
         "fraction": round(count / total, 4) if total else 0.0,
         "example": examples[fp]}
        for fp, count in counts.most_common(10)
    ]
    entropy = 0.0
    if total:
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
    return {
        "total": total,
        "unique_shapes": len(counts),
        "top_shapes": top,
        "shape_entropy": round(entropy, 4),
    }


def cluster_by_fingerprint(passwords: Iterable[str]) -> dict[str, list[str]]:
    """Group passwords by fingerprint; shapes ordered by first appearance."""
    clusters: dict[str, list[str]] = {}
    for pw in passwords:
        clusters.setdefault(fingerprint(pw), []).append(pw)
    return clusters


def shape_similarity(fp_a: str, fp_b: str) -> float:
    """0-1 similarity between two fingerprints (collapsed or verbose).

    Uses Levenshtein distance over the pattern strings normalised by the
    longer one. Identical shapes score 1.0.
    """
    if fp_a == fp_b:
        return 1.0
    if not fp_a or not fp_b:
        return 0.0
    # classic DP edit distance
    prev = list(range(len(fp_b) + 1))
    for i, ca in enumerate(fp_a, 1):
        cur = [i] + [0] * len(fp_b)
        for j, cb in enumerate(fp_b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    dist = prev[-1]
    return round(1.0 - dist / max(len(fp_a), len(fp_b)), 4)
