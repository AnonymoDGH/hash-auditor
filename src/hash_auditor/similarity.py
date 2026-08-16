"""Password similarity and mutation analysis for hash-auditor.

When users rotate a password they rarely create a new one: they tweak the
old one. This module measures how close two passwords are and *how* one was
derived from the other, which is exactly what password-history policies and
cracking rule-sets exploit.

Metrics
-------
levenshtein(a, b)
    classic edit distance (insert/delete/substitute), full-matrix DP.
edit_script(a, b)
    the minimal list of operations turning a into b.
similarity_ratio(a, b)
    0.0-1.0 normalised similarity built on the edit distance.
detect_mutation(a, b)
    classify the relationship: identical, case_flip, digit_increment,
    suffix_swap, prefix_swap, leet_flip, reversed, appended, prepended,
    substitution, unrelated.
cluster_passwords(passwords, threshold)
    group similar passwords with union-find over similarity_ratio.

Public API is the five functions above plus MUTATION_LABELS.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

from typing import Iterable, Sequence

__all__ = [
    "levenshtein",
    "edit_script",
    "similarity_ratio",
    "detect_mutation",
    "cluster_passwords",
    "MUTATION_LABELS",
]

#: Human-readable labels for every mutation class detect_mutation reports.
MUTATION_LABELS: dict[str, str] = {
    "identical": "the same password",
    "case_flip": "only letter case changed",
    "digit_increment": "a trailing counter was bumped",
    "suffix_swap": "the suffix changed (e.g. year rotation)",
    "prefix_swap": "the prefix changed",
    "leet_flip": "l33t substitutions applied or removed",
    "reversed": "the password was reversed",
    "appended": "characters were appended",
    "prepended": "characters were prepended",
    "substitution": "a few characters were substituted",
    "unrelated": "no obvious relationship",
}

_LEET_PAIRS = {
    "4": "a", "@": "a", "3": "e", "1": "i", "0": "o",
    "5": "s", "$": "s", "7": "t", "!": "i", "8": "b",
}


def levenshtein(a: str, b: str) -> int:
    """Edit distance between two strings (insert/delete/substitute = 1).

    Uses the full dynamic-programming matrix; O(len(a)*len(b)) time and
    space, fine for password-length inputs.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1,        # delete
                         cur[j - 1] + 1,     # insert
                         prev[j - 1] + cost)  # substitute
        prev = cur
    return prev[-1]


def edit_script(a: str, b: str) -> list[tuple[str, int, str]]:
    """Minimal edit script turning BTQaBTQ into BTQbBTQ.

    Returns operations as (op, position, char) tuples where op is one of
    'keep', 'substitute', 'insert', 'delete'. Position refers to the
    current (partially edited) string. The script is minimal: the number of
    non-keep operations equals levenshtein(a, b).
    """
    n, m = len(a), len(b)
    # Build the DP matrix, then walk back from (n, m).
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        dp[i][0] = i
    for j in range(m + 1):
        dp[0][j] = j
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1,
                           dp[i][j - 1] + 1,
                           dp[i - 1][j - 1] + cost)
    ops: list[tuple[str, int, str]] = []
    i, j = n, m
    while i > 0 or j > 0:
        if i > 0 and j > 0 and a[i - 1] == b[j - 1] and \
                dp[i][j] == dp[i - 1][j - 1]:
            ops.append(("keep", i - 1, a[i - 1]))
            i -= 1
            j -= 1
        elif i > 0 and j > 0 and dp[i][j] == dp[i - 1][j - 1] + 1:
            ops.append(("substitute", i - 1, b[j - 1]))
            i -= 1
            j -= 1
        elif i > 0 and dp[i][j] == dp[i - 1][j] + 1:
            ops.append(("delete", i - 1, a[i - 1]))
            i -= 1
        else:
            ops.append(("insert", i, b[j - 1]))
            j -= 1
    ops.reverse()
    return ops


def similarity_ratio(a: str, b: str) -> float:
    """Normalised similarity: 1 - distance / max(len(a), len(b)).

    Two empty strings are identical (1.0). The ratio is symmetric and in
    [0.0, 1.0].
    """
    if not a and not b:
        return 1.0
    return 1.0 - levenshtein(a, b) / max(len(a), len(b))


def _deleet(text: str) -> str:
    return "".join(_LEET_PAIRS.get(ch, ch) for ch in text)


def _split_trailing_digits(text: str) -> tuple[str, str]:
    i = len(text)
    while i > 0 and text[i - 1].isdigit():
        i -= 1
    return text[:i], text[i:]


def detect_mutation(a: str, b: str) -> dict:
    """Classify how BTQbBTQ relates to BTQaBTQ.

    Returns a dict with 'label' (one of MUTATION_LABELS), 'similarity'
    (0-1), 'distance' (edit distance) and 'detail' (a human sentence).
    Checks run cheapest-first and the first confident match wins.
    """
    result = {
        "label": "unrelated",
        "similarity": round(similarity_ratio(a, b), 4),
        "distance": levenshtein(a, b),
        "detail": "",
    }

    def finish(label: str, detail: str) -> dict:
        result["label"] = label
        result["detail"] = detail
        return result

    if a == b:
        return finish("identical", "passwords are identical")

    if a.lower() == b.lower():
        return finish("case_flip", "only the case of letters changed")

    if a[::-1] == b and len(a) >= 4:
        return finish("reversed", "one password is the other reversed")

    # Digit increment: same stem, trailing counter bumped by 1.
    stem_a, num_a = _split_trailing_digits(a)
    stem_b, num_b = _split_trailing_digits(b)
    if stem_a and stem_a == stem_b and num_a and num_b:
        try:
            if int(num_b) - int(num_a) == 1:
                return finish(
                    "digit_increment",
                    f"trailing counter bumped {num_a} -> {num_b}")
        except ValueError:  # pragma: no cover -- digit strings always parse
            pass

    # Appended/prepended: one password is an exact prefix/suffix of the
    # other, with a shared part of at least 4 characters.
    prefix = 0
    while prefix < min(len(a), len(b)) and a[prefix] == b[prefix]:
        prefix += 1
    if prefix >= 4 and prefix == len(a) and len(b) > len(a):
        return finish("appended", f"{len(b) - len(a)} character(s) appended")
    if prefix >= 4 and prefix == len(b) and len(a) > len(b):
        return finish("appended", f"{len(a) - len(b)} character(s) removed")
    suffix = 0
    while suffix < min(len(a), len(b)) - prefix and \
            a[-1 - suffix] == b[-1 - suffix]:
        suffix += 1
    if suffix >= 4 and suffix == len(a) and len(b) > len(a):
        return finish("prepended", f"{len(b) - len(a)} character(s) prepended")
    if suffix >= 4 and suffix == len(b) and len(a) > len(b):
        return finish("prepended", f"{len(a) - len(b)} character(s) removed")

    # Suffix swap: same alphabetic stem, different trailing digits.
    if stem_a and stem_a == stem_b and num_a and num_b and len(stem_a) >= 4:
        return finish(
            "suffix_swap",
            f"suffix rotated {num_a} -> {num_b}")

    # Leet flip: equal after de-leet-ing and case-folding.
    if _deleet(a).lower() == _deleet(b).lower():
        return finish("leet_flip", "l33t substitutions applied or removed")

    # Small substitution: distance <= 25% of the length, same length.
    if len(a) == len(b) and a and result["distance"] <= max(1, len(a) // 4):
        return finish(
            "substitution",
            f"{result['distance']} character(s) substituted")

    result["detail"] = "no obvious relationship"
    return result


def cluster_passwords(passwords: Sequence[str],
                      threshold: float = 0.7) -> list[list[str]]:
    """Group passwords whose similarity_ratio is >= BTQthresholdBTQ.

    Uses union-find so similarity is transitive within a cluster. Returns
    clusters in first-appearance order, members in input order.
    """
    n = len(passwords)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[max(rx, ry)] = min(rx, ry)

    for i in range(n):
        for j in range(i + 1, n):
            if similarity_ratio(passwords[i], passwords[j]) >= threshold:
                union(i, j)

    groups: dict[int, list[str]] = {}
    order: list[int] = []
    for i in range(n):
        root = find(i)
        if root not in groups:
            groups[root] = []
            order.append(root)
        groups[root].append(passwords[i])
    return [groups[root] for root in order]
