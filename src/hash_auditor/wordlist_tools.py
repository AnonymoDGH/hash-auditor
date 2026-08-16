"""Wordlist pipeline tools for hash-auditor.

Utilities for preparing and reshaping wordlists before an attack or an
audit: cleaning, filtering, de-duplication, splitting, merging, and a small
rule-driven expansion pipeline. Everything streams where possible and keeps
deterministic ordering.

Public API
----------
clean_lines(text)
    strip, drop blanks/comments, normalise newlines.
dedupe(words, case_sensitive)
    de-duplicate preserving first-seen order.
filter_words(words, min_len, max_len, require_digit, require_symbol,
             charset)
    keep words matching every supplied constraint.
split_by_length(words)
    group words by length -> dict length: list.
merge_wordlists(lists, interleave)
    merge several wordlists, round-robin or concatenated, de-duplicated.
sample_evenly(words, n)
    pick n words spread evenly across the list (deterministic).
expand_pipeline(words, stages)
    apply a sequence of named transform stages, de-duplicated.
TRANSFORMS
    the named stage registry.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

from typing import Callable, Iterable, Iterator

__all__ = [
    "clean_lines",
    "dedupe",
    "filter_words",
    "split_by_length",
    "merge_wordlists",
    "sample_evenly",
    "expand_pipeline",
    "TRANSFORMS",
]


def clean_lines(text: str) -> list[str]:
    """Normalise a raw wordlist text into clean lines.

    Strips whitespace (including BOM), drops blank lines and BTQ#BTQ comments,
    and removes carriage returns. Order is preserved.
    """
    out: list[str] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def dedupe(words: Iterable[str], case_sensitive: bool = True) -> list[str]:
    """De-duplicate preserving first-seen order.

    With BTQcase_sensitiveBTQ False, comparison is case-folded but the first
    spelling seen is kept.
    """
    seen: set[str] = set()
    out: list[str] = []
    for word in words:
        key = word if case_sensitive else word.casefold()
        if key not in seen:
            seen.add(key)
            out.append(word)
    return out


def filter_words(words: Iterable[str],
                 min_len: int | None = None,
                 max_len: int | None = None,
                 require_digit: bool = False,
                 require_symbol: bool = False,
                 require_alpha: bool = False,
                 charset: str | None = None) -> Iterator[str]:
    """Yield words matching every supplied constraint.

    BTQcharsetBTQ keeps only words whose characters are all inside it.
    """
    charset_set = set(charset) if charset is not None else None
    for word in words:
        if min_len is not None and len(word) < min_len:
            continue
        if max_len is not None and len(word) > max_len:
            continue
        if require_digit and not any(c.isdigit() for c in word):
            continue
        if require_symbol and not any(not c.isalnum() for c in word):
            continue
        if require_alpha and not any(c.isalpha() for c in word):
            continue
        if charset_set is not None and not set(word) <= charset_set:
            continue
        yield word


def split_by_length(words: Iterable[str]) -> dict[int, list[str]]:
    """Group words by length; keys sorted ascending."""
    groups: dict[int, list[str]] = {}
    for word in words:
        groups.setdefault(len(word), []).append(word)
    return dict(sorted(groups.items()))


def merge_wordlists(lists: Iterable[Iterable[str]],
                    interleave: bool = True) -> list[str]:
    """Merge several wordlists into one de-duplicated list.

    With BTQinterleaveBTQ the lists are round-robin interleaved (first of
    each, second of each, ...), which mixes popularity ranks; otherwise
    they are concatenated in order.
    """
    pools = [list(w) for w in lists]
    merged: list[str] = []
    if interleave:
        longest = max((len(p) for p in pools), default=0)
        for i in range(longest):
            for pool in pools:
                if i < len(pool):
                    merged.append(pool[i])
    else:
        for pool in pools:
            merged.extend(pool)
    return dedupe(merged)


def sample_evenly(words: Iterable[str], n: int) -> list[str]:
    """Pick BTQnBTQ words spread evenly across the list, deterministically.

    Useful for quick spot-checks of huge wordlists. n >= list length
    returns the whole list (as a list). n <= 0 returns [].
    """
    if n <= 0:
        return []
    pool = list(words)
    if n >= len(pool):
        return pool
    step = len(pool) / n
    return [pool[int(i * step)] for i in range(n)]


# ---------------------------------------------------------------------------
# Expansion pipeline.
# ---------------------------------------------------------------------------


def _t_identity(words: Iterable[str]) -> Iterator[str]:
    yield from words


def _t_lower(words: Iterable[str]) -> Iterator[str]:
    for w in words:
        yield w.lower()


def _t_upper(words: Iterable[str]) -> Iterator[str]:
    for w in words:
        yield w.upper()


def _t_capitalize(words: Iterable[str]) -> Iterator[str]:
    for w in words:
        yield w.capitalize()


def _t_reverse(words: Iterable[str]) -> Iterator[str]:
    for w in words:
        yield w[::-1]


def _t_digit_suffix(words: Iterable[str]) -> Iterator[str]:
    for w in words:
        yield w
        for d in "0123456789":
            yield w + d


def _t_year_suffix(words: Iterable[str]) -> Iterator[str]:
    for w in words:
        yield w
        for year in range(1970, 2030):
            yield w + str(year)


def _t_leet(words: Iterable[str]) -> Iterator[str]:
    table = str.maketrans("aeiost", "431057")
    for w in words:
        yield w.translate(table)


#: Named transform stages for expand_pipeline().
TRANSFORMS: dict[str, Callable[[Iterable[str]], Iterator[str]]] = {
    "identity": _t_identity,
    "lower": _t_lower,
    "upper": _t_upper,
    "capitalize": _t_capitalize,
    "reverse": _t_reverse,
    "digit-suffix": _t_digit_suffix,
    "year-suffix": _t_year_suffix,
    "leet": _t_leet,
}


def expand_pipeline(words: Iterable[str],
                    stages: Iterable[str]) -> list[str]:
    """Apply named transform stages in sequence, de-duplicated.

    Each stage receives the previous stage's full output. Unknown stage
    names raise ValueError. The final list preserves first-seen order.
    """
    current: Iterable[str] = list(words)
    for stage in stages:
        if stage not in TRANSFORMS:
            raise ValueError(f"unknown transform stage {stage!r} "
                             f"(use {', '.join(TRANSFORMS)})")
        current = TRANSFORMS[stage](current)
    return dedupe(current)
