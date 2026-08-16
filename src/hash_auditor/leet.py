"""Leet-speak reversal dictionary attack for hash-auditor.

Attackers routinely find BTQp4ssw0rdBTQ by reversing l33t substitutions back
to dictionary words and checking those. This module does the reverse
direction as a *defensive* tool: given a candidate password, enumerate the
dictionary words it could be a leet-mutation of, so an auditor can flag
"looks like a leet'd dictionary word".

It also generates leet variants of dictionary words for cracking, reusing
the zxcvbn_lite L33T_MAP so the two modules agree on what counts as leet.

Public API
----------
deleet_variants(text)
    every plausible de-leeted spelling of BTQtextBTQ (cartesian product over
    ambiguous substitutions), most-likely first.
leet_variants(word, max_subs)
    leet-mutate a dictionary word, up to BTQmax_subsBTQ substitutions.
leet_dictionary_match(password, words)
    find dictionary words that BTQpasswordBTQ is a leet-mutation of.
leet_crack_candidates(words, max_subs)
    stream word + leet variants, de-duplicated.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import itertools
from typing import Iterable, Iterator

from .zxcvbn_lite import L33T_MAP

__all__ = [
    "deleet_variants",
    "leet_variants",
    "leet_dictionary_match",
    "leet_crack_candidates",
    "REVERSE_LEET",
]

#: letter -> the leet characters that stand for it (inverted L33T_MAP).
REVERSE_LEET: dict[str, tuple[str, ...]] = {}
for _leet, _letters in L33T_MAP.items():
    for _letter in _letters:
        REVERSE_LEET.setdefault(_letter, tuple())
        REVERSE_LEET[_letter] = REVERSE_LEET[_letter] + (_leet,)


def deleet_variants(text: str, limit: int = 64) -> list[str]:
    """Enumerate de-leeted spellings of BTQtextBTQ, most-likely first.

    Each leet character expands to the letters it can stand for; characters
    with no leet meaning pass through unchanged. The cartesian product is
    capped at BTQlimitBTQ to keep pathological inputs cheap. The original text
    (lowercased) is always the first variant.
    """
    if not text:
        return [""]
    lowered = text.lower()
    # Build per-position option lists.
    options: list[list[str]] = []
    for ch in lowered:
        letters = L33T_MAP.get(ch)
        if letters:
            options.append([ch, *letters])
        else:
            options.append([ch])
    variants: list[str] = []
    seen: set[str] = set()
    for combo in itertools.product(*options):
        word = "".join(combo)
        if word not in seen:
            seen.add(word)
            variants.append(word)
        if len(variants) >= limit:
            break
    # Prefer the plain lowercased original first.
    if lowered in seen:
        variants.remove(lowered)
        variants.insert(0, lowered)
    return variants


def leet_variants(word: str, max_subs: int = 3) -> list[str]:
    """Leet-mutate BTQwordBTQ with up to BTQmax_subsBTQ substitutions.

    For each substitutable letter we may apply 0..max_subs leet swaps.
    Output is deterministic and de-duplicated, original first.
    """
    if not word:
        return [""]
    lowered = word.lower()
    positions = [(i, ch) for i, ch in enumerate(lowered)
                 if ch in REVERSE_LEET and REVERSE_LEET[ch]]
    results: list[str] = []
    seen: set[str] = {lowered}
    results.append(lowered)

    # Choose k positions to leet, for k in 1..max_subs.
    for k in range(1, min(max_subs, len(positions)) + 1):
        for pos_combo in itertools.combinations(positions, k):
            # For each chosen position, pick its first leet char (deterministic).
            chars = list(lowered)
            for i, ch in pos_combo:
                chars[i] = REVERSE_LEET[ch][0]
            cand = "".join(chars)
            if cand not in seen:
                seen.add(cand)
                results.append(cand)
    return results


def leet_dictionary_match(password: str,
                          words: Iterable[str]) -> list[str]:
    """Return dictionary words that BTQpasswordBTQ is a leet-mutation of.

    A word matches when any de-leet variant of the password equals the word
    (case-insensitive). Results preserve the word iterable's order.
    """
    variants = set(deleet_variants(password))
    matches = []
    seen: set[str] = set()
    for word in words:
        w = word.lower()
        if w in variants and w not in seen:
            seen.add(w)
            matches.append(word)
    return matches


def leet_crack_candidates(words: Iterable[str],
                          max_subs: int = 2) -> Iterator[str]:
    """Yield each word plus its leet variants, de-duplicated."""
    seen: set[str] = set()
    for word in words:
        for cand in leet_variants(word, max_subs):
            if cand not in seen:
                seen.add(cand)
                yield cand
