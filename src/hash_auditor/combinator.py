"""Combinator and hybrid attacks for hash-auditor.

Wordlist attacks rarely run on raw words: real crackers combine them.
This module implements the classic combination strategies, all streaming
and de-duplicated:

combinator(words_a, words_b)
    every a+b pair (hashcat's combinator attack).
hybrid_word_mask(wordlist, mask, position)
    word + mask-expansion (hashcat -a 6/7): append or prepend every mask
    candidate to every word.
toggle_attack(words, positions)
    case-toggle the given positions of each word (2^k variants).
separator_join(words, separators, count)
    passphrase construction: join BTQcountBTQ words with each separator.
rule_chain(words, rules)
    apply rules.mutate_stream with a rule list (thin wrapper that keeps
    the attack surface in one place).
attack_stats(candidates)
    count/length summary of a candidate stream.

Every generator is lazy; materialise only what you hash.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import itertools
from typing import Iterable, Iterator

from .mask import MaskEngine
from .rules import mutate_stream

__all__ = [
    "combinator",
    "hybrid_word_mask",
    "toggle_attack",
    "separator_join",
    "rule_chain",
    "attack_stats",
]


def combinator(words_a: Iterable[str], words_b: Iterable[str],
               separator: str = "", dedupe: bool = True) -> Iterator[str]:
    """Yield every a+b concatenation (hashcat -a 1).

    BTQwords_bBTQ is materialised once; BTQwords_aBTQ streams. With BTQdedupeBTQ a
    candidate is yielded only on first occurrence.
    """
    right = list(words_b)
    seen: set[str] = set()
    for a in words_a:
        for b in right:
            cand = a + separator + b
            if dedupe:
                if cand in seen:
                    continue
                seen.add(cand)
            yield cand


def hybrid_word_mask(wordlist: Iterable[str], mask: str,
                     position: str = "append",
                     engine: MaskEngine | None = None,
                     dedupe: bool = True) -> Iterator[str]:
    """Word + mask hybrid (hashcat -a 6 append / -a 7 prepend).

    For every word, every mask candidate is appended (or prepended).
    BTQpositionBTQ must be 'append' or 'prepend'.
    """
    if position not in ("append", "prepend"):
        raise ValueError("position must be 'append' or 'prepend'")
    engine = engine or MaskEngine()
    mask_candidates = list(engine.candidates(mask))
    seen: set[str] = set()
    for word in wordlist:
        for cand in mask_candidates:
            out = word + cand if position == "append" else cand + word
            if dedupe:
                if out in seen:
                    continue
                seen.add(out)
            yield out


def toggle_attack(words: Iterable[str],
                  positions: Iterable[int]) -> Iterator[str]:
    """Yield every case-toggle combination of the given positions.

    For k positions each word yields up to 2^k variants (fewer when a
    position is out of range or not a letter). Positions are applied as a
    bitmask in sorted order, so output is deterministic.
    """
    pos = sorted(set(positions))
    for word in words:
        chars = list(word)
        for bits in range(1 << len(pos)):
            out = list(chars)
            for k, p in enumerate(pos):
                if bits >> k & 1 and 0 <= p < len(out):
                    out[p] = out[p].swapcase()
            yield "".join(out)


def separator_join(words: Iterable[str], separators: Iterable[str] = (" ", "-", "_", "."),
                   count: int = 3, dedupe: bool = True) -> Iterator[str]:
    """Yield passphrases: every ordered BTQcountBTQ-word tuple joined by each
    separator. Words are sampled with replacement (repeats allowed)."""
    if count < 1:
        raise ValueError("count must be >= 1")
    pool = list(words)
    seps = list(separators)
    seen: set[str] = set()
    for combo in itertools.product(pool, repeat=count):
        for sep in seps:
            cand = sep.join(combo)
            if dedupe:
                if cand in seen:
                    continue
                seen.add(cand)
            yield cand


def rule_chain(words: Iterable[str], rules: Iterable[str]) -> Iterator[str]:
    """Apply a rule list to every word via rules.mutate_stream."""
    return mutate_stream(words, rules)


def attack_stats(candidates: Iterable[str]) -> dict:
    """Summarise a candidate stream: count, unique, length stats."""
    count = 0
    unique: set[str] = set()
    total_len = 0
    min_len: int | None = None
    max_len = 0
    for cand in candidates:
        count += 1
        unique.add(cand)
        n = len(cand)
        total_len += n
        if min_len is None or n < min_len:
            min_len = n
        if n > max_len:
            max_len = n
    return {
        "count": count,
        "unique": len(unique),
        "min_length": min_len if min_len is not None else 0,
        "max_length": max_len,
        "avg_length": round(total_len / count, 2) if count else 0.0,
    }
