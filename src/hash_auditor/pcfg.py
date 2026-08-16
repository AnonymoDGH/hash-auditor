"""PCFG password guess generation for hash-auditor.

Probabilistic Context-Free Grammars (Matt Weir et al., 2009) model how real
people build passwords: a base word, then a digit run, then a symbol. Each
part is drawn from a frequency-ranked distribution learned from breach data.
A PCFG generator emits guesses in *probability order*, so the most likely
passwords are tried first -- far more efficient than blind brute force.

This module ships a small, hand-tuned grammar (no training data needed) and
a best-first generator that interleaves structures by descending probability.

Grammar
-------
A password is a structure string like BTQL4 D3 S1BTQ:
    L  a run of letters (length = the digit that follows)
    D  a run of digits
    S  a run of symbols
Each structure expands by choosing, for every token, a concrete string from
that token's length-conditioned distribution. The probability of a guess is
the product of the structure probability and every token probability.

Public API
----------
PcfgGrammar
    holds structure weights and per-token distributions; sample().
PcfgGenerator
    best-first enumeration of (probability, guess) pairs.
default_grammar()
    the built-in grammar.
generate_pcfg(n, grammar)
    the top-n most probable guesses.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field
from typing import Iterator

__all__ = [
    "PcfgGrammar",
    "PcfgGenerator",
    "default_grammar",
    "generate_pcfg",
    "TOKEN_KINDS",
]

#: Token kinds and the alphabet each draws from.
TOKEN_KINDS: dict[str, str] = {
    "L": "abcdefghijklmnopqrstuvwxyz",
    "D": "0123456789",
    "S": "!@#$%^&*",
}


def _letter_weights(length: int) -> list[tuple[str, float]]:
    """A deterministic, Zipf-ish distribution over letter runs.

    We bias toward common short words/patterns rather than uniform noise so
    the generator behaves like a real PCFG trained on breach data.
    """
    alpha = TOKEN_KINDS["L"]
    # Common stems, most probable first; pad with single letters.
    stems = ["pass", "love", "god", "sex", "money", "dragon", "master",
             "qwerty", "shadow", "sun", "abc", "admin", "let", "ilove"]
    out: list[tuple[str, float]] = []
    if length <= 6:
        for i, stem in enumerate(stems):
            if len(stem) == length:
                out.append((stem, 1.0 / (i + 2)))
    # Fill the rest with individual letters, Zipf-weighted.
    for i, ch in enumerate(alpha):
        out.append((ch * length if length > 1 else ch, 0.5 / (i + 1)))
    return _normalize(out)


def _digit_weights(length: int) -> list[tuple[str, float]]:
    """Digits: common counters and years first, then uniform-ish."""
    common = {1: ["1", "7", "0", "3", "9"],
              2: ["13", "69", "21", "00", "77"],
              3: ["123", "420", "666", "777", "007"],
              4: ["2024", "2023", "1234", "2000", "1999", "6969"],
              5: ["12345", "54321"],
              6: ["123456", "654321"]}
    out: list[tuple[str, float]] = []
    for i, d in enumerate(common.get(length, [])):
        out.append((d, 1.0 / (i + 2)))
    # Uniform filler so the distribution is complete.
    filler = "0" * length
    out.append((filler, 0.1))
    return _normalize(out)


def _symbol_weights(length: int) -> list[tuple[str, float]]:
    alpha = TOKEN_KINDS["S"]
    out = [(ch * length if length > 1 else ch, 1.0 / (i + 1))
           for i, ch in enumerate(alpha)]
    return _normalize(out)


def _normalize(pairs: list[tuple[str, float]]) -> list[tuple[str, float]]:
    total = sum(w for _, w in pairs)
    if total <= 0:
        n = len(pairs)
        return sorted(((s, 1.0 / n) for s, _ in pairs),
                      key=lambda sp: (-sp[1], sp[0]))
    normed = [(s, w / total) for s, w in pairs]
    # descending by probability, ties broken by token for determinism
    return sorted(normed, key=lambda sp: (-sp[1], sp[0]))


@dataclass
class PcfgGrammar:
    """A PCFG: structure weights plus per-kind/length token distributions."""

    #: structure string -> probability weight (normalised on init).
    structures: dict[str, float] = field(default_factory=dict)
    #: (kind, length) -> list of (token, probability), sorted desc.
    tokens: dict[tuple[str, int], list[tuple[str, float]]] = \
        field(default_factory=dict)

    def __post_init__(self) -> None:
        total = sum(self.structures.values())
        if total > 0:
            self.structures = {s: w / total
                               for s, w in self.structures.items()}

    def structure_prob(self, structure: str) -> float:
        return self.structures.get(structure, 0.0)

    def token_dist(self, kind: str, length: int) -> list[tuple[str, float]]:
        return self.tokens.get((kind, length), [])

    def parse_structure(self, structure: str) -> list[tuple[str, int]]:
        """Split BTQL4 D3 S1BTQ into [('L', 4), ('D', 3), ('S', 1)]."""
        parts: list[tuple[str, int]] = []
        for tok in structure.split():
            kind, num = tok[0], tok[1:]
            if kind not in TOKEN_KINDS or not num.isdigit():
                raise ValueError(f"bad structure token {tok!r}")
            parts.append((kind, int(num)))
        return parts

    def guess_probability(self, structure: str,
                          tokens: list[str]) -> float:
        """Probability of one concrete guess under the grammar."""
        prob = self.structure_prob(structure)
        parts = self.parse_structure(structure)
        if len(tokens) != len(parts):
            return 0.0
        for (kind, length), token in zip(parts, tokens):
            dist = dict(self.token_dist(kind, length))
            prob *= dist.get(token, 0.0)
        return prob


def default_grammar() -> PcfgGrammar:
    """The built-in grammar: common password shapes, hand-weighted."""
    structures = {
        "L6 D2": 0.20,
        "L4 D4": 0.15,
        "L8 D1": 0.12,
        "L6 D4": 0.10,
        "L5 D3": 0.10,
        "L4 D2 S1": 0.08,
        "L6 D2 S1": 0.07,
        "L3 D4": 0.06,
        "D6": 0.06,
        "L8": 0.06,
    }
    tokens: dict[tuple[str, int], list[tuple[str, float]]] = {}
    lengths_needed = {1, 2, 3, 4, 5, 6, 8}
    for length in lengths_needed:
        tokens[("L", length)] = _letter_weights(length)
        tokens[("D", length)] = _digit_weights(length)
        tokens[("S", 1)] = _symbol_weights(1)
    return PcfgGrammar(structures=structures, tokens=tokens)


class PcfgGenerator:
    """Enumerate guesses in descending probability order.

    The built-in grammar is small (a few thousand total expansions), so the
    generator materialises every expansion, scores it, and sorts once. This
    is exact -- the output is provably in descending probability order with
    no duplicates -- and fast enough for interactive use. Ties are broken
    by the guess string itself so the order is fully deterministic.
    """

    def __init__(self, grammar: PcfgGrammar | None = None) -> None:
        self.grammar = grammar or default_grammar()
        self._sorted: list[tuple[float, str]] | None = None

    def _expand_structure(self, structure: str) -> Iterator[tuple[float, str]]:
        """Yield every (probability, guess) for one structure."""
        parts = self.grammar.parse_structure(structure)
        base = self.grammar.structure_prob(structure)
        if base <= 0:
            return
        dists = [self.grammar.token_dist(kind, length)
                 for kind, length in parts]
        if any(not d for d in dists):
            return
        for combo in itertools.product(*dists):
            prob = base
            guess = []
            for token, p in combo:
                prob *= p
                guess.append(token)
            yield prob, "".join(guess)

    def _all(self) -> list[tuple[float, str]]:
        if self._sorted is None:
            best: dict[str, float] = {}
            for structure in self.grammar.structures:
                for prob, guess in self._expand_structure(structure):
                    if prob > best.get(guess, 0.0):
                        best[guess] = prob
            self._sorted = sorted(best.items(),
                                  key=lambda kv: (-kv[1], kv[0]))
            self._sorted = [(p, g) for g, p in self._sorted]
        return self._sorted

    def generate(self) -> Iterator[tuple[float, str]]:
        """Yield (probability, guess) in descending probability order."""
        for prob, guess in self._all():
            yield prob, guess


def generate_pcfg(n: int, grammar: PcfgGrammar | None = None) -> list[str]:
    """Return the top-BTQnBTQ most probable guesses from the grammar."""
    if n < 0:
        raise ValueError("n must be >= 0")
    if n == 0:
        return []
    gen = PcfgGenerator(grammar)
    out: list[str] = []
    for _, guess in gen.generate():
        out.append(guess)
        if len(out) >= n:
            break
    return out
