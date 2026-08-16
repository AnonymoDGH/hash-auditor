"""Mask attacks: hashcat-style pattern-driven brute force.

A mask describes the shape of a password with character-class tokens:

    ?l  lowercase a-z          ?u  uppercase A-Z
    ?d  digit 0-9              ?s  space + 32 punctuation symbols
    ?a  all printable (l+u+d+s)
    ?h  hex lowercase (0-9a-f) ?H  hex uppercase (0-9A-F)
    ?b  space + tab            ??  literal '?'

Anything else is a literal character. Custom charsets can be registered on a
MaskEngine as `?1` .. `?4` (hashcat's custom charset slots).

The engine expands masks lazily: candidates stream in lexicographic order of
the per-position alphabets without materialising the full keyspace, so
`?d?d?d?d?d?d?d?d` (100M candidates) is iterable. mask_info() reports the
keyspace size and entropy without expanding.

Public API
----------
CHARSETS
    the built-in token -> alphabet map.
parse_mask(mask) -> list[str]
    per-position alphabets; raises MaskError on bad tokens.
mask_info(mask, custom)
    keyspace size, entropy bits, per-position layout.
MaskEngine
    register custom charsets, stream candidates, crack hashes.
estimate_mask_time(mask, hashes_per_second)
    human-readable worst-case cracking time.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import hashlib
import itertools
import math
from typing import Callable, Iterator

__all__ = [
    "CHARSETS",
    "MaskError",
    "parse_mask",
    "mask_info",
    "MaskEngine",
    "estimate_mask_time",
]


class MaskError(ValueError):
    """Raised for malformed masks."""


_LOW = "abcdefghijklmnopqrstuvwxyz"
_UP = _LOW.upper()
_DIG = "0123456789"
_SYM = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

#: Built-in mask tokens.
CHARSETS: dict[str, str] = {
    "?l": _LOW,
    "?u": _UP,
    "?d": _DIG,
    "?s": _SYM,
    "?a": _LOW + _UP + _DIG + _SYM,
    "?h": _DIG + "abcdef",
    "?H": _DIG + "ABCDEF",
    "?b": " \t",
    "??": "?",
}

_HASHLIB = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def parse_mask(mask: str,
               custom: dict[str, str] | None = None) -> list[str]:
    """Expand a mask into one alphabet string per position.

    Raises MaskError for an unknown token or an empty mask. Custom slots
    (?1..?4) are looked up in `custom`.
    """
    if not mask:
        raise MaskError("empty mask")
    custom = custom or {}
    alphabets: list[str] = []
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "?":
            if i + 1 >= len(mask):
                raise MaskError("mask ends with a dangling '?'")
            token = mask[i:i + 2]
            if token in CHARSETS:
                alphabets.append(CHARSETS[token])
            elif token in ("?1", "?2", "?3", "?4"):
                if token not in custom:
                    raise MaskError(f"custom charset {token} not registered")
                alphabets.append(custom[token])
            else:
                raise MaskError(f"unknown mask token {token!r}")
            i += 2
        else:
            alphabets.append(ch)
            i += 1
    return alphabets


def mask_info(mask: str,
              custom: dict[str, str] | None = None) -> dict:
    """Describe a mask without expanding it.

    Returns positions (per-position alphabet size and a short label),
    keyspace_size, and entropy_bits (log2 of the keyspace).
    """
    alphabets = parse_mask(mask, custom)
    positions = []
    keyspace = 1
    for alpha in alphabets:
        keyspace *= len(alpha)
        label = _token_label(alpha)
        positions.append({"size": len(alpha), "label": label})
    return {
        "mask": mask,
        "length": len(alphabets),
        "positions": positions,
        "keyspace_size": keyspace,
        "entropy_bits": round(math.log2(keyspace), 2) if keyspace > 1 else 0.0,
    }


def _token_label(alpha: str) -> str:
    for token, cs in CHARSETS.items():
        if token != "??" and cs == alpha:
            return token
    if len(alpha) == 1:
        return repr(alpha)
    return f"custom[{len(alpha)}]"


class MaskEngine:
    """Streams mask candidates and cracks hashes with them.

    Custom charsets are registered per-engine in the hashcat slots
    ?1 .. ?4.
    """

    def __init__(self) -> None:
        self.custom: dict[str, str] = {}

    def register(self, slot: int, alphabet: str) -> None:
        """Register a custom charset in slot 1-4; empty alphabets rejected."""
        if slot not in (1, 2, 3, 4):
            raise MaskError("custom slot must be 1, 2, 3 or 4")
        if not alphabet:
            raise MaskError("custom alphabet must be non-empty")
        self.custom[f"?{slot}"] = alphabet

    def candidates(self, mask: str) -> Iterator[str]:
        """Yield every candidate matching `mask`, lexicographic order."""
        alphabets = parse_mask(mask, self.custom)
        for combo in itertools.product(*alphabets):
            yield "".join(combo)

    def count(self, mask: str) -> int:
        """Keyspace size of `mask` (no expansion)."""
        return mask_info(mask, self.custom)["keyspace_size"]

    def crack(self, target_hash: str, mask: str, algo: str = "md5",
              limit: int | None = None,
              progress: Callable[[int, str], None] | None = None,
              progress_every: int = 100_000) -> dict:
        """Try every mask candidate against `target_hash`.

        Returns a dict with 'found', 'plaintext', 'attempts'. With `limit`
        only the first N candidates are tried. `progress`, when given, is
        called every `progress_every` attempts with (attempts, last_guess).
        """
        algo = algo.lower()
        if algo not in _HASHLIB:
            raise MaskError(f"unknown algorithm {algo!r} "
                            f"(use {', '.join(_HASHLIB)})")
        hasher = _HASHLIB[algo]
        target = target_hash.strip().lower()
        attempts = 0
        last = ""
        for cand in self.candidates(mask):
            attempts += 1
            last = cand
            if hasher(cand.encode("utf-8")).hexdigest() == target:
                return {"found": True, "plaintext": cand,
                        "attempts": attempts}
            if progress and attempts % progress_every == 0:
                progress(attempts, last)
            if limit is not None and attempts >= limit:
                break
        return {"found": False, "plaintext": None, "attempts": attempts}


def estimate_mask_time(mask: str, hashes_per_second: float,
                       custom: dict[str, str] | None = None) -> dict:
    """Worst-case time to exhaust `mask` at a given hash rate.

    Returns seconds plus a human string in the largest sensible unit.
    """
    if hashes_per_second <= 0:
        raise ValueError("hashes_per_second must be positive")
    keyspace = mask_info(mask, custom)["keyspace_size"]
    seconds = keyspace / hashes_per_second
    return {
        "keyspace_size": keyspace,
        "seconds": seconds,
        "human": _human_seconds(seconds),
    }


def _human_seconds(seconds: float) -> str:
    units = (("year", 365 * 24 * 3600), ("day", 24 * 3600),
             ("hour", 3600), ("minute", 60), ("second", 1))
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            return f"{value:,.1f} {name}s" if value != 1 else f"1 {name}"
    return f"{seconds:.3f} seconds"
