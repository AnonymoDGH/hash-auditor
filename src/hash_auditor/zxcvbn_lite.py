"""zxcvbn-lite: a pattern-based password strength estimator.

A compact, deterministic re-imagining of Dropbox's zxcvbn, built on the
embedded wordlists from hash_auditor.wordlists. It finds greedy, overlapping
pattern matches in a password and estimates the minimum number of guesses an
attacker would need, then converts that into crack times for four standard
attack speeds and a 0-4 score.

Detected patterns
-----------------
* dictionary  -- ranked substring matches against the embedded password,
                   word and name lists, with an uppercase-variation penalty.
* l33t        -- dictionary matches after reversing common l33t substitutions
                   (4->a, @->a, 3->e, 1->i/l, 0->o, 5->s, $->s, 7->t).
* spatial     -- keyboard walks on an embedded QWERTY adjacency graph
                   ('qwerty', 'zxcvbn', 'asdfgh', ...).
* date        -- years 1900-2039 and day/month/year layouts.
* repeat      -- runs of one character ('aaa', '1111').
* sequence    -- ascending/descending runs ('abc', '123', 'cba', '987').
* brute       -- whatever is left over, priced by character-class pool size.

Public API
----------
estimate(password) -> dict
    Full report: every match found, the optimal match sequence, total
    guesses, crack_times_seconds for four attack speeds, human-readable
    crack_times_display, and a 0-4 score.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import math
import re
from typing import Iterator

from .wordlists import EMBEDDED_NAMES, EMBEDDED_PASSWORDS, EMBEDDED_WORDS

__all__ = [
    "estimate",
    "L33T_MAP",
    "QWERTY_GRAPH",
    "ATTACK_SPEEDS",
    "dictionary_matches",
    "l33t_matches",
    "spatial_matches",
    "date_matches",
    "repeat_matches",
    "sequence_matches",
]

# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

#: l33t character -> tuple of letters it commonly stands for.
L33T_MAP: dict[str, tuple[str, ...]] = {
    "4": ("a",),
    "@": ("a",),
    "3": ("e",),
    "1": ("i", "l"),
    "0": ("o",),
    "5": ("s",),
    "$": ("s",),
    "7": ("t",),
}

#: Attack scenarios -> guesses per second (zxcvbn's standard four).
ATTACK_SPEEDS: dict[str, float] = {
    "online_throttling_100_per_hour": 100.0 / 3600.0,
    "online_no_throttling_10_per_second": 10.0,
    "offline_slow_hashing_10k_per_second": 1e4,
    "offline_fast_hashing_10b_per_second": 1e10,
}

#: Guess thresholds for the 0-4 score (zxcvbn-compatible).
_SCORE_THRESHOLDS = (1e3, 1e6, 1e8, 1e10)

# ---------------------------------------------------------------------------
# QWERTY adjacency graph, built once from keyboard geometry.
# ---------------------------------------------------------------------------


def _build_qwerty_graph() -> dict[str, frozenset[str]]:
    """Build an adjacency map for the unshifted QWERTY layout.

    Keys are placed on a staggered grid; two keys are adjacent when their
    grid distance is at most ~1.1 columns and at most 1 row apart. The
    result includes letters and the digit row.
    """
    rows = [
        (0.0, "1234567890"),
        (0.5, "qwertyuiop"),
        (0.75, "asdfghjkl"),
        (1.25, "zxcvbnm"),
    ]
    coords: dict[str, tuple[float, int]] = {}
    for row_idx, (offset, keys) in enumerate(rows):
        for col, key in enumerate(keys):
            coords[key] = (offset + col, row_idx)

    graph: dict[str, set[str]] = {k: set() for k in coords}
    items = list(coords.items())
    for a, (ax, ay) in items:
        for b, (bx, by) in items:
            if a != b and abs(ay - by) <= 1 and abs(ax - bx) <= 1.1:
                graph[a].add(b)
    return {k: frozenset(v) for k, v in graph.items()}


#: QWERTY adjacency: key -> frozenset of neighbouring keys.
QWERTY_GRAPH: dict[str, frozenset[str]] = _build_qwerty_graph()

# ---------------------------------------------------------------------------
# Ranked dictionaries.
# ---------------------------------------------------------------------------


def _rank(words: list[str]) -> dict[str, int]:
    """Map each lowercased word to its 1-based rank (first wins)."""
    out: dict[str, int] = {}
    for i, w in enumerate(words):
        lw = w.lower()
        if lw not in out:
            out[lw] = i + 1
    return out


#: Ranked dictionaries used by dictionary_match, smallest ranks first.
_RANKED_DICTS: dict[str, dict[str, int]] = {
    "passwords": _rank(EMBEDDED_PASSWORDS),
    "words": _rank(EMBEDDED_WORDS),
    "names": _rank(EMBEDDED_NAMES),
}


# ---------------------------------------------------------------------------
# Match helpers. A match is a dict:
#   pattern, i, j (half-open span), token, guesses, plus pattern details.
# ---------------------------------------------------------------------------


def _uppercase_variants(token: str) -> int:
    """Number of plausible uppercase spellings of token (zxcvbn-lite)."""
    letters = [ch for ch in token if ch.isalpha()]
    if not letters or all(ch.islower() for ch in letters):
        return 1
    if token[0].isupper() and all(
        ch.islower() or not ch.isalpha() for ch in token[1:]
    ):
        return 2  # Leading-capital: word or Word.
    if all(ch.isupper() for ch in letters):
        return 2  # word or WORD.
    return 4  # Arbitrary mixing costs a bit more.


def dictionary_matches(password: str) -> list[dict]:
    """Find ranked dictionary words in every substring of password.

    Matching is case-insensitive; an uppercase-variation multiplier is
    applied when the token is not all-lowercase.
    """
    matches: list[dict] = []
    n = len(password)
    lowered = password.lower()
    for i in range(n):
        for j in range(i + 2, min(i + 31, n) + 1):  # words are >= 2 chars
            token = lowered[i:j]
            for dict_name, ranks in _RANKED_DICTS.items():
                rank = ranks.get(token)
                if rank is not None:
                    matches.append({
                        "pattern": "dictionary",
                        "i": i,
                        "j": j,
                        "token": password[i:j],
                        "matched_word": token,
                        "dictionary": dict_name,
                        "rank": rank,
                        "guesses": rank * _uppercase_variants(password[i:j]),
                    })
    return matches


def _l33t_variants(password: str) -> Iterator[str]:
    """Yield de-l33ted variants of password (bounded at 256 variants)."""
    chars: list[tuple[str, ...]] = []
    for ch in password:
        chars.append((ch,) + L33T_MAP.get(ch, ()))
    total = 1
    for opts in chars:
        total *= len(opts)
        if total > 256:
            total = 256
            break

    def walk(pos: int, acc: list[str]) -> Iterator[str]:
        if pos == len(chars):
            yield "".join(acc)
            return
        for opt in chars[pos]:
            acc.append(opt)
            yield from walk(pos + 1, acc)
            acc.pop()

    seen: set[str] = set()
    for variant in walk(0, []):
        if variant not in seen:
            seen.add(variant)
            yield variant


def l33t_matches(password: str) -> list[dict]:
    """Dictionary matches found after reversing l33t substitutions.

    Only considered when the password contains at least one l33t character.
    Each match's guesses are multiplied by 2 ** (number of l33t chars in
    the matched token) to account for the substitution choices.
    """
    if not any(ch in L33T_MAP for ch in password):
        return []
    found: list[dict] = []
    seen_spans: set[tuple[int, int, str]] = set()
    for variant in _l33t_variants(password):
        if variant == password.lower():
            continue
        for m in dictionary_matches(variant):
            token = password[m["i"]:m["j"]]
            if token.lower() == m["matched_word"]:
                continue  # Not actually l33ted -- plain dictionary match.
            key = (m["i"], m["j"], m["matched_word"])
            if key in seen_spans:
                continue
            seen_spans.add(key)
            subs = sum(1 for ch in token if ch in L33T_MAP)
            found.append({
                **m,
                "pattern": "l33t",
                "token": token,
                "l33t_chars": subs,
                "guesses": m["guesses"] * (2 ** max(subs, 1)),
            })
    return found


def spatial_matches(password: str) -> list[dict]:
    """Detect keyboard walks of length >= 3 on the QWERTY graph."""
    matches: list[dict] = []
    n = len(password)
    i = 0
    lowered = password.lower()
    while i < n - 1:
        j = i + 1
        turns = 0
        while j < n:
            prev, cur = lowered[j - 1], lowered[j]
            if prev in QWERTY_GRAPH and cur in QWERTY_GRAPH[prev]:
                j += 1
            else:
                break
        length = j - i
        if length >= 3:
            # Count direction changes (turns) inside the walk.
            for k in range(i + 2, j):
                a, b, c = lowered[k - 2], lowered[k - 1], lowered[k]
                if b in QWERTY_GRAPH and a in QWERTY_GRAPH[b] and c in QWERTY_GRAPH[b]:
                    if a != c:
                        turns += 1
            avg_degree = sum(len(v) for v in QWERTY_GRAPH.values()) / len(QWERTY_GRAPH)
            guesses = len(QWERTY_GRAPH) * avg_degree * length * (turns + 1)
            matches.append({
                "pattern": "spatial",
                "i": i,
                "j": j,
                "token": password[i:j],
                "turns": turns,
                "guesses": int(guesses),
            })
            i = j
        else:
            i += 1
    return matches


_YEAR_RE = re.compile(r"(19\d{2}|20[0-3]\d)")
_DATE_SEP_RE = re.compile(
    r"(\d{1,2})[/\-.](\d{1,2})[/\-.](19\d{2}|20[0-3]\d)"
)
_DATE_RAW_RE = re.compile(r"(\d{2})(\d{2})(19\d{2}|20[0-3]\d)")


def date_matches(password: str) -> list[dict]:
    """Detect years (1900-2039) and day/month/year layouts."""
    matches: list[dict] = []
    for m in _DATE_SEP_RE.finditer(password):
        matches.append({
            "pattern": "date",
            "i": m.start(),
            "j": m.end(),
            "token": m.group(0),
            "separator": m.group(0)[len(m.group(1))],
            "guesses": 365 * 140,
        })
    covered = {(m["i"], m["j"]) for m in matches}
    for m in _DATE_RAW_RE.finditer(password):
        if not any(ci <= m.start() and m.end() <= cj for ci, cj in covered):
            matches.append({
                "pattern": "date",
                "i": m.start(),
                "j": m.end(),
                "token": m.group(0),
                "separator": "",
                "guesses": 365 * 140,
            })
    for m in _YEAR_RE.finditer(password):
        if not any(ci <= m.start() and m.end() <= cj for ci, cj in covered):
            matches.append({
                "pattern": "date",
                "i": m.start(),
                "j": m.end(),
                "token": m.group(0),
                "year": int(m.group(0)),
                "guesses": 140,
            })
    return matches


def repeat_matches(password: str) -> list[dict]:
    """Detect runs of a single character of length >= 3 ('aaa', '1111')."""
    matches: list[dict] = []
    for m in re.finditer(r"(.)\1{2,}", password):
        ch = m.group(1)
        matches.append({
            "pattern": "repeat",
            "i": m.start(),
            "j": m.end(),
            "token": m.group(0),
            "base_char": ch,
            "guesses": _brute_char_guesses(ch) * len(m.group(0)),
        })
    return matches


def sequence_matches(password: str) -> list[dict]:
    """Detect ascending/descending letter/digit runs of length >= 3."""
    matches: list[dict] = []
    n = len(password)
    i = 0
    while i < n - 2:
        a, b = password[i], password[i + 1]
        if a.isalnum() and b.isalnum() and ord(b) - ord(a) in (1, -1) \
                and a.isalpha() == b.isalpha():
            step = ord(b) - ord(a)
            j = i + 2
            while j < n and password[j].isalnum() \
                    and password[j].isalpha() == a.isalpha() \
                    and ord(password[j]) - ord(password[j - 1]) == step:
                j += 1
            length = j - i
            if length >= 3:
                first = password[i]
                if first in "aAzZ019":
                    base = 4
                elif first.isdigit():
                    base = 10
                else:
                    base = 26
                matches.append({
                    "pattern": "sequence",
                    "i": i,
                    "j": j,
                    "token": password[i:j],
                    "ascending": step == 1,
                    "guesses": base * length,
                })
                i = j
                continue
        i += 1
    return matches


# ---------------------------------------------------------------------------
# Brute-force pricing and the final estimate.
# ---------------------------------------------------------------------------


def _brute_char_guesses(ch: str) -> int:
    """Pool size for a single character under brute force."""
    if ch.islower():
        return 26
    if ch.isupper():
        return 26
    if ch.isdigit():
        return 10
    return 33


def _display_time(seconds: float) -> str:
    """Human-readable crack time, zxcvbn-style."""
    if seconds < 1:
        return "less than a second"
    minute, hour, day = 60.0, 3600.0, 86400.0
    if seconds < minute:
        return f"{math.ceil(seconds)} seconds"
    if seconds < hour:
        return f"{math.ceil(seconds / minute)} minutes"
    if seconds < day:
        return f"{math.ceil(seconds / hour)} hours"
    if seconds < day * 31:
        return f"{math.ceil(seconds / day)} days"
    if seconds < day * 365:
        return f"{math.ceil(seconds / (day * 31))} months"
    if seconds < day * 365 * 100:
        return f"{math.ceil(seconds / (day * 365))} years"
    return "centuries"


def estimate(password: str) -> dict:
    """Estimate the strength of password.

    Returns a dict with:

    * 'password' -- the input,
    * 'matches' -- every pattern match found (may overlap),
    * 'sequence' -- the optimal non-overlapping match sequence covering the
      whole password (brute-force segments included),
    * 'guesses' / 'log10_guesses' -- total estimated guesses,
    * 'crack_times_seconds' -- dict over the four ATTACK_SPEEDS scenarios,
    * 'crack_times_display' -- human-readable version of the above,
    * 'score' -- 0 (trivial) to 4 (strong).
    """
    if not password:
        return {
            "password": password,
            "matches": [],
            "sequence": [],
            "guesses": 0,
            "log10_guesses": 0.0,
            "crack_times_seconds": {k: 0.0 for k in ATTACK_SPEEDS},
            "crack_times_display": {k: "less than a second" for k in ATTACK_SPEEDS},
            "score": 0,
        }

    matches: list[dict] = []
    matches += dictionary_matches(password)
    matches += l33t_matches(password)
    matches += spatial_matches(password)
    matches += date_matches(password)
    matches += repeat_matches(password)
    matches += sequence_matches(password)

    n = len(password)
    # dp[k] = (min guesses to cover password[:k], backpointer match or None)
    dp: list[float] = [1.0] + [math.inf] * n
    back: list[dict | None] = [None] * (n + 1)
    by_end: dict[int, list[dict]] = {}
    for m in matches:
        by_end.setdefault(m["j"], []).append(m)

    for k in range(1, n + 1):
        # Extend brute force by one character.
        cost = dp[k - 1] * _brute_char_guesses(password[k - 1])
        if cost < dp[k]:
            dp[k] = cost
            back[k] = None
        for m in by_end.get(k, ()):
            cost = dp[m["i"]] * max(m["guesses"], 1)
            if cost < dp[k]:
                dp[k] = cost
                back[k] = m

    # Walk backpointers to recover the optimal sequence.
    sequence: list[dict] = []
    k = n
    while k > 0:
        m = back[k]
        if m is None:
            # Merge into a trailing brute-force segment.
            start = k - 1
            while start > 0 and back[start] is None:
                start -= 1
            guesses = 1
            for ch in password[start:k]:
                guesses *= _brute_char_guesses(ch)
            sequence.append({
                "pattern": "bruteforce",
                "i": start,
                "j": k,
                "token": password[start:k],
                "guesses": guesses,
            })
            k = start
        else:
            sequence.append(m)
            k = m["i"]
    sequence.reverse()

    guesses = int(dp[n])
    crack_times = {
        name: guesses / speed for name, speed in ATTACK_SPEEDS.items()
    }
    score = 0
    for threshold in _SCORE_THRESHOLDS:
        if guesses >= threshold:
            score += 1

    return {
        "password": password,
        "matches": matches,
        "sequence": sequence,
        "guesses": guesses,
        "log10_guesses": math.log10(guesses) if guesses > 0 else 0.0,
        "crack_times_seconds": crack_times,
        "crack_times_display": {
            name: _display_time(t) for name, t in crack_times.items()
        },
        "score": score,
    }
