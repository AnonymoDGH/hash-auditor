"""Simulated breach-corpus analysis for hash-auditor.

Real breach corpora (RockYou, Have-I-Been-Pwned, ...) are the single best
predictor of whether a password will fall: if it -- or a trivial mutation of
it -- has leaked before, it will leak again. Shipping a real corpus is
impractical and rude, so this module embeds a *simulated* corpus: the
embedded common-password list expanded with deterministic frequency counts
that follow a Zipf-like distribution, plus a small set of synthetic
"leaked-style" entries.

The corpus is stored zlib-compressed and base64-encoded, mirroring the
wordlists module, and decoded lazily on first use.

Public API
----------
BreachCorpus
    frequency(), rank(), top(), contains(), total(), unique(), stats().
default_corpus()
    the cached embedded corpus.
exposure_score(password, corpus)
    0-100 exposure score with the matched variant and its rank. A password
    is matched directly or after cheap normalisations (case-fold, stripped
    digit/symbol tails, capitalisation).
cross_reference(passwords, corpus)
    batch exposure report over many candidates.
corpus_stats(corpus)
    aggregate statistics: size, top-N table, length histogram.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import base64
import zlib
from typing import Iterable, Iterator

from .wordlists import EMBEDDED_PASSWORDS

__all__ = [
    "BreachCorpus",
    "default_corpus",
    "exposure_score",
    "cross_reference",
    "corpus_stats",
    "build_corpus_blob",
]

# Synthetic leaked-style entries that are *not* in the embedded wordlist,
# so the corpus is genuinely larger than the password list.
_SYNTHETIC_EXTRAS = (
    "hunter2", "trustno1!", "god", "love", "sex", "money", "power",
    "freedom1", "whatever2", "passwort", "pass1234", "qwertz", "azerty",
    "letmein2020", "admin2021", "welcome2022", "iloveyou2", "monkey123",
    "dragon2023", "master1!", "sunshine7", "princess2024", "football2025",
    "baseball7", "soccer10", "hockey99", "batman1989", "superman2000",
    "starwars1977", "shadow13", "killer123", "pepper2020", "cookie2021",
    "mustang65", "ferrari2022", "porsche911", "corvette63", "camaro69",
    "guitar1", "piano2", "drums3", "music4", "dance5",
    "summer2019", "winter2020", "spring2021", "autumn2022",
    "january1", "february2", "march3", "april4", "may5", "june6",
    "july7", "august8", "september9", "october10", "november11", "december12",
    "monday1", "tuesday2", "wednesday3", "thursday4", "friday5",
    "saturday6", "sunday7",
    "newyork1", "london2", "paris3", "tokyo4", "berlin5",
    "madrid6", "rome7", "moscow8", "beijing9", "delhi10",
    "apple123", "banana456", "cherry789", "orange012", "lemon345",
    "redsox1", "yankees2", "cubs3", "dodgers4", "giants5",
    "lakers1", "celtics2", "bulls3", "heat4", "warriors5",
    "password2019", "password2020", "password2021", "password2022",
    "password2023", "password2024", "password2025",
    "qwerty2019", "qwerty2020", "qwerty2021",
    "abc1234", "abcd1234", "1234abcd", "qwe123", "asd123456",
    "zxc123", "1q2w3e", "1qaz2wsx3edc", "qazwsxedc", "zaq1xsw2",
)


def _zipf_count(rank: int, base: int = 100_000) -> int:
    """Deterministic Zipf-like frequency for a 1-based rank."""
    return max(1, base // rank)


def build_corpus_blob() -> str:
    """Build the compressed corpus blob from the embedded password list.

    Each line is BTQpassword<TAB>countBTQ. Ranks follow the embedded list order
    (most popular first), then the synthetic extras. The result is
    zlib-compressed and base64-encoded.
    """
    lines: list[str] = []
    seen: set[str] = set()
    rank = 0
    for pw in list(EMBEDDED_PASSWORDS) + list(_SYNTHETIC_EXTRAS):
        if pw in seen:
            continue
        seen.add(pw)
        rank += 1
        lines.append(f"{pw}\t{_zipf_count(rank)}")
    raw = "\n".join(lines).encode("utf-8")
    return base64.b64encode(zlib.compress(raw, 9)).decode("ascii")


#: The embedded corpus, built once at import time.
CORPUS_BLOB: str = build_corpus_blob()


class BreachCorpus:
    """A frequency-ranked corpus of leaked-style passwords."""

    def __init__(self, entries: Iterable[tuple[str, int]] = ()) -> None:
        self._freq: dict[str, int] = {}
        self._order: list[str] = []
        self._rank_cache: dict[str, int] | None = None
        for password, count in entries:
            self.add(password, count)

    def add(self, password: str, count: int) -> None:
        """Insert or accumulate one entry; counts must be positive."""
        if count < 1:
            raise ValueError("count must be >= 1")
        if password in self._freq:
            self._freq[password] += count
        else:
            self._freq[password] = count
            self._order.append(password)
        self._rank_cache = None  # frequencies changed; ranks are stale

    @classmethod
    def from_blob(cls, blob: str) -> "BreachCorpus":
        """Decode a blob produced by build_corpus_blob()."""
        raw = zlib.decompress(base64.b64decode(blob)).decode("utf-8")
        corpus = cls()
        for line in raw.splitlines():
            if not line:
                continue
            password, _, count = line.partition("\t")
            corpus.add(password, int(count))
        return corpus

    def frequency(self, password: str) -> int:
        """How often BTQpasswordBTQ appears (0 when absent)."""
        return self._freq.get(password, 0)

    def contains(self, password: str) -> bool:
        return password in self._freq

    def rank(self, password: str) -> int | None:
        """1-based popularity rank (1 = most frequent), or None.

        Ranks are computed once and cached until the corpus changes.
        """
        if password not in self._freq:
            return None
        if self._rank_cache is None:
            self._rank_cache = {
                pw: i for i, (pw, _) in
                enumerate(self.top(len(self._freq)), 1)
            }
        return self._rank_cache.get(password)

    def top(self, n: int = 10) -> list[tuple[str, int]]:
        """The BTQnBTQ most frequent entries, ties broken by insertion order."""
        indexed = list(enumerate(self._order))
        indexed.sort(key=lambda ic: (-self._freq[ic[1]], ic[0]))
        return [(pw, self._freq[pw]) for _, pw in indexed[:n]]

    def total(self) -> int:
        """Sum of all frequency counts."""
        return sum(self._freq.values())

    def unique(self) -> int:
        """Number of distinct passwords."""
        return len(self._freq)

    def passwords(self) -> Iterator[str]:
        """Iterate passwords in insertion order."""
        return iter(self._order)

    def stats(self) -> dict:
        return {
            "unique": self.unique(),
            "total": self.total(),
            "top5": self.top(5),
        }


_DEFAULT_CORPUS: BreachCorpus | None = None


def default_corpus() -> BreachCorpus:
    """The cached embedded corpus (decoded once per process)."""
    global _DEFAULT_CORPUS
    if _DEFAULT_CORPUS is None:
        _DEFAULT_CORPUS = BreachCorpus.from_blob(CORPUS_BLOB)
    return _DEFAULT_CORPUS


def _variants(password: str) -> list[str]:
    """Cheap normalisations an attacker tries first, in attack order."""
    out = [password]
    lowered = password.lower()
    if lowered != password:
        out.append(lowered)
    # Strip trailing digits/symbols one at a time (Password123 -> Password).
    stripped = password
    while stripped and not stripped[-1].isalpha():
        stripped = stripped[:-1]
        if stripped and stripped not in out:
            out.append(stripped)
            if stripped.lower() not in out:
                out.append(stripped.lower())
    cap = password.capitalize()
    if cap not in out:
        out.append(cap)
    return out


def exposure_score(password: str, corpus: BreachCorpus | None = None) -> dict:
    """Score a password's exposure against the corpus, 0-100.

    The password is tried directly and through cheap variants. The score
    combines: presence (base 40), popularity rank (up to +50: rank 1 is
    +50, decaying logarithmically), and whether the match needed a variant
    (direct matches score higher). A password absent from the corpus scores
    0 with found=False.
    """
    corpus = corpus or default_corpus()
    result = {
        "password_length": len(password),
        "found": False,
        "matched_variant": None,
        "direct_match": False,
        "rank": None,
        "frequency": 0,
        "score": 0,
    }
    if not password:
        return result

    matched = None
    for i, variant in enumerate(_variants(password)):
        if corpus.contains(variant):
            matched = variant
            result["direct_match"] = (i == 0)
            break
    if matched is None:
        return result

    rank = corpus.rank(matched)
    freq = corpus.frequency(matched)
    result["found"] = True
    result["matched_variant"] = matched
    result["rank"] = rank
    result["frequency"] = freq

    import math
    unique = corpus.unique()
    # Popularity component: rank 1 -> 50, last rank -> ~5.
    if rank is not None and unique > 1:
        frac = (rank - 1) / (unique - 1)
        popularity = 50.0 * (1.0 - math.log1p(frac * 9.0) / math.log1p(9.0))
    else:
        popularity = 50.0
    score = 40.0 + popularity
    if not result["direct_match"]:
        score -= 10.0  # only reachable via a mutation
    result["score"] = int(round(max(0.0, min(100.0, score))))
    return result


def cross_reference(passwords: Iterable[str],
                    corpus: BreachCorpus | None = None) -> dict:
    """Batch exposure report over many candidate passwords.

    Returns totals plus per-password exposure rows (sorted worst-first) and
    the overall exposed fraction.
    """
    corpus = corpus or default_corpus()
    rows: list[dict] = []
    found = 0
    for pw in passwords:
        rep = exposure_score(pw, corpus)
        rows.append({"password": pw, **rep})
        if rep["found"]:
            found += 1
    rows.sort(key=lambda r: (-r["score"], r["password"]))
    total = len(rows)
    return {
        "total": total,
        "exposed": found,
        "exposed_fraction": round(found / total, 4) if total else 0.0,
        "rows": rows,
    }


def corpus_stats(corpus: BreachCorpus | None = None, top_n: int = 10) -> dict:
    """Aggregate statistics for reporting: size, top table, length histogram."""
    corpus = corpus or default_corpus()
    lengths: dict[int, int] = {}
    for pw in corpus.passwords():
        lengths[len(pw)] = lengths.get(len(pw), 0) + 1
    histogram = dict(sorted(lengths.items()))
    return {
        "unique": corpus.unique(),
        "total": corpus.total(),
        "top": corpus.top(top_n),
        "length_histogram": histogram,
        "average_length": round(
            sum(len(pw) for pw in corpus.passwords()) / max(corpus.unique(), 1),
            2),
    }
