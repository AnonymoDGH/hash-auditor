"""Incremental brute force with checkpointing for hash-auditor.

Exhaustive search over a charset, ordered by length then lexicographically
(the classic "incremental" mode). The distinguishing feature here is
*resumability*: the search state is a single integer index into the ordered
keyspace, so a run can be checkpointed to disk and resumed later without
re-trying candidates.

Keyspace ordering
-----------------
Length 1: every charset character in order.
Length 2: every pair, lexicographic.
... and so on. The index of a candidate is its rank in this ordering, which
gives an O(1) resume point and a clean progress fraction.

Public API
----------
incremental_index(alphabet, length, rank)
    global index of the BTQrankBTQ-th password of BTQlengthBTQ.
index_to_candidate(alphabet, index)
    decode a global index into its candidate string.
BruteForcer
    stream candidates, crack a hash, checkpoint/resume.
Checkpoint
    JSON-serialisable resume state.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

__all__ = [
    "incremental_index",
    "index_to_candidate",
    "candidate_to_index",
    "BruteForcer",
    "Checkpoint",
]

_HASHLIB = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def _count_up_to(alphabet: str, length: int) -> int:
    """Number of candidates of length < BTQlengthBTQ (geometric sum)."""
    base = len(alphabet)
    if base <= 1:
        return length - 1
    return (base ** length - base) // (base - 1)


def incremental_index(alphabet: str, length: int, rank: int) -> int:
    """Global index of the BTQrankBTQ-th (0-based) password of BTQlengthBTQ."""
    if length < 1:
        raise ValueError("length must be >= 1")
    base = len(alphabet)
    if not 0 <= rank < base ** length:
        raise ValueError("rank out of range for this length")
    return _count_up_to(alphabet, length) + rank


def index_to_candidate(alphabet: str, index: int) -> str:
    """Decode a global index into its candidate string."""
    if index < 0:
        raise ValueError("index must be >= 0")
    base = len(alphabet)
    length = 1
    while index >= _count_up_to(alphabet, length + 1):
        length += 1
    rank = index - _count_up_to(alphabet, length)
    chars = []
    for _ in range(length):
        chars.append(alphabet[rank % base])
        rank //= base
    return "".join(reversed(chars))


def candidate_to_index(alphabet: str, candidate: str) -> int:
    """Inverse of index_to_candidate()."""
    base = len(alphabet)
    pos = {ch: i for i, ch in enumerate(alphabet)}
    rank = 0
    for ch in candidate:
        if ch not in pos:
            raise ValueError(f"character {ch!r} not in alphabet")
        rank = rank * base + pos[ch]
    return incremental_index(alphabet, len(candidate), rank)


@dataclass
class Checkpoint:
    """Resumable search state."""

    alphabet: str
    algo: str
    target: str
    next_index: int = 0
    attempts: int = 0

    def to_json(self) -> str:
        return json.dumps({
            "alphabet": self.alphabet,
            "algo": self.algo,
            "target": self.target,
            "next_index": self.next_index,
            "attempts": self.attempts,
        }, indent=1)

    @classmethod
    def from_json(cls, text: str) -> "Checkpoint":
        data = json.loads(text)
        return cls(alphabet=data["alphabet"], algo=data["algo"],
                   target=data["target"], next_index=data["next_index"],
                   attempts=data["attempts"])

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.write_text(self.to_json(), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str | Path) -> "Checkpoint":
        return cls.from_json(Path(path).read_text(encoding="utf-8"))


class BruteForcer:
    """Incremental brute-force over a charset with resume support."""

    def __init__(self, alphabet: str, algo: str = "md5") -> None:
        if not alphabet:
            raise ValueError("alphabet must be non-empty")
        algo = algo.lower()
        if algo not in _HASHLIB:
            raise ValueError(f"unknown algorithm {algo!r}")
        self.alphabet = alphabet
        self.algo = algo
        self._hasher = _HASHLIB[algo]

    def candidates(self, start_index: int = 0,
                   max_index: int | None = None) -> Iterator[tuple[int, str]]:
        """Yield (index, candidate) from BTQstart_indexBTQ onward."""
        index = start_index
        while max_index is None or index < max_index:
            yield index, index_to_candidate(self.alphabet, index)
            index += 1

    def crack(self, target_hash: str, start_index: int = 0,
              max_attempts: int | None = None,
              checkpoint_path: str | Path | None = None,
              checkpoint_every: int = 10_000,
              progress: Callable[[int, str], None] | None = None,
              progress_every: int = 10_000) -> dict:
        """Search for BTQtarget_hashBTQ; returns found/plaintext/attempts/index.

        When BTQcheckpoint_pathBTQ is given the state is written every
        BTQcheckpoint_everyBTQ attempts so an interrupted run can resume from
        the saved next_index.
        """
        target = target_hash.strip().lower()
        checkpoint = Checkpoint(alphabet=self.alphabet, algo=self.algo,
                                target=target, next_index=start_index)
        attempts = 0
        for index, cand in self.candidates(start_index):
            attempts += 1
            if self._hasher(cand.encode("utf-8")).hexdigest() == target:
                return {"found": True, "plaintext": cand,
                        "attempts": attempts, "index": index}
            if progress and attempts % progress_every == 0:
                progress(attempts, cand)
            if checkpoint_path and attempts % checkpoint_every == 0:
                checkpoint.next_index = index + 1
                checkpoint.attempts = attempts
                checkpoint.save(checkpoint_path)
            if max_attempts is not None and attempts >= max_attempts:
                if checkpoint_path:
                    checkpoint.next_index = index + 1
                    checkpoint.attempts = attempts
                    checkpoint.save(checkpoint_path)
                break
        return {"found": False, "plaintext": None,
                "attempts": attempts,
                "index": checkpoint.next_index}
