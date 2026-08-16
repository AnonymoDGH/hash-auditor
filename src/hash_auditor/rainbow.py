"""Rainbow tables: a small, deterministic time-memory tradeoff engine.

A rainbow table trades disk space for cracking time. Instead of hashing every
candidate (brute force) or storing every hash (lookup table), it stores only
the *endpoints* of long reduction chains:

    start --H--> hash --R_0--> pw --H--> hash --R_1--> ... --R_{t-1}--> end

Each column of the table uses a *different* reduction function R_i, which is
what distinguishes rainbow tables from naive chain tables and suppresses most
collisions. To look up a target hash, the table walks the hash forward from
every possible column position; when a walk lands on a stored endpoint, the
corresponding start point is regenerated and searched for the plaintext.

This implementation is deliberately small and fully deterministic so it can
be exercised end-to-end in unit tests:

* MD5 is the hash (fast, and the classic rainbow-table target);
* the keyspace is an arbitrary alphabet raised to a fixed password length;
* reduction maps a digest to a keyspace index via big-integer modulo.

Public API
----------
keyspace(alphabet, length)
    every password over `alphabet` of exactly `length` chars, in order.
reduction(digest, column, size)
    the column-specific reduction function, digest -> keyspace index.
RainbowTable
    build / save / load / lookup / coverage. Tables serialise to JSON.
build_table(alphabet, length, chains, chain_length, seed)
    convenience constructor with a seeded start-point generator.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import random
from pathlib import Path
from typing import Iterator

__all__ = [
    "keyspace",
    "keyspace_size",
    "index_to_password",
    "password_to_index",
    "reduction",
    "RainbowTable",
    "build_table",
]


def keyspace(alphabet: str, length: int) -> Iterator[str]:
    """Yield every password of `length` characters over `alphabet`.

    Order is lexicographic with respect to the alphabet, which is also the
    order implied by index_to_password(). Duplicate characters in the
    alphabet are removed (first occurrence wins) so the mapping stays a
    bijection.
    """
    alphabet = _dedupe(alphabet)
    if length < 1:
        raise ValueError("length must be >= 1")
    for combo in itertools.product(alphabet, repeat=length):
        yield "".join(combo)


def keyspace_size(alphabet: str, length: int) -> int:
    """Number of passwords of `length` over `alphabet`."""
    return len(_dedupe(alphabet)) ** length


def _dedupe(alphabet: str) -> str:
    seen: set[str] = set()
    out: list[str] = []
    for ch in alphabet:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
    return "".join(out)


def index_to_password(alphabet: str, length: int, index: int) -> str:
    """Map a keyspace index to its password (mixed-radix decode)."""
    alphabet = _dedupe(alphabet)
    base = len(alphabet)
    size = base ** length
    if not 0 <= index < size:
        raise ValueError(f"index {index} outside keyspace of size {size}")
    chars: list[str] = []
    for _ in range(length):
        chars.append(alphabet[index % base])
        index //= base
    return "".join(reversed(chars))


def password_to_index(alphabet: str, password: str) -> int:
    """Inverse of index_to_password(); raises on foreign characters."""
    alphabet = _dedupe(alphabet)
    base = len(alphabet)
    pos = {ch: i for i, ch in enumerate(alphabet)}
    index = 0
    for ch in password:
        if ch not in pos:
            raise ValueError(f"character {ch!r} not in alphabet")
        index = index * base + pos[ch]
    return index


def reduction(digest: bytes, column: int, size: int) -> int:
    """Reduce a digest to a keyspace index for a given chain column.

    The column is mixed into the digest bytes before the big-integer modulo
    so that every column of the table uses a distinct reduction function --
    the defining property of a rainbow table.
    """
    if size < 1:
        raise ValueError("size must be >= 1")
    mixed = bytes(b ^ (column & 0xFF) for b in digest)
    return int.from_bytes(hashlib.md5(mixed).digest(), "big") % size


class RainbowTable:
    """A rainbow table over one keyspace.

    Attributes
    ----------
    alphabet, length:
        define the keyspace.
    chain_length:
        number of hash/reduction steps per chain (the `t` parameter).
    chains:
        list of `(endpoint_index, start_index)` pairs, one per chain.
    """

    def __init__(self, alphabet: str, length: int, chain_length: int) -> None:
        if chain_length < 1:
            raise ValueError("chain_length must be >= 1")
        self.alphabet = _dedupe(alphabet)
        self.length = length
        self.chain_length = chain_length
        self.chains: list[tuple[int, int]] = []

    # -- construction -------------------------------------------------------

    @property
    def size(self) -> int:
        """Keyspace size."""
        return keyspace_size(self.alphabet, self.length)

    def add_chain(self, start_index: int) -> int:
        """Compute one chain from `start_index` and store its endpoint.

        Returns the endpoint index. The chain itself is *not* stored -- only
        the (endpoint, start) pair, which is the whole point of the tradeoff.
        """
        if not 0 <= start_index < self.size:
            raise ValueError("start_index outside keyspace")
        index = start_index
        for column in range(self.chain_length):
            password = index_to_password(self.alphabet, self.length, index)
            digest = hashlib.md5(password.encode("utf-8")).digest()
            index = reduction(digest, column, self.size)
        self.chains.append((index, start_index))
        return index

    # -- lookup --------------------------------------------------------------

    def _walk(self, index: int, from_column: int, to_column: int) -> int:
        """Advance a keyspace index through columns [from_column, to_column)."""
        for column in range(from_column, to_column):
            password = index_to_password(self.alphabet, self.length, index)
            digest = hashlib.md5(password.encode("utf-8")).digest()
            index = reduction(digest, column, self.size)
        return index

    def lookup(self, target_hash: str) -> str | None:
        """Find the plaintext for `target_hash`, or None.

        For each possible column position the target hash is walked forward
        to the end of the chain; a hit on a stored endpoint triggers a
        regeneration of that chain from its start point, and the chain is
        scanned for a password whose hash matches the target. False alarms
        (endpoint collisions) are verified and rejected.
        """
        target = target_hash.strip().lower()
        if not _is_hex(target):
            return None
        target_digest = bytes.fromhex(target)

        endpoint_map: dict[int, list[int]] = {}
        for endpoint, start in self.chains:
            endpoint_map.setdefault(endpoint, []).append(start)

        for column in range(self.chain_length):
            # Reduce the target with this column's function, walk the rest.
            index = reduction(target_digest, column, self.size)
            walked = self._walk(index, column + 1, self.chain_length)
            for start in endpoint_map.get(walked, []):
                found = self._regenerate(start, column, target)
                if found is not None:
                    return found
        return None

    def _regenerate(self, start_index: int, hit_column: int,
                    target: str) -> str | None:
        """Re-walk a chain from its start, checking hashes up to hit_column."""
        index = start_index
        for column in range(hit_column + 1):
            password = index_to_password(self.alphabet, self.length, index)
            if hashlib.md5(password.encode("utf-8")).hexdigest() == target:
                return password
            digest = hashlib.md5(password.encode("utf-8")).digest()
            index = reduction(digest, column, self.size)
        return None

    # -- statistics -----------------------------------------------------------

    def coverage(self) -> float:
        """Fraction of the keyspace reachable from the stored start points.

        A lower bound on crackable coverage: distinct start points divided by
        keyspace size. Merges reduce real coverage, which is why rainbow
        tables are measured empirically.
        """
        if not self.chains:
            return 0.0
        starts = {start for _, start in self.chains}
        return len(starts) / self.size

    def stats(self) -> dict:
        """Summary dict: keyspace, chain geometry, coverage."""
        return {
            "alphabet": self.alphabet,
            "length": self.length,
            "keyspace_size": self.size,
            "chain_length": self.chain_length,
            "chains": len(self.chains),
            "distinct_starts": len({s for _, s in self.chains}),
            "coverage": round(self.coverage(), 6),
        }

    # -- serialisation ---------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialisable representation of the table."""
        return {
            "format": "hash-auditor-rainbow/1",
            "hash": "md5",
            "alphabet": self.alphabet,
            "length": self.length,
            "chain_length": self.chain_length,
            "chains": [[endpoint, start] for endpoint, start in self.chains],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RainbowTable":
        """Rebuild a table from to_dict() output."""
        if data.get("format") != "hash-auditor-rainbow/1":
            raise ValueError("not a hash-auditor rainbow table")
        if data.get("hash") != "md5":
            raise ValueError(f"unsupported hash: {data.get('hash')!r}")
        table = cls(data["alphabet"], data["length"], data["chain_length"])
        table.chains = [(int(e), int(s)) for e, s in data["chains"]]
        return table

    def save(self, path: str | Path) -> Path:
        """Write the table to `path` as JSON; returns the path."""
        path = Path(path)
        path.write_text(json.dumps(self.to_dict(), indent=1), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str | Path) -> "RainbowTable":
        """Read a table written by save()."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)


def build_table(alphabet: str, length: int, chains: int, chain_length: int,
                seed: int = 0) -> RainbowTable:
    """Build a table with `chains` seeded-random start points.

    The same arguments and seed always produce the same table, which keeps
    tests deterministic. Start points are sampled without replacement when
    the keyspace is large enough, with replacement otherwise.
    """
    if chains < 1:
        raise ValueError("chains must be >= 1")
    table = RainbowTable(alphabet, length, chain_length)
    rng = random.Random(seed)
    size = table.size
    if chains <= size:
        starts = rng.sample(range(size), chains)
    else:
        starts = [rng.randrange(size) for _ in range(chains)]
    for start in starts:
        table.add_chain(start)
    return table


def _is_hex(text: str) -> bool:
    if len(text) % 2:
        return False
    try:
        bytes.fromhex(text)
        return True
    except ValueError:
        return False
