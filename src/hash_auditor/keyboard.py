"""Keyboard-walk (spatial) password generation for hash-auditor.

Passwords like BTQqwertyBTQ, BTQ1qaz2wsxBTQ and BTQzxcvbnBTQ are keyboard walks:
the finger traces a path across adjacent keys. Attackers generate these
systematically. This module models the QWERTY board as a graph and
enumerates walks of a given length, optionally with shift variations.

Public API
----------
KEYBOARD_ROWS
    the staggered QWERTY layout used for adjacency.
adjacency_graph()
    key -> frozenset of adjacent keys.
walks(length, start)
    every spatial walk of BTQlengthBTQ keys, optionally from BTQstartBTQ.
walk_candidates(min_len, max_len, with_shift)
    stream walk passwords, shortest first, de-duplicated.
is_walk(password, max_gap)
    whether a password is a single contiguous keyboard walk.
walk_score(password)
    0-1 "how walk-like" a password is (fraction of adjacent steps).

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

from typing import Iterator

__all__ = [
    "KEYBOARD_ROWS",
    "adjacency_graph",
    "walks",
    "walk_candidates",
    "is_walk",
    "walk_score",
]

#: Staggered QWERTY rows (letters + digit row), top to bottom.
KEYBOARD_ROWS: tuple[str, ...] = (
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

_GRAPH: dict[str, frozenset[str]] | None = None


def adjacency_graph() -> dict[str, frozenset[str]]:
    """Build (and cache) the key -> adjacent-keys map.

    Two keys are adjacent when they are horizontally next to each other in
    a row, or vertically/diagonally touching between staggered rows.
    """
    global _GRAPH
    if _GRAPH is not None:
        return _GRAPH

    # Assign each key a (row, column) on a half-unit staggered grid.
    offsets = [0.0, 0.5, 0.75, 1.25]
    coords: dict[str, tuple[float, float]] = {}
    for r, row in enumerate(KEYBOARD_ROWS):
        for c, key in enumerate(row):
            coords[key] = (offsets[r] + c, float(r))

    graph: dict[str, set[str]] = {k: set() for k in coords}
    keys = list(coords)
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            a, b = keys[i], keys[j]
            (ax, ay), (bx, by) = coords[a], coords[b]
            dx, dy = abs(ax - bx), abs(ay - by)
            # adjacent: same row neighbours, or touching rows within ~1 col
            if dy == 0 and dx == 1:
                graph[a].add(b)
                graph[b].add(a)
            elif dy == 1 and dx <= 1.0:
                graph[a].add(b)
                graph[b].add(a)
    _GRAPH = {k: frozenset(v) for k, v in graph.items()}
    return _GRAPH


def walks(length: int, start: str | None = None) -> Iterator[str]:
    """Yield every spatial walk of exactly BTQlengthBTQ keys.

    With BTQstartBTQ only walks beginning at that key are produced. Walks may
    revisit keys (real fingers do). Order is deterministic (DFS over the
    sorted adjacency lists).
    """
    if length < 1:
        raise ValueError("length must be >= 1")
    graph = adjacency_graph()
    if start is not None and start not in graph:
        raise ValueError(f"unknown key {start!r}")

    def extend(path: list[str]) -> Iterator[str]:
        if len(path) == length:
            yield "".join(path)
            return
        for nxt in sorted(graph[path[-1]]):
            path.append(nxt)
            yield from extend(path)
            path.pop()

    starts = [start] if start else sorted(graph)
    for s in starts:
        yield from extend([s])


def walk_candidates(min_len: int = 4, max_len: int = 8,
                   with_shift: bool = False) -> Iterator[str]:
    """Stream walk passwords from BTQmin_lenBTQ to BTQmax_lenBTQ keys, de-duplicated.

    Shortest walks first. With BTQwith_shiftBTQ each walk also yields its
    fully-shifted uppercase form.
    """
    if min_len < 1 or max_len < min_len:
        raise ValueError("need 1 <= min_len <= max_len")
    seen: set[str] = set()
    for length in range(min_len, max_len + 1):
        for walk in walks(length):
            if walk not in seen:
                seen.add(walk)
                yield walk
            if with_shift:
                up = walk.upper()
                if up not in seen:
                    seen.add(up)
                    yield up


def is_walk(password: str, max_gap: int = 0) -> bool:
    """True when BTQpasswordBTQ is one contiguous keyboard walk.

    Every consecutive pair of characters must be adjacent keys. Case is
    ignored. BTQmax_gapBTQ tolerates that many non-adjacent steps.
    """
    if len(password) < 2:
        return False
    graph = adjacency_graph()
    lowered = password.lower()
    gaps = 0
    for a, b in zip(lowered, lowered[1:]):
        if a not in graph or b not in graph or b not in graph[a]:
            gaps += 1
            if gaps > max_gap:
                return False
    return True


def walk_score(password: str) -> float:
    """Fraction of consecutive steps that are adjacent keys (0.0-1.0).

    1.0 means a perfect walk; 0.0 means no adjacent steps. Non-key keys
    count as non-adjacent.
    """
    if len(password) < 2:
        return 0.0
    graph = adjacency_graph()
    lowered = password.lower()
    steps = len(lowered) - 1
    adjacent = 0
    for a, b in zip(lowered, lowered[1:]):
        if a in graph and b in graph.get(a, frozenset()):
            adjacent += 1
    return round(adjacent / steps, 4)
